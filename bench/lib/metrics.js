'use strict';

/**
 * Turns raw verdicts into the numbers §2 of the extensions PRD asks for:
 * true-positive rate on the labeled agent corpus, false-positive rate on the
 * human panel, and a per-signal false-positive rate so a single new detection
 * cannot hide inside an acceptable aggregate.
 *
 * That last one is the point of the exercise. A category can sit comfortably
 * under budget while one reason inside it fires on every screen-reader user,
 * because the other reasons in that category never fire at all. Averages hide
 * exactly the failure we care about, so everything here is computed per signal
 * and per persona first, and aggregated only for display.
 */

const { HUMAN_FP_EVIDENCE } = require('./corpus');

/**
 * Thresholds from PRD §2. Both sides are decision thresholds, not score
 * summaries: a human is a false positive when the score would have cost them
 * something, and an agent is a true positive when the score would have stopped
 * it.
 */
const DEFAULTS = {
  fpThreshold: 0.5, // human scored at or above this = false positive
  tpThreshold: 0.8, // agent scored at or above this = caught
  perSignalFpBudget: 0.003, // 0.3%, PRD §2
  panelFpBudget: 0.005, // 0.5%, PRD §2
  classTprFloor: 0.9, // 90%, PRD §2
};

/**
 * Detection reasons carry interpolated values — hostnames, counts, field names.
 * Left raw, `Reverse DNS suggests VPN/proxy: ec2-1-2-3-4.aws.com` and the same
 * message about a different host would count as two signals with one sample
 * each, and neither would ever look like it had a rate. Collapse the variable
 * part so a signal is counted as one thing.
 */
function signalKey(reason) {
  if (typeof reason !== 'string') return '(unnamed)';
  return reason
    .replace(/\([^)]*\d[^)]*\)/g, '') // "...too fast after page load (143ms)"
    .split(':')[0] // "Reverse DNS suggests VPN/proxy: host"
    .replace(/\b\d+(\.\d+)?\b/g, 'N') // "Missing 3 expected browser headers"
    .replace(/\s+/g, ' ')
    .trim();
}

function rate(hits, total) {
  return total === 0 ? null : hits / total;
}

function isObservedHuman(sample) {
  return sample.label === 'human' && sample.provenance === 'captured' &&
    HUMAN_FP_EVIDENCE.has(sample.labelEvidence);
}

function isHumanNeighborhood(sample) {
  return sample.label === 'human' &&
    (sample.provenance === 'captured' || sample.provenance === 'derived') &&
    HUMAN_FP_EVIDENCE.has(sample.labelEvidence);
}

function familyKey(row) {
  return row.sample.provenance === 'derived' ? row.sample.source : row.sample.id;
}

function experimentalStats(rows, policy) {
  const counts = { detected: 0, clear: 0, unknown: 0 };
  for (const row of rows) {
    const status = row.experimental?.observations?.[policy]?.status;
    counts[status === 'detected' || status === 'clear' ? status : 'unknown']++;
  }
  const known = counts.detected + counts.clear;
  return {
    total: rows.length,
    ...counts,
    known,
    rate: rate(counts.detected, known),
  };
}

function computeExperimental(ok) {
  // Derived samples repeat their parent's browser observation and would make a
  // single capture look like independent evidence. Keep this panel to base
  // samples; it is descriptive and never participates in a gate.
  const base = ok.filter((row) => row.sample.provenance !== 'derived');
  const policies = new Set();
  for (const row of base) {
    for (const policy of Object.keys(row.experimental?.observations || {})) policies.add(policy);
  }

  return [...policies].sort().map((policy) => {
    const humans = base.filter((row) => row.sample.label === 'human');
    const evidentialHumans = humans.filter((row) => isObservedHuman(row.sample));
    const exploratoryHumans = humans.filter((row) => !isObservedHuman(row.sample));
    const agents = base.filter((row) => row.sample.label === 'agent');
    const groups = new Map();

    for (const row of base) {
      const key = `${row.sample.label}\0${row.sample.group}`;
      const group = groups.get(key) || {
        label: row.sample.label,
        group: row.sample.group,
        provenance: new Set(),
        rows: [],
      };
      group.provenance.add(row.sample.provenance);
      group.rows.push(row);
      groups.set(key, group);
    }

    return {
      policy,
      humans: experimentalStats(evidentialHumans, policy),
      exploratoryHumans: experimentalStats(exploratoryHumans, policy),
      agents: experimentalStats(agents, policy),
      byGroup: [...groups.values()]
        .map((group) => ({
          label: group.label,
          group: group.group,
          provenance: [...group.provenance].sort().join('+'),
          ...experimentalStats(group.rows, policy),
        }))
        .sort((a, b) => a.label.localeCompare(b.label) || b.rate - a.rate || a.group.localeCompare(b.group)),
    };
  });
}

/**
 * @param {object[]} results  from replayCorpus
 * @param {object}   opts     threshold overrides
 */
function computeMetrics(results, opts = {}) {
  const cfg = { ...DEFAULTS, ...opts };

  const errors = results.filter((r) => r.error);
  const ok = results.filter((r) => !r.error);

  const replayedHumans = ok.filter((r) => r.sample.label === 'human');
  const replayedAgents = ok.filter((r) => r.sample.label === 'agent');
  const humans = replayedHumans.filter((r) => r.sample.provenance !== 'derived');
  const agents = replayedAgents.filter((r) => r.sample.provenance !== 'derived');

  // A real browser payload is not automatically a real-human observation.
  // Only independently verified human sessions and legitimate paired controls
  // support the observed panel. Derived children remain useful, but only as a
  // capture-family robustness check: changing --derive must never manufacture
  // independent people or change a denominator.
  const evidentialHumans = humans.filter((r) => isObservedHuman(r.sample));
  const neighborhoodHumans = replayedHumans.filter((r) => isHumanNeighborhood(r.sample));
  const nonEvidentialHumans = humans.filter((r) => !isObservedHuman(r.sample));

  const byGroup = (rows, isHit, keyFor = (r) => r.sample.group) => {
    const groups = new Map();
    for (const r of rows) {
      const key = keyFor(r);
      const g = groups.get(key) || {
        group: key,
        total: 0,
        hits: 0,
        provenance: new Set(),
        labelEvidence: new Set(),
        scores: [],
      };
      g.total++;
      if (isHit(r)) g.hits++;
      g.provenance.add(r.sample.provenance);
      if (r.sample.labelEvidence) g.labelEvidence.add(r.sample.labelEvidence);
      g.scores.push(r.score);
      groups.set(key, g);
    }
    return [...groups.values()]
      .map((g) => ({
        group: g.group,
        total: g.total,
        hits: g.hits,
        rate: rate(g.hits, g.total),
        provenance: [...g.provenance].sort().join('+'),
        labelEvidence: [...g.labelEvidence].sort().join('+'),
        medianScore: median(g.scores),
        maxScore: Math.max(...g.scores),
      }))
      .sort((a, b) => b.rate - a.rate || a.group.localeCompare(b.group));
  };

  const isFalsePositive = (r) => r.score >= cfg.fpThreshold;
  const isCaught = (r) => r.score >= cfg.tpThreshold;

  // Per-signal false positives. A signal counts once per human sample it fires
  // on, regardless of how many times it appears in that sample's detections.
  const signals = new Map();
  const touch = (key) => {
    const s = signals.get(key) || {
      signal: key,
      category: null,
      humanSamples: new Set(),
      humanFamilies: new Set(),
      humanFamilyPersonas: new Set(),
      agentSamples: new Set(),
    };
    signals.set(key, s);
    return s;
  };

  for (const r of evidentialHumans) {
    const seen = new Set();
    for (const d of r.detections) {
      const key = signalKey(d.reason);
      if (seen.has(key)) continue;
      seen.add(key);
      const s = touch(key);
      s.category = s.category || d.category;
      s.humanSamples.add(r.sample.id);
    }
  }
  for (const r of neighborhoodHumans) {
    const seen = new Set();
    for (const d of r.detections) {
      const key = signalKey(d.reason);
      if (seen.has(key)) continue;
      seen.add(key);
      const s = touch(key);
      s.category = s.category || d.category;
      s.humanFamilies.add(familyKey(r));
      s.humanFamilyPersonas.add(r.sample.group);
    }
  }
  for (const r of agents) {
    const seen = new Set();
    for (const d of r.detections) {
      const key = signalKey(d.reason);
      if (seen.has(key)) continue;
      seen.add(key);
      const s = touch(key);
      s.category = s.category || d.category;
      s.agentSamples.add(r.sample.id);
    }
  }

  const perSignal = [...signals.values()]
    .map((s) => ({
      signal: s.signal,
      category: s.category,
      humanHits: s.humanSamples.size,
      humanTotal: evidentialHumans.length,
      humanFpr: rate(s.humanSamples.size, evidentialHumans.length),
      familyHits: s.humanFamilies.size,
      familyTotal: evidentialHumans.length,
      familyRate: rate(s.humanFamilies.size, evidentialHumans.length),
      firesOnPersonas: [...s.humanFamilyPersonas].sort(),
      agentHits: s.agentSamples.size,
      agentTotal: agents.length,
      agentTpr: rate(s.agentSamples.size, agents.length),
      overBudget: rate(s.humanFamilies.size, evidentialHumans.length) > cfg.perSignalFpBudget,
    }))
    .sort((a, b) => (b.familyRate || 0) - (a.familyRate || 0) || a.signal.localeCompare(b.signal));

  const nonEvidentialSignals = new Map();
  for (const r of nonEvidentialHumans) {
    const seen = new Set();
    for (const d of r.detections) {
      const key = signalKey(d.reason);
      if (seen.has(key)) continue;
      seen.add(key);
      const signal = nonEvidentialSignals.get(key) || {
        signal: key,
        category: d.category || null,
        hits: 0,
        personas: new Set(),
        provenance: new Set(),
      };
      signal.hits++;
      signal.personas.add(r.sample.group);
      signal.provenance.add(r.sample.provenance);
      nonEvidentialSignals.set(key, signal);
    }
  }
  const exploratorySignals = [...nonEvidentialSignals.values()]
    .map((signal) => ({
      signal: signal.signal,
      category: signal.category,
      hits: signal.hits,
      total: nonEvidentialHumans.length,
      rate: rate(signal.hits, nonEvidentialHumans.length),
      personas: [...signal.personas].sort(),
      provenance: [...signal.provenance].sort().join('+'),
    }))
    .sort((a, b) => b.rate - a.rate || a.signal.localeCompare(b.signal));

  return {
    config: cfg,
    counts: {
      total: results.length,
      scored: ok.length,
      errors: errors.length,
      humans: humans.length,
      humansEvidential: evidentialHumans.length,
      agents: agents.length,
      replayedHumans: replayedHumans.length,
      replayedAgents: replayedAgents.length,
    },
    errors: errors.map((e) => ({ id: e.sample.id, error: e.error })),
    humanPanel: {
      all: { total: humans.length, hits: humans.filter(isFalsePositive).length, rate: rate(humans.filter(isFalsePositive).length, humans.length) },
      evidential: {
        total: evidentialHumans.length,
        hits: evidentialHumans.filter(isFalsePositive).length,
        rate: rate(evidentialHumans.filter(isFalsePositive).length, evidentialHumans.length),
      },
      neighborhood: (() => {
        const families = new Set(evidentialHumans.map(familyKey));
        const hits = new Set(neighborhoodHumans.filter(isFalsePositive).map(familyKey));
        return { total: families.size, hits: hits.size, rate: rate(hits.size, families.size) };
      })(),
      excludedByEvidence: byGroup(
        nonEvidentialHumans,
        isFalsePositive,
        (r) => r.sample.labelEvidence
      ),
      exploratorySignals,
      byPersona: byGroup(humans, isFalsePositive),
    },
    agentCorpus: {
      all: { total: agents.length, hits: agents.filter(isCaught).length, rate: rate(agents.filter(isCaught).length, agents.length) },
      byClass: byGroup(agents, isCaught),
      byScenario: byGroup(
        agents,
        isCaught,
        (r) => r.sample.scenario || r.sample.id.split('/')[1] || r.sample.group
      ),
    },
    perSignal,
    experimental: {
      // Observe-only browser consistency candidates. This is deliberately
      // outside humanPanel, agentCorpus, perSignal, and evaluateGate.
      policies: computeExperimental(ok),
    },
  };
}

function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/**
 * The CI gate.
 *
 * Deliberately narrow: it fails on a per-signal FP budget breach, replay
 * errors, and explicitly recorded fixed-corpus agent regressions. It warns —
 * without failing — on the aggregate FPR and absolute per-class TPR target.
 * Those two are population claims, and this corpus is not a population sample.
 * See bench/README.md.
 */
function evaluateGate(metrics, knownArtifacts = [], agentRegressionFloors = {}) {
  const failures = [];
  const warnings = [];
  const exempted = [];
  const cfg = metrics.config;

  // An exemption matches on the normalized signal key, so it survives the
  // interpolated values in a reason string.
  const artifactFor = (signal) =>
    knownArtifacts.find((a) => signalKey(a.signal) === signal);

  for (const s of metrics.perSignal) {
    if (s.familyRate <= cfg.perSignalFpBudget) continue;

    const artifact = artifactFor(s.signal);
    const detail =
      `"${s.signal}" fired in ${s.familyHits}/${s.familyTotal} observed-human capture families ` +
      `(${pct(s.familyRate)}, budget ${pct(cfg.perSignalFpBudget)}; ` +
      `${s.humanHits}/${s.humanTotal} base captures) ` +
      `— personas: ${s.firesOnPersonas.join(', ')}`;

    if (artifact) {
      // Caused by the recorder rather than by FCaptcha misfiring. Still
      // measured and still printed — just not a build failure. See
      // bench/corpus/known-artifacts.json.
      exempted.push(`${detail}\n         known artifact: ${artifact.reason}`);
    } else {
      failures.push(`signal over FP budget: ${detail}`);
    }
  }

  if (metrics.counts.errors > 0) {
    failures.push(`${metrics.counts.errors} sample(s) failed to replay — the run is incomplete`);
  }

  const panel = metrics.humanPanel.evidential;
  if (panel.total > 0 && panel.rate > cfg.panelFpBudget) {
    warnings.push(
      `observed human FP rate ${pct(panel.rate)} exceeds the ${pct(cfg.panelFpBudget)} target ` +
        `(${panel.hits}/${panel.total} independently observed captures)`
    );
  }

  for (const c of metrics.agentCorpus.byClass) {
    if (c.rate < cfg.classTprFloor) {
      const detail =
        `class "${c.group}" TPR ${pct(c.rate)} below the ${pct(cfg.classTprFloor)} target ` +
        `(${c.hits}/${c.total} caught)`;
      const regressionFloor = agentRegressionFloors[c.group];
      if (regressionFloor !== undefined && c.rate < regressionFloor) {
        failures.push(
          `${detail}; below its fixed-corpus regression floor ${pct(regressionFloor)}`
        );
      } else {
        warnings.push(detail);
      }
    }
  }
  for (const group of Object.keys(agentRegressionFloors)) {
    if (!metrics.agentCorpus.byClass.some((c) => c.group === group)) {
      failures.push(`agent regression class "${group}" is missing from the corpus`);
    }
  }

  return { passed: failures.length === 0, failures, warnings, exempted };
}

function pct(x) {
  if (x === null || x === undefined) return 'n/a';
  return `${(x * 100).toFixed(2)}%`;
}

module.exports = { DEFAULTS, computeMetrics, evaluateGate, median, pct, signalKey };
