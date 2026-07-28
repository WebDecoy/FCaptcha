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

const { EVIDENTIAL } = require('./corpus');

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

/**
 * @param {object[]} results  from replayCorpus
 * @param {object}   opts     threshold overrides
 */
function computeMetrics(results, opts = {}) {
  const cfg = { ...DEFAULTS, ...opts };

  const errors = results.filter((r) => r.error);
  const ok = results.filter((r) => !r.error);

  const humans = ok.filter((r) => r.sample.label === 'human');
  const agents = ok.filter((r) => r.sample.label === 'agent');

  // Only captured and derived samples can support a false-positive claim;
  // hand-authored ones are regression fixtures. Both are measured, but the
  // reporter is required to keep them apart.
  const evidentialHumans = humans.filter((r) => EVIDENTIAL.has(r.sample.provenance));

  const byGroup = (rows, isHit) => {
    const groups = new Map();
    for (const r of rows) {
      const g = groups.get(r.sample.group) || { group: r.sample.group, total: 0, hits: 0, provenance: new Set(), scores: [] };
      g.total++;
      if (isHit(r)) g.hits++;
      g.provenance.add(r.sample.provenance);
      g.scores.push(r.score);
      groups.set(r.sample.group, g);
    }
    return [...groups.values()]
      .map((g) => ({
        group: g.group,
        total: g.total,
        hits: g.hits,
        rate: rate(g.hits, g.total),
        provenance: [...g.provenance].sort().join('+'),
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
  const touch = (key, bucket) => {
    const s = signals.get(key) || {
      signal: key,
      category: null,
      humanHits: 0,
      agentHits: 0,
      humanSamples: new Set(),
      agentSamples: new Set(),
    };
    signals.set(key, s);
    return s;
  };

  for (const r of humans) {
    const seen = new Set();
    for (const d of r.detections) {
      const key = signalKey(d.reason);
      if (seen.has(key)) continue;
      seen.add(key);
      const s = touch(key);
      s.category = s.category || d.category;
      s.humanHits++;
      s.humanSamples.add(r.sample.group);
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
      s.agentHits++;
      s.agentSamples.add(r.sample.group);
    }
  }

  const perSignal = [...signals.values()]
    .map((s) => ({
      signal: s.signal,
      category: s.category,
      humanHits: s.humanHits,
      humanTotal: humans.length,
      humanFpr: rate(s.humanHits, humans.length),
      firesOnPersonas: [...s.humanSamples].sort(),
      agentHits: s.agentHits,
      agentTotal: agents.length,
      agentTpr: rate(s.agentHits, agents.length),
      overBudget: rate(s.humanHits, humans.length) > cfg.perSignalFpBudget,
    }))
    .sort((a, b) => (b.humanFpr || 0) - (a.humanFpr || 0) || a.signal.localeCompare(b.signal));

  return {
    config: cfg,
    counts: {
      total: results.length,
      scored: ok.length,
      errors: errors.length,
      humans: humans.length,
      humansEvidential: evidentialHumans.length,
      agents: agents.length,
    },
    errors: errors.map((e) => ({ id: e.sample.id, error: e.error })),
    humanPanel: {
      all: { total: humans.length, hits: humans.filter(isFalsePositive).length, rate: rate(humans.filter(isFalsePositive).length, humans.length) },
      evidential: {
        total: evidentialHumans.length,
        hits: evidentialHumans.filter(isFalsePositive).length,
        rate: rate(evidentialHumans.filter(isFalsePositive).length, evidentialHumans.length),
      },
      byPersona: byGroup(humans, isFalsePositive),
    },
    agentCorpus: {
      all: { total: agents.length, hits: agents.filter(isCaught).length, rate: rate(agents.filter(isCaught).length, agents.length) },
      byClass: byGroup(agents, isCaught),
    },
    perSignal,
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
 * Deliberately narrow: it fails on a per-signal FP budget breach and on
 * replay errors, and it warns — without failing — on the aggregate FPR and
 * per-class TPR. Those two are population claims, and this corpus is not a
 * population sample. Gating on them would dress a regression check up as
 * evidence about real users. See bench/README.md.
 */
function evaluateGate(metrics, knownArtifacts = []) {
  const failures = [];
  const warnings = [];
  const exempted = [];
  const cfg = metrics.config;

  // An exemption matches on the normalized signal key, so it survives the
  // interpolated values in a reason string.
  const artifactFor = (signal) =>
    knownArtifacts.find((a) => signalKey(a.signal) === signal);

  for (const s of metrics.perSignal) {
    if (s.humanFpr <= cfg.perSignalFpBudget) continue;

    const artifact = artifactFor(s.signal);
    const detail =
      `"${s.signal}" fired on ${s.humanHits}/${s.humanTotal} human samples ` +
      `(${pct(s.humanFpr)}, budget ${pct(cfg.perSignalFpBudget)}) ` +
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
      `human panel FPR ${pct(panel.rate)} exceeds the ${pct(cfg.panelFpBudget)} target ` +
        `(${panel.hits}/${panel.total} captured+derived samples)`
    );
  }

  for (const c of metrics.agentCorpus.byClass) {
    if (c.rate < cfg.classTprFloor) {
      warnings.push(
        `class "${c.group}" TPR ${pct(c.rate)} below the ${pct(cfg.classTprFloor)} target ` +
          `(${c.hits}/${c.total} caught)`
      );
    }
  }

  return { passed: failures.length === 0, failures, warnings, exempted };
}

function pct(x) {
  if (x === null || x === undefined) return 'n/a';
  return `${(x * 100).toFixed(2)}%`;
}

module.exports = { DEFAULTS, computeMetrics, evaluateGate, median, pct, signalKey };
