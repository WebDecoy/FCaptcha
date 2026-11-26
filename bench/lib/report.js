'use strict';

/**
 * Renders the metrics, with the qualifications attached to the numbers rather
 * than buried in a README nobody opens.
 *
 * The design rule here: any figure that could be quoted out of context carries
 * its provenance in the same line. "FPR 0.00%" is a claim about people;
 * "Observed FP rate 0.00% (11 independently observed captures)" is a claim
 * about this corpus, which is the only claim we can support. Derived variants
 * are reported as capture-family robustness and never enlarge the denominator.
 */

const { pct } = require('./metrics');
const { HUMAN_FP_EVIDENCE } = require('./corpus');

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
};

const bar = (ch = '─', n = 74) => ch.repeat(n);

function heading(text) {
  return `\n${C.bold}${text}${C.reset}\n${C.dim}${bar()}${C.reset}`;
}

function table(rows, columns) {
  if (!rows.length) return `  ${C.dim}(none)${C.reset}`;
  const widths = columns.map((c) =>
    Math.max(c.header.length, ...rows.map((r) => String(c.value(r)).length))
  );
  const line = (cells) =>
    `  ${cells.map((c, i) => (columns[i].right ? String(c).padStart(widths[i]) : String(c).padEnd(widths[i]))).join('  ')}`;

  const out = [
    `${C.dim}${line(columns.map((c) => c.header))}${C.reset}`,
    `${C.dim}${line(widths.map((w) => '─'.repeat(w)))}${C.reset}`,
  ];
  for (const r of rows) {
    const cells = columns.map((c) => c.value(r));
    const colored = columns.some((c) => c.flag && c.flag(r));
    out.push(colored ? `${C.red}${line(cells)}${C.reset}` : line(cells));
  }
  return out.join('\n');
}

function summarizeCaveats(samples) {
  const counts = new Map();
  for (const s of samples) {
    for (const c of s.caveats || []) counts.set(c, (counts.get(c) || 0) + 1);
  }
  return counts;
}

function renderReport(metrics, corpus, gate) {
  const out = [];
  const cfg = metrics.config;

  out.push(`${C.bold}FCaptcha detection benchmark${C.reset}`);
  out.push('Regression corpus only: derived samples are correlated, not independent people or hardware. A passing gate is not a population accuracy estimate.');
  out.push(
    `${C.dim}${metrics.counts.humans} human / ${metrics.counts.agents} agent samples, ` +
      `${metrics.counts.errors} error(s). ` +
      `human flagged at score >= ${cfg.fpThreshold}, agent caught at >= ${cfg.tpThreshold}.${C.reset}`
  );

  // ---- Human panel -------------------------------------------------------
  out.push(heading('Human panel — false positives'));

  const evid = metrics.humanPanel.evidential;
  const caveats = summarizeCaveats(corpus.filter((s) =>
    s.label === 'human' && s.provenance === 'captured' && HUMAN_FP_EVIDENCE.has(s.labelEvidence)
  ));
  const caveatNote = caveats.size
    ? ` ${C.yellow}[${[...caveats.entries()].map(([k, n]) => `${k} ×${n}`).join(', ')}]${C.reset}`
    : '';

  if (evid.total === 0) {
    out.push(`  ${C.yellow}no independently observed human captures — nothing here supports an FP observation${C.reset}`);
  } else {
    const bad = evid.rate > cfg.panelFpBudget;
    out.push(
      `  ${bad ? C.red : C.green}Observed FP rate ${pct(evid.rate)}${C.reset} ` +
        `(${evid.hits}/${evid.total} independently observed capture families; ` +
        `${evid.captureHits}/${evid.captures} base captures, target < ${pct(cfg.panelFpBudget)})${caveatNote}`
    );
    const neighborhood = metrics.humanPanel.neighborhood;
    out.push(
      `  ${C.dim}Neighborhood robustness ${pct(neighborhood.rate)} ` +
        `(${neighborhood.hits}/${neighborhood.total} capture families had any base or derived variant cross the threshold; ` +
        `derived rows never increase N)${C.reset}`
    );
    if (metrics.counts.humans > metrics.counts.humansEvidential) {
      const excluded = metrics.humanPanel.excludedByEvidence
        .map((row) => `${row.labelEvidence || row.group} ×${row.total}`)
        .join(', ');
      out.push(
        `  ${C.dim}${metrics.counts.humans - metrics.counts.humansEvidential} structural or self-reported human fixture(s) measured but excluded ` +
          `from this figure (${excluded}) — see bench/README.md${C.reset}`
      );
    }
  }

  out.push('');
  out.push(
    table(metrics.humanPanel.byPersona, [
      { header: 'PERSONA', value: (r) => r.group },
      { header: 'N', value: (r) => r.total, right: true },
      { header: 'FLAGGED', value: (r) => r.hits, right: true, flag: (r) => r.hits > 0 },
      { header: 'RATE', value: (r) => pct(r.rate), right: true },
      { header: 'MED SCORE', value: (r) => r.medianScore?.toFixed(3) ?? '-', right: true },
      { header: 'MAX SCORE', value: (r) => r.maxScore?.toFixed(3) ?? '-', right: true },
      { header: 'LABEL EVIDENCE', value: (r) => r.labelEvidence || '-' },
    ])
  );

  if (metrics.humanPanel.exploratorySignals.length) {
    out.push(heading('Non-evidential human labels — exploratory only'));
    out.push(
      `  ${C.yellow}Simulated and self-reported human labels are not observed-human ground truth. ` +
        `These clusters never affect observed-human figures or gates.${C.reset}`
    );
    out.push('');
    out.push(
      table(metrics.humanPanel.exploratorySignals, [
        { header: 'SIGNAL', value: (r) => truncate(r.signal, 44) },
        { header: 'CAT', value: (r) => r.category || '-' },
        { header: 'LABELED HUMAN', value: (r) => `${r.hits}/${r.total}`, right: true },
        { header: 'RATE', value: (r) => pct(r.rate), right: true },
        { header: 'PERSONAS', value: (r) => truncate(r.personas.join(','), 34) },
        { header: 'PROVENANCE', value: (r) => r.provenance },
      ])
    );
  }

  // ---- Agent corpus ------------------------------------------------------
  out.push(heading('Agent corpus — true positives'));
  const ag = metrics.agentCorpus.all;
  out.push(
    `  TPR ${pct(ag.rate)} (${ag.hits}/${ag.total} caught at score >= ${cfg.tpThreshold}, ` +
      `target >= ${pct(cfg.classTprFloor)} per class)`
  );
  out.push('');
  out.push(
    table(metrics.agentCorpus.byClass, [
      { header: 'CLASS', value: (r) => r.group },
      { header: 'N', value: (r) => r.total, right: true },
      { header: 'CAUGHT', value: (r) => r.hits, right: true },
      { header: 'TPR', value: (r) => pct(r.rate), right: true, flag: (r) => r.rate < cfg.classTprFloor },
      { header: 'MED SCORE', value: (r) => r.medianScore?.toFixed(3) ?? '-', right: true },
      { header: 'PROVENANCE', value: (r) => r.provenance },
    ])
  );
  out.push('');
  out.push(`${C.dim}  Agent scenarios (capture choreography/configuration):${C.reset}`);
  out.push(
    table(metrics.agentCorpus.byScenario, [
      { header: 'SCENARIO', value: (r) => r.group },
      { header: 'N', value: (r) => r.total, right: true },
      { header: 'CAUGHT', value: (r) => r.hits, right: true },
      { header: 'TPR', value: (r) => pct(r.rate), right: true },
      { header: 'MED SCORE', value: (r) => r.medianScore?.toFixed(3) ?? '-', right: true },
      { header: 'MAX SCORE', value: (r) => r.maxScore?.toFixed(3) ?? '-', right: true },
      { header: 'PROVENANCE', value: (r) => r.provenance },
    ])
  );

  // ---- Per-signal --------------------------------------------------------
  out.push(heading(`Per-signal human capture-family robustness (budget ${pct(cfg.perSignalFpBudget)})`));
  out.push(
    `  ${C.dim}A signal is over budget when it fires in observed-human capture families more often than the ` +
      `budget allows. A family counts once even when many derived variants fire.${C.reset}`
  );
  out.push('');

  const firing = metrics.perSignal.filter((s) => s.familyHits > 0);
  out.push(
    table(firing, [
      { header: 'SIGNAL', value: (r) => truncate(r.signal, 44) },
      { header: 'CAT', value: (r) => r.category || '-' },
      { header: 'BASE', value: (r) => `${r.humanHits}/${r.humanTotal}`, right: true },
      { header: 'FAMILY', value: (r) => `${r.familyHits}/${r.familyTotal}`, right: true },
      { header: 'FAMILY RATE', value: (r) => pct(r.familyRate), right: true, flag: (r) => r.overBudget },
      { header: 'AGENT', value: (r) => `${r.agentHits}/${r.agentTotal}`, right: true },
      { header: 'PERSONAS', value: (r) => truncate(r.firesOnPersonas.join(','), 34) },
    ])
  );

  if (!firing.length) {
    out.push(`  ${C.green}no signal fired on any human sample${C.reset}`);
  }

  // Signals that only ever fire on agents are the ones earning their keep.
  const agentOnly = metrics.perSignal.filter((s) => s.familyHits === 0 && s.agentHits > 0);
  if (agentOnly.length) {
    out.push('');
    out.push(`  ${C.dim}Fires on agents only (${agentOnly.length}):${C.reset}`);
    for (const s of agentOnly) {
      out.push(
        `    ${C.green}✓${C.reset} ${truncate(s.signal, 52).padEnd(52)} ` +
          `${C.dim}${s.agentHits}/${s.agentTotal} agents${C.reset}`
      );
    }
  }

  // ---- Experimental observations ----------------------------------------
  if (metrics.experimental.policies.length) {
    out.push(heading('Experimental observations — non-gating'));
    out.push(
      `  ${C.yellow}Base samples only. These versioned observations never affect production scores, ` +
        `recommendations, signal budgets, or the release gate.${C.reset}`
    );
    out.push(`  ${C.dim}Detection rates exclude unknown/unsupported observations.${C.reset}`);
    out.push('');
    out.push(
      table(metrics.experimental.policies, [
        { header: 'POLICY', value: (r) => r.policy },
        { header: 'HUMAN', value: (r) => observationRate(r.humans), right: true },
        { header: 'SELF-REPORTED', value: (r) => observationRate(r.exploratoryHumans), right: true },
        { header: 'AGENT', value: (r) => observationRate(r.agents), right: true },
        { header: 'UNKNOWN H/A', value: (r) => `${r.humans.unknown}/${r.agents.unknown}`, right: true },
      ])
    );

    for (const policy of metrics.experimental.policies) {
      const detected = policy.byGroup.filter((row) => row.detected > 0);
      if (!detected.length) continue;
      out.push('');
      out.push(`${C.dim}  ${policy.policy} detections by base-sample group:${C.reset}`);
      out.push(
        table(detected, [
          { header: 'LABEL', value: (r) => r.label },
          { header: 'GROUP', value: (r) => r.group },
          { header: 'DETECTED/KNOWN', value: (r) => `${r.detected}/${r.known}`, right: true },
          { header: 'RATE', value: (r) => pct(r.rate), right: true },
          { header: 'PROVENANCE', value: (r) => r.provenance },
        ])
      );
    }
  }

  // ---- Known gaps --------------------------------------------------------
  const gaps = corpus.filter((s) => s.unmeasured);
  if (gaps.length) {
    out.push(heading('Known gaps — classes with no data'));
    for (const g of gaps) out.push(`  ${C.yellow}!${C.reset} ${g.group}: ${g.notes}`);
  }

  // ---- Gate --------------------------------------------------------------
  if (gate) {
    out.push(heading('Gate'));
    for (const f of gate.failures) out.push(`  ${C.red}FAIL${C.reset} ${f}`);
    for (const w of gate.warnings) out.push(`  ${C.yellow}WARN${C.reset} ${w}`);
    // Printed, never hidden: an exemption that stops being visible stops being
    // reviewable, and becomes a place regressions go to die.
    for (const e of gate.exempted || []) out.push(`  ${C.dim}EXEMPT${C.reset} ${e}`);
    if (!gate.failures.length && !gate.warnings.length) {
      out.push(`  ${C.green}PASS${C.reset} no signal over budget, no replay errors`);
    } else if (!gate.failures.length) {
      out.push(`  ${C.green}PASS${C.reset} (warnings above are not gated — see bench/README.md)`);
    }
  }

  if (metrics.errors.length) {
    out.push(heading('Replay errors'));
    for (const e of metrics.errors) out.push(`  ${C.red}${e.id}${C.reset}: ${e.error}`);
  }

  return `${out.join('\n')}\n`;
}

function renderResearchReport(results, metrics) {
  const out = [];
  out.push(`${C.bold}FCaptcha research replay${C.reset}`);
  out.push(
    `${C.yellow}Exploratory only: labels are self-reported. ` +
      `No FPR, TPR, signal budget, or release gate is computed.${C.reset}`
  );
  out.push(
    `${C.dim}${metrics.counts.scored} scored / ${metrics.counts.errors} error(s); ` +
      `samples remain ephemeral and are not written to the corpus or JSON.${C.reset}`
  );

  out.push(heading('Research samples'));
  out.push(
    table(results, [
      { header: 'BROWSER/OS', value: (r) => `${r.sample.capture?.browser || '-'}/${r.sample.capture?.os || '-'}` },
      { header: 'INPUT', value: (r) => r.sample.capture?.input || '-' },
      { header: 'ENDPOINT', value: (r) => r.sample.capture?.endpoint || '-' },
      { header: 'SCORE', value: (r) => r.error ? '-' : r.score?.toFixed(3) ?? '-', right: true },
      { header: 'RECOMMENDATION', value: (r) => r.error ? 'error' : r.recommendation || '-' },
      { header: 'SIGNALS', value: (r) => r.error ? '-' : (r.detections || []).length, right: true },
    ])
  );

  if (metrics.humanPanel.exploratorySignals.length) {
    out.push(heading('Observed signals — exploratory only'));
    out.push(
      table(metrics.humanPanel.exploratorySignals, [
        { header: 'SIGNAL', value: (r) => truncate(r.signal, 48) },
        { header: 'CAT', value: (r) => r.category || '-' },
        { header: 'SAMPLES', value: (r) => `${r.hits}/${r.total}`, right: true },
        { header: 'RATE', value: (r) => pct(r.rate), right: true },
      ])
    );
  }

  if (metrics.experimental.policies.length) {
    out.push(heading('Experimental observations — exploratory only'));
    out.push(
      `  ${C.yellow}Observe-only browser consistency candidates; no score, recommendation, ` +
        `FPR claim, or release gate is changed.${C.reset}`
    );
    out.push('');
    out.push(
      table(metrics.experimental.policies, [
        { header: 'POLICY', value: (r) => r.policy },
        { header: 'DETECTED', value: (r) => r.exploratoryHumans.detected, right: true },
        { header: 'CLEAR', value: (r) => r.exploratoryHumans.clear, right: true },
        { header: 'UNKNOWN', value: (r) => r.exploratoryHumans.unknown, right: true },
        { header: 'RATE', value: (r) => pct(r.exploratoryHumans.rate), right: true },
      ])
    );
  }

  if (metrics.errors.length) {
    out.push(heading('Replay errors'));
    for (const error of metrics.errors) out.push(`  ${C.red}${error.id}${C.reset}: ${error.error}`);
  }

  return `${out.join('\n')}\n`;
}

function renderHostedSmokeReport(results) {
  const errors = results.filter((result) => result.error);
  const out = [];
  out.push(`${C.bold}FCaptcha hosted smoke replay${C.reset}`);
  out.push(
    `${C.yellow}Operational only: production proxying and shared egress make hosted scores ` +
      `non-comparable. No FPR, TPR, signal budget, or release gate is computed.${C.reset}`
  );
  out.push(
    `${C.dim}${results.length - errors.length}/${results.length} checks completed; ` +
      `${errors.length} error(s). No signal-level JSON is written.${C.reset}`
  );

  out.push(heading('Endpoint smoke checks'));
  out.push(
    table(results, [
      { header: 'LABEL', value: (result) => result.sample.label },
      { header: 'SCENARIO', value: (result) => truncate(result.sample.scenario || result.sample.group, 36) },
      { header: 'ENDPOINT', value: (result) => result.sample.capture?.endpoint === '/api/score' ? '/api/score' : '/api/verify' },
      { header: 'STATUS', value: (result) => result.error ? 'error' : 'completed', flag: (result) => Boolean(result.error) },
    ])
  );

  if (errors.length) {
    out.push(heading('Replay errors'));
    for (const error of errors) out.push(`  ${C.red}${error.sample.id}${C.reset}: ${error.error}`);
  }

  return `${out.join('\n')}\n`;
}

function truncate(s, n) {
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}

function observationRate(stats) {
  return stats.known ? `${stats.detected}/${stats.known} (${pct(stats.rate)})` : `0/0 (n/a)`;
}

module.exports = { renderHostedSmokeReport, renderReport, renderResearchReport };
