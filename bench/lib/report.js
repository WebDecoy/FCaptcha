'use strict';

/**
 * Renders the metrics, with the qualifications attached to the numbers rather
 * than buried in a README nobody opens.
 *
 * The design rule here: any figure that could be quoted out of context carries
 * its provenance in the same line. "FPR 0.00%" is a claim about people;
 * "FPR 0.00% (11 captured+derived samples, environment-normalized)" is a claim
 * about this corpus, which is the only claim we can support.
 */

const { pct } = require('./metrics');

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
  out.push(
    `${C.dim}${metrics.counts.humans} human / ${metrics.counts.agents} agent samples, ` +
      `${metrics.counts.errors} error(s). ` +
      `human flagged at score >= ${cfg.fpThreshold}, agent caught at >= ${cfg.tpThreshold}.${C.reset}`
  );

  // ---- Human panel -------------------------------------------------------
  out.push(heading('Human panel — false positives'));

  const evid = metrics.humanPanel.evidential;
  const caveats = summarizeCaveats(corpus.filter((s) => s.label === 'human'));
  const caveatNote = caveats.size
    ? ` ${C.yellow}[${[...caveats.entries()].map(([k, n]) => `${k} ×${n}`).join(', ')}]${C.reset}`
    : '';

  if (evid.total === 0) {
    out.push(`  ${C.yellow}no captured or derived human samples — nothing here supports an FP claim${C.reset}`);
  } else {
    const bad = evid.rate > cfg.panelFpBudget;
    out.push(
      `  ${bad ? C.red : C.green}FPR ${pct(evid.rate)}${C.reset} ` +
        `(${evid.hits}/${evid.total} captured+derived, target < ${pct(cfg.panelFpBudget)})${caveatNote}`
    );
    if (metrics.counts.humans > evid.total) {
      out.push(
        `  ${C.dim}${metrics.counts.humans - evid.total} synthetic human sample(s) measured but excluded ` +
          `from this figure — see bench/README.md${C.reset}`
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
      { header: 'PROVENANCE', value: (r) => r.provenance },
    ])
  );

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

  // ---- Per-signal --------------------------------------------------------
  out.push(heading(`Per-signal false positives (budget ${pct(cfg.perSignalFpBudget)})`));
  out.push(
    `  ${C.dim}A signal is over budget when it fires on human samples more often than the ` +
      `budget allows,${C.reset}`
  );
  out.push(`  ${C.dim}regardless of how the category it belongs to performs overall.${C.reset}`);
  out.push('');

  const firing = metrics.perSignal.filter((s) => s.humanHits > 0);
  out.push(
    table(firing, [
      { header: 'SIGNAL', value: (r) => truncate(r.signal, 44) },
      { header: 'CAT', value: (r) => r.category || '-' },
      { header: 'HUMAN', value: (r) => `${r.humanHits}/${r.humanTotal}`, right: true },
      { header: 'FPR', value: (r) => pct(r.humanFpr), right: true, flag: (r) => r.overBudget },
      { header: 'AGENT', value: (r) => `${r.agentHits}/${r.agentTotal}`, right: true },
      { header: 'PERSONAS', value: (r) => truncate(r.firesOnPersonas.join(','), 34) },
    ])
  );

  if (!firing.length) {
    out.push(`  ${C.green}no signal fired on any human sample${C.reset}`);
  }

  // Signals that only ever fire on agents are the ones earning their keep.
  const agentOnly = metrics.perSignal.filter((s) => s.humanHits === 0 && s.agentHits > 0);
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

function truncate(s, n) {
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}

module.exports = { renderReport };
