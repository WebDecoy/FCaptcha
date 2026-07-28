#!/usr/bin/env node
'use strict';

/**
 * Compares candidate score-aggregation schemes on the labeled corpus.
 *
 * Retuning a scorer by reasoning about it is how you get a scorer that is
 * plausible and wrong. This replays the corpus once, keeps every detection, and
 * then recomputes the final score under each candidate offline — so the schemes
 * are compared on identical evidence, and the only thing that varies is the
 * arithmetic.
 *
 * Usage: node bench/tools/compare-aggregation.js [--derive N]
 */

const path = require('path');
const { deriveVariant, loadCorpus } = require('../lib/corpus');
const { replayCorpus } = require('../lib/replay');
const { makeRng } = require('../lib/rng');

const WEIGHTS = {
  vision_ai: 0.15,
  headless: 0.15,
  automation: 0.08,
  cdp: 0.12,
  behavioral: 0.18,
  fingerprint: 0.08,
  rate_limit: 0.01,
  datacenter: 0.07,
  tor_vpn: 0.01,
  bot: 0.13,
  declared_ai: 0.02,
};

/**
 * Detections a browser only produces by declaring its own automation.
 *
 * `navigator.webdriver` is a W3C-standard flag whose entire purpose is to let a
 * page know it is being driven; the others are globals injected by a specific
 * automation framework. No ordinary browsing session sets any of them, which is
 * what makes them dispositive rather than merely suspicious.
 */
const SELF_DECLARED = [
  /^WebDriver detected$/, // navigator.webdriver === true (W3C-specified)
  /^CDP automation detected/, // chromedriver_cdc / puppeteer_eval / cdp_script_injection globals
];

const isSelfDeclared = (d) => SELF_DECLARED.some((re) => re.test(d.reason || ''));

function byCategory(detections) {
  const out = {};
  for (const d of detections) (out[d.category] ||= []).push(d);
  return out;
}

// --- candidate aggregations ------------------------------------------------

/** Current: confidence-weighted mean within a category. */
function categoryMean(dets) {
  const tw = dets.reduce((s, d) => s + d.confidence, 0);
  if (!tw) return 0;
  return Math.min(1, dets.reduce((s, d) => s + d.score * d.confidence, 0) / tw);
}

/**
 * Noisy-OR: treat each detection as independent evidence of strength
 * score x confidence, and combine as "at least one is right".
 *
 * Two properties matter. Evidence accumulates — adding a corroborating signal
 * can only raise the category, never lower it. And an isolated low-confidence
 * detection is treated more leniently than the mean treats it, because its
 * confidence discounts it instead of setting the category outright.
 */
function categoryNoisyOr(dets) {
  let survive = 1;
  for (const d of dets) survive *= 1 - Math.max(0, Math.min(1, d.score * d.confidence));
  return 1 - survive;
}

const finalScore = (catScores) =>
  Math.min(1, Object.entries(WEIGHTS).reduce((t, [c, w]) => t + (catScores[c] || 0) * w, 0));

const SCHEMES = {
  current: (dets) => {
    const cats = {};
    for (const [c, ds] of Object.entries(byCategory(dets))) cats[c] = categoryMean(ds);
    return finalScore(cats);
  },

  noisyOr: (dets) => {
    const cats = {};
    for (const [c, ds] of Object.entries(byCategory(dets))) cats[c] = categoryNoisyOr(ds);
    return finalScore(cats);
  },

  noisyOrPlusFloor: (dets) => {
    const cats = {};
    for (const [c, ds] of Object.entries(byCategory(dets))) cats[c] = categoryNoisyOr(ds);
    const base = finalScore(cats);
    return dets.some(isSelfDeclared) ? Math.max(base, 0.9) : base;
  },

  currentPlusFloor: (dets) => {
    const cats = {};
    for (const [c, ds] of Object.entries(byCategory(dets))) cats[c] = categoryMean(ds);
    const base = finalScore(cats);
    return dets.some(isSelfDeclared) ? Math.max(base, 0.9) : base;
  },
};

// --- reporting -------------------------------------------------------------

function stats(values) {
  if (!values.length) return { n: 0 };
  const s = [...values].sort((a, b) => a - b);
  return {
    n: s.length,
    min: s[0],
    median: s[s.length >> 1],
    max: s[s.length - 1],
  };
}

async function main() {
  const deriveArg = process.argv.indexOf('--derive');
  const derive = deriveArg > -1 ? Number(process.argv[deriveArg + 1]) : 3;

  const base = loadCorpus().filter((s) => !s.unmeasured);
  const rng = makeRng(1);
  const corpus = [...base];
  let n = 0;
  for (const s of base) {
    if (s.provenance !== 'captured') continue;
    for (let i = 0; i < derive; i++) {
      const v = deriveVariant(s, rng, n++);
      if (s.caveats) v.caveats = [...s.caveats];
      corpus.push(v);
    }
  }

  console.log(`replaying ${corpus.length} samples once, then scoring offline under each scheme\n`);
  const results = (await replayCorpus('http://localhost:3000', corpus, { concurrency: 6 })).filter(
    (r) => !r.error
  );

  const humans = results.filter((r) => r.sample.label === 'human');
  const agents = results.filter((r) => r.sample.label === 'agent');

  const rows = [];
  for (const [name, scheme] of Object.entries(SCHEMES)) {
    const h = humans.map((r) => scheme(r.detections));
    const a = agents.map((r) => scheme(r.detections));
    rows.push({
      name,
      humanStats: stats(h),
      agentStats: stats(a),
      fpr: h.filter((s) => s >= 0.5).length / h.length,
      tpr: a.filter((s) => s >= 0.8).length / a.length,
      // How cleanly the two populations separate: worst agent minus worst human.
      margin: Math.min(...a) - Math.max(...h),
    });
  }

  const pct = (x) => `${(x * 100).toFixed(1)}%`;
  const f = (x) => (x === undefined ? '-' : x.toFixed(3));

  console.log(
    'SCHEME              HUMAN med/max    AGENT min/med    FPR@.5    TPR@.8    MARGIN'
  );
  console.log('─'.repeat(84));
  for (const r of rows) {
    console.log(
      `${r.name.padEnd(20)}${`${f(r.humanStats.median)}/${f(r.humanStats.max)}`.padEnd(17)}` +
        `${`${f(r.agentStats.min)}/${f(r.agentStats.median)}`.padEnd(17)}` +
        `${pct(r.fpr).padStart(6)}    ${pct(r.tpr).padStart(6)}    ${f(r.margin).padStart(6)}`
    );
  }

  console.log(
    '\nMARGIN is the gap between the lowest-scoring agent and the highest-scoring human.'
  );
  console.log('Positive means the two populations do not overlap at all on this corpus.');
  console.log(`\n(${humans.length} human / ${agents.length} agent samples)`);
}

main().catch((e) => {
  console.error(e.stack || e.message);
  process.exit(1);
});
