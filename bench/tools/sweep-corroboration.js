#!/usr/bin/env node
'use strict';

/**
 * Sweeps the two constants behind the behavioural corroboration floor.
 *
 * The floor exists because a source-patched browser scrubs every JS-observable
 * automation flag, so it trips no headless, cdp, fingerprint, datacenter or bot
 * category. Those weights total 0.59, and the weighted sum silently keeps all of
 * it — leaving such a browser a ceiling of 0.41 against a 0.5 threshold. It
 * cannot be blocked however obviously robotic its movement is.
 *
 * The rule under test: when N behavioural categories independently reach
 * `agreeAt`, floor the final score at `floor`. Same shape as the existing
 * dispositive floor, but earned by corroboration rather than self-declaration.
 *
 * Two constants, and picking them by intuition already failed once — a 3-of-4
 * rule chosen because it "felt conservative" produced results byte-identical to
 * the baseline, because the adversary reaches 0.5 in only two categories. So
 * this reports the whole grid, including where the rule stops firing and where
 * it starts catching humans.
 *
 * Usage: node bench/tools/sweep-corroboration.js [--derive N]
 */

const { deriveVariant, loadCorpus } = require('../lib/corpus');
const { replayCorpus } = require('../lib/replay');
const { makeRng } = require('../lib/rng');

const WEIGHTS = {
  vision_ai: 0.15, headless: 0.15, automation: 0.08, cdp: 0.12,
  behavioral: 0.18, fingerprint: 0.08, rate_limit: 0.01,
  datacenter: 0.07, tor_vpn: 0.01, bot: 0.13, declared_ai: 0.02,
};

// The categories a browser trips by how it moves rather than by what it is.
const BEHAVIOURAL = ['vision_ai', 'behavioral', 'automation', 'cdp'];

const SELF_DECLARED = [/^WebDriver detected$/, /^CDP automation detected/];
const isSelfDeclared = (d) => SELF_DECLARED.some((re) => re.test(d.reason || ''));

function categoryNoisyOr(dets) {
  let survive = 1;
  for (const d of dets) survive *= 1 - Math.max(0, Math.min(1, d.score * d.confidence));
  return 1 - survive;
}

function categoriesOf(detections) {
  const byCat = {};
  for (const d of detections) (byCat[d.category] ||= []).push(d);
  const out = {};
  for (const [c, ds] of Object.entries(byCat)) out[c] = categoryNoisyOr(ds);
  return out;
}

/** Score one sample under a given (agreeAt, minAgree, floor). */
function score(detections, agreeAt, minAgree, floor) {
  const cats = categoriesOf(detections);
  const base = Math.min(
    1,
    Object.entries(WEIGHTS).reduce((t, [c, w]) => t + (cats[c] || 0) * w, 0)
  );
  if (detections.some(isSelfDeclared)) return Math.max(base, 0.9);
  const agreeing = BEHAVIOURAL.filter((c) => (cats[c] || 0) >= agreeAt).length;
  return agreeing >= minAgree ? Math.max(base, floor) : base;
}

/** How many behavioural categories agree, for diagnosing where a rule fires. */
const agreementCount = (detections, agreeAt) =>
  BEHAVIOURAL.filter((c) => (categoriesOf(detections)[c] || 0) >= agreeAt).length;

async function main() {
  const i = process.argv.indexOf('--derive');
  const derive = i > -1 ? Number(process.argv[i + 1]) : 8;

  const base = loadCorpus().filter((s) => !s.unmeasured);
  const rng = makeRng(1);
  const corpus = [...base];
  let n = 0;
  for (const s of base) {
    if (s.provenance !== 'captured') continue;
    for (let k = 0; k < derive; k++) {
      const v = deriveVariant(s, rng, n++);
      if (s.clientIp) v.clientIp = s.clientIp;
      corpus.push(v);
    }
  }

  console.log(`replaying ${corpus.length} samples once, then sweeping offline\n`);
  const results = (await replayCorpus('http://localhost:3000', corpus, {})).filter((r) => !r.error);

  const humans = results.filter((r) => r.sample.label === 'human');
  const agents = results.filter((r) => r.sample.label === 'agent');

  // Where the rule *could* fire, before choosing anything. If humans routinely
  // reach the same agreement count as agents, no floor value saves the rule.
  console.log('Behavioural agreement, by population');
  console.log('  (how many of the four categories reach the threshold)\n');
  console.log('  THRESHOLD   HUMANS reaching 2+/3+/4+      AGENTS reaching 2+/3+/4+');
  for (const agreeAt of [0.3, 0.4, 0.5, 0.6, 0.7]) {
    const count = (rows, min) =>
      rows.filter((r) => agreementCount(r.detections, agreeAt) >= min).length;
    console.log(
      `  ${agreeAt.toFixed(2)}        ` +
        `${String(count(humans, 2)).padStart(3)}/${String(count(humans, 3)).padStart(3)}/${String(count(humans, 4)).padStart(3)}` +
        ` of ${humans.length}`.padEnd(14) +
        `${String(count(agents, 2)).padStart(3)}/${String(count(agents, 3)).padStart(3)}/${String(count(agents, 4)).padStart(3)}` +
        ` of ${agents.length}`
    );
  }

  console.log('\n\nGrid: worst agent / worst human / margin / human FPR at 0.5\n');
  console.log('  AGREE@  N  FLOOR   AGENT min   HUMAN max   MARGIN   FPR     VERDICT');
  console.log('  ' + '─'.repeat(74));

  const rows = [];
  for (const agreeAt of [0.3, 0.4, 0.5, 0.6, 0.7]) {
    for (const minAgree of [2, 3]) {
      for (const floor of [0.5, 0.6, 0.7, 0.8]) {
        const h = humans.map((r) => score(r.detections, agreeAt, minAgree, floor));
        const a = agents.map((r) => score(r.detections, agreeAt, minAgree, floor));
        const humanMax = Math.max(...h);
        const agentMin = Math.min(...a);
        const fpr = h.filter((s) => s >= 0.5).length / h.length;
        const margin = agentMin - humanMax;

        let verdict = '';
        if (fpr > 0) verdict = 'FP — rejects humans';
        else if (agentMin < 0.5) verdict = 'agent still allowed';
        else verdict = 'separates';

        rows.push({ agreeAt, minAgree, floor, agentMin, humanMax, margin, fpr, verdict });
        console.log(
          `  ${agreeAt.toFixed(2)}    ${minAgree}  ${floor.toFixed(2)}    ` +
            `${agentMin.toFixed(3).padStart(7)}     ${humanMax.toFixed(3).padStart(7)}   ` +
            `${margin.toFixed(3).padStart(6)}   ${(fpr * 100).toFixed(1).padStart(5)}%  ${verdict}`
        );
      }
    }
  }

  const usable = rows.filter((r) => r.verdict === 'separates');
  console.log(`\n${usable.length} of ${rows.length} combinations separate the populations.`);
  if (usable.length) {
    const best = usable.reduce((a, b) => (b.margin > a.margin ? b : a));
    console.log(
      `Widest margin: agreeAt=${best.agreeAt} N=${best.minAgree} floor=${best.floor} ` +
        `(margin ${best.margin.toFixed(3)})`
    );
    console.log(
      '\nPrefer a setting in the middle of a stable region over the single widest\n' +
        'margin: this is one synthetic adversary sample, so a value that only works\n' +
        'at an exact threshold is fitted to it rather than measured.'
    );
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
