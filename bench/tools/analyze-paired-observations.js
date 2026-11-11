#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { analyzePairs } = require('../lib/paired-analysis');
const { loadCorpus } = require('../lib/corpus');

function parseArgs(argv) {
  const args = {
    agentGroup: 'browser-internal',
    controlGroup: 'browser-internal-control',
    top: 20,
    minCoverage: 1,
    json: null,
  };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--agent-group') args.agentGroup = argv[++i];
    else if (arg === '--control-group') args.controlGroup = argv[++i];
    else if (arg === '--top') args.top = Number(argv[++i]);
    else if (arg === '--min-coverage') args.minCoverage = Number(argv[++i]);
    else if (arg === '--json') args.json = argv[++i];
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!Number.isInteger(args.top) || args.top < 1) throw new Error('--top must be a positive integer');
  if (!(args.minCoverage > 0 && args.minCoverage <= 1)) {
    throw new Error('--min-coverage must be greater than 0 and at most 1');
  }
  return args;
}

function number(value) {
  if (!Number.isFinite(value)) return '-';
  if (Math.abs(value) >= 1000 || (Math.abs(value) > 0 && Math.abs(value) < 0.001)) {
    return value.toExponential(3);
  }
  return Number(value.toFixed(4)).toString();
}

function printReport(result, top) {
  console.log('FCaptcha paired observation analysis');
  console.log('====================================');
  console.log(`${result.pairCount} captured pair(s): ${result.pairKeys.join(', ')}`);
  console.log(`${result.capturedHumanCount} captured human sample(s) used for zero-FP screening.`);
  console.log('Derived and self-reported samples are excluded. Array elements are summarized, not aligned by index.');
  console.log('');

  if (result.promotionCandidates.length) {
    console.log(`PROMOTION REVIEW: ${result.promotionCandidates.length} corpus separator(s) survived all checks.`);
    console.log('These are research candidates, not authorization to enforce; independent captures are still required.');
  } else {
    console.log('NO PROMOTION CANDIDATE: no single observation caught every agent with zero captured-human');
    console.log('false positives, consistent pair direction, and complete leave-one-pair-out detection.');
  }
  console.log('');
  console.log('Top zero-FP candidates on the captured corpus');
  console.log('CAUGHT  LOO    DIR  DELTA    THRESHOLD  MODES          FEATURE');
  console.log('------  -----  ---  -------  ---------  -------------  -------');
  for (const feature of result.features.filter((item) => item.caught > 0).slice(0, top)) {
    const loo = `${feature.looCaught}/${feature.totalAgents}`;
    const direction = feature.direction || 'set';
    const delta = feature.kind === 'numeric' ? number(feature.cliffsDelta) : '-';
    const threshold = feature.kind === 'numeric'
      ? `${feature.direction === 'high' ? '>' : '<'}${number(feature.threshold)}`
      : feature.value === undefined ? '-' : JSON.stringify(feature.value).slice(0, 10);
    const modes = feature.modes
      ? Object.entries(feature.modes)
        .map(([mode, stats]) => `${mode[0]}${stats.caught}/${stats.total}`)
        .join(',')
      : '-';
    console.log(
      `${`${feature.caught}/${feature.totalAgents}`.padEnd(7)} ` +
      `${loo.padEnd(6)} ${direction.padEnd(4)} ${delta.padEnd(8)} ${threshold.padEnd(10)} ` +
      `${modes.padEnd(14)} ${feature.path}`
    );
  }
  if (!result.features.some((item) => item.caught > 0)) console.log('(none)');
  console.log('');

  const strongest = result.features
    .filter((feature) => feature.kind === 'numeric')
    .sort((a, b) => Math.abs(b.cliffsDelta) - Math.abs(a.cliffsDelta))
    .slice(0, Math.min(top, 10));
  console.log('Largest paired distribution shifts (interesting, not necessarily safe)');
  console.log('DELTA    CONSISTENCY  OVERLAP  AGENT MED  CONTROL MED  FEATURE');
  console.log('-------  -----------  -------  ---------  -----------  -------');
  for (const feature of strongest) {
    console.log(
      `${number(feature.cliffsDelta).padEnd(8)} ` +
      `${number(feature.pairDirections.consistency).padEnd(12)} ` +
      `${number(feature.ranges.overlapRatio).padEnd(8)} ` +
      `${number(feature.ranges.agent.median).padEnd(10)} ` +
      `${number(feature.ranges.control.median).padEnd(12)} ${feature.path}`
    );
  }

  const bestPartial = result.features.find((feature) => feature.caught > 0);
  console.log('');
  console.log('Next evidence');
  if (bestPartial) {
    const modeText = bestPartial.modes
      ? Object.entries(bestPartial.modes)
        .map(([mode, stats]) => `${mode} ${stats.caught}/${stats.total}`)
        .join(', ')
      : 'mode split unavailable';
    const missed = result.pairKeys.filter((key) => !bestPartial.caughtKeys.includes(key));
    console.log(`Best partial candidate: ${bestPartial.path} (${bestPartial.caught}/${bestPartial.totalAgents}; ${modeText}).`);
    console.log(`It misses: ${missed.join(', ') || '(none)'}.`);
  }
  if (!result.promotionCandidates.length) {
    console.log('Collect new paired widget and invisible runs on an independent machine/profile before retuning.');
    console.log('Derived variants do not increase confidence, and no listed threshold is approved for enforcement.');
  }
}

function main() {
  const args = parseArgs(process.argv);
  const result = analyzePairs(loadCorpus(), args);
  printReport(result, args.top);
  if (args.json) {
    const destination = path.resolve(args.json);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, `${JSON.stringify(result, null, 2)}\n`);
    console.log(`\nwrote ${destination}`);
  }
}

if (require.main === module) main();

module.exports = { parseArgs, printReport };
