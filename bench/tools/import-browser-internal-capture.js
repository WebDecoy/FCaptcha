#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const { loadCorpus, saveSamples, validate } = require('../lib/corpus');
const { toBrowserInternalSample } = require('../lib/manual-import');

function parseArgs(argv) {
  const args = { index: 0 };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--report') args.report = argv[++i];
    else if (arg === '--out') args.out = argv[++i];
    else if (arg === '--scenario') args.scenario = argv[++i];
    else if (arg === '--input') args.input = argv[++i];
    else if (arg === '--notes') args.notes = argv[++i];
    else if (arg === '--index') args.index = Number(argv[++i]);
    else if (arg === '--help' || arg === '-h') args.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return args;
}

function usage() {
  return `Usage:
  node bench/tools/import-browser-internal-capture.js \\
    --report bench/test-results/<capture>/report.json \\
    --out bench/corpus/captured/agent-browser-internal.json \\
    --scenario chrome-auto-browse-widget --input "browser-internal pointer/keyboard"

The output path must not exist. The report must come from camoufox_bench.py's
--external-agent mode. The importer refuses manual-human, Playwright-driven,
normalized, incomplete, and unlabeled reports.
`;
}

function requireSlug(value, name) {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value || '')) {
    throw new Error(`--${name} must be a lowercase hyphenated slug`);
  }
}

function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write(usage());
    return;
  }
  if (!args.report || !args.out || !args.scenario || !args.input) {
    throw new Error(`--report, --out, --scenario and --input are required\n\n${usage()}`);
  }
  requireSlug(args.scenario, 'scenario');
  if (!Number.isInteger(args.index) || args.index < 0) {
    throw new Error('--index must be a non-negative integer');
  }

  const out = path.resolve(args.out);
  if (fs.existsSync(out)) throw new Error(`refusing to overwrite ${out}`);
  const reportBytes = fs.readFileSync(path.resolve(args.report));
  const report = JSON.parse(reportBytes);
  const sample = validate(toBrowserInternalSample(report, args, reportBytes), args.report);
  if (loadCorpus().some((row) => row.id === sample.id)) {
    throw new Error(`corpus already contains id ${sample.id}`);
  }

  saveSamples(out, [sample]);
  console.log(`wrote ${sample.id} to ${out}`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

module.exports = { parseArgs, requireSlug };
