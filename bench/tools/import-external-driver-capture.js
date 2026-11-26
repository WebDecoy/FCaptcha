#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const { loadCorpus, saveSamples, validate } = require('../lib/corpus');
const { toExternalDriverSample } = require('../lib/manual-import');

function parseArgs(argv) {
  const args = { index: 0 };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--report') args.report = argv[++i];
    else if (arg === '--out') args.out = argv[++i];
    else if (arg === '--group') args.group = argv[++i];
    else if (arg === '--scenario') args.scenario = argv[++i];
    else if (arg === '--input') args.input = argv[++i];
    else if (arg === '--notes') args.notes = argv[++i];
    else if (arg === '--expected-client-version') args.expectedClientVersion = argv[++i];
    else if (arg === '--expected-driver-name') args.expectedDriverName = argv[++i];
    else if (arg === '--expected-driver-version') args.expectedDriverVersion = argv[++i];
    else if (arg === '--expected-driver-commit') args.expectedDriverCommit = argv[++i];
    else if (arg === '--index') args.index = Number(argv[++i]);
    else if (arg === '--help' || arg === '-h') args.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return args;
}

function usage() {
  return `Usage:
  node bench/tools/import-external-driver-capture.js \\
    --report bench/test-results/<capture>/report.json \\
    --out bench/corpus/captured/agent-browser-harness-cdp-form-0000.json \\
    --group browser-harness-macbook-cdp-agent \\
    --scenario browser-harness-real-chrome-form \\
    --input "Browser Harness over loopback CDP" \\
    --expected-client-version 1.52.0 \\
    --expected-driver-name browser-harness \\
    --expected-driver-version 0.1.13 \\
    --expected-driver-commit c24e5072ee66f8499bacd663f4f4bcb089bc4492

The output path must not exist. The report must come from camoufox_bench.py's
--external-driver mode. The importer refuses manual, browser-internal,
normalized, incomplete, takeover, unpinned, and provenance-mismatched reports.
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
  const required = [
    'report',
    'out',
    'scenario',
    'input',
    'expectedClientVersion',
    'expectedDriverName',
    'expectedDriverVersion',
    'expectedDriverCommit',
  ];
  const missing = required.filter((name) => !args[name]);
  if (missing.length) {
    throw new Error(`missing required argument(s): ${missing.join(', ')}\n\n${usage()}`);
  }
  requireSlug(args.scenario, 'scenario');
  if (args.group) requireSlug(args.group, 'group');
  requireSlug(args.expectedDriverName, 'expected-driver-name');
  if (!/^[a-f0-9]{40}$/.test(args.expectedDriverCommit)) {
    throw new Error('--expected-driver-commit must be a full lowercase Git SHA');
  }
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(args.expectedDriverVersion)) {
    throw new Error('--expected-driver-version must be semantic');
  }
  if (!Number.isInteger(args.index) || args.index < 0) {
    throw new Error('--index must be a non-negative integer');
  }

  const out = path.resolve(args.out);
  if (fs.existsSync(out)) throw new Error(`refusing to overwrite ${out}`);
  const reportBytes = fs.readFileSync(path.resolve(args.report));
  const report = JSON.parse(reportBytes);
  const sample = validate(toExternalDriverSample(report, args, reportBytes), args.report);
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
