'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  parseArgs,
  requireSlug,
} = require('../tools/import-external-driver-capture');

test('parses pinned external-driver importer arguments', () => {
  const args = parseArgs([
    'node', 'import-external-driver-capture.js',
    '--report', 'report.json',
    '--out', 'sample.json',
    '--scenario', 'browser-harness-real-chrome-form',
    '--input', 'Browser Harness over loopback CDP',
    '--expected-client-version', '1.51.4',
    '--expected-driver-name', 'browser-harness',
    '--expected-driver-version', '0.1.13',
    '--expected-driver-commit', 'c24e5072ee66f8499bacd663f4f4bcb089bc4492',
    '--index', '4',
  ]);

  assert.equal(args.report, 'report.json');
  assert.equal(args.scenario, 'browser-harness-real-chrome-form');
  assert.equal(args.expectedDriverName, 'browser-harness');
  assert.equal(args.expectedDriverVersion, '0.1.13');
  assert.equal(args.expectedDriverCommit, 'c24e5072ee66f8499bacd663f4f4bcb089bc4492');
  assert.equal(args.index, 4);
});

test('requires stable external-driver slugs', () => {
  assert.doesNotThrow(() => requireSlug('browser-harness', 'expected-driver-name'));
  assert.throws(() => requireSlug('../escape', 'scenario'), /lowercase hyphenated slug/);
  assert.throws(() => requireSlug('BrowserHarness', 'expected-driver-name'), /lowercase hyphenated slug/);
});
