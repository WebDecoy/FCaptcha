'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  parseArgs,
  requireSlug,
} = require('../tools/import-browser-internal-capture');

test('parses browser-internal importer arguments', () => {
  const args = parseArgs([
    'node', 'import-browser-internal-capture.js',
    '--report', 'report.json',
    '--out', 'sample.json',
    '--scenario', 'chrome-auto-browse-widget',
    '--input', 'browser-internal pointer and keyboard',
    '--expected-client-version', '1.51.4',
    '--index', '3',
  ]);

  assert.equal(args.report, 'report.json');
  assert.equal(args.scenario, 'chrome-auto-browse-widget');
  assert.equal(args.expectedClientVersion, '1.51.4');
  assert.equal(args.index, 3);
});

test('requires a stable corpus scenario slug', () => {
  assert.doesNotThrow(() => requireSlug('chrome-auto-browse-widget', 'scenario'));
  assert.throws(() => requireSlug('../escape', 'scenario'), /lowercase hyphenated slug/);
  assert.throws(() => requireSlug('Uppercase', 'scenario'), /lowercase hyphenated slug/);
});
