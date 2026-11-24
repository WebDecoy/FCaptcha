'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  parseArgs,
  requireSlug,
} = require('../tools/import-manual-capture');

test('manual importer parses a pinned accessibility workflow', () => {
  const args = parseArgs([
    'node', 'import-manual-capture.js',
    '--report', 'report.json',
    '--out', 'sample.json',
    '--group', 'accessibility-screen-reader',
    '--scenario', 'chrome-macos-screen-reader-keyboard',
    '--input', 'VoiceOver and keyboard only',
    '--expected-workflow', 'screen-reader-keyboard-selection',
    '--expected-client-version', '1.51.4',
  ]);

  assert.equal(args.expectedWorkflow, 'screen-reader-keyboard-selection');
  assert.equal(args.expectedClientVersion, '1.51.4');
});

test('manual importer rejects unsafe workflow slugs', () => {
  assert.doesNotThrow(() => requireSlug('screen-reader-keyboard-selection', 'expected-workflow'));
  assert.throws(
    () => requireSlug('../screen-reader', 'expected-workflow'),
    /lowercase hyphenated slug/
  );
});
