'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { DEFAULT_EXPORT_URL } = require('./research-import');
const { parseArgs } = require('../run-bench');

test('research export options are explicit and mutually exclusive', () => {
  assert.equal(parseArgs(['node', 'run-bench.js']).researchUrl, null);
  assert.equal(
    parseArgs(['node', 'run-bench.js', '--research-export']).researchUrl,
    DEFAULT_EXPORT_URL
  );
  assert.equal(
    parseArgs(['node', 'run-bench.js', '--research-url', 'https://example.com/api/research/captures']).researchUrl,
    'https://example.com/api/research/captures'
  );
  assert.throws(
    () => parseArgs([
      'node',
      'run-bench.js',
      '--research-export',
      '--research-input',
      '/tmp/export.ndjson',
    ]),
    /cannot be combined/
  );
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--research-url']),
    /requires a value/
  );
});
