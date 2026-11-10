'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { DEFAULT_EXPORT_URL } = require('./research-import');
const { parseArgs } = require('../run-bench');

test('research export options are explicit and mutually exclusive', () => {
  assert.equal(parseArgs(['node', 'run-bench.js']).researchUrl, null);
  assert.equal(parseArgs(['node', 'run-bench.js']).researchStdin, false);
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
    /mutually exclusive/
  );
  assert.equal(
    parseArgs(['node', 'run-bench.js', '--research-stdin']).researchStdin,
    true
  );
  assert.throws(
    () => parseArgs([
      'node',
      'run-bench.js',
      '--research-stdin',
      '--research-input',
      '/tmp/export.ndjson',
    ]),
    /mutually exclusive/
  );
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--research-url']),
    /requires a value/
  );
});

test('research-only mode requires an ephemeral source and cannot gate or persist', () => {
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--research-only']),
    /requires --research/
  );
  assert.equal(
    parseArgs(['node', 'run-bench.js', '--research-only', '--research-stdin']).researchOnly,
    true
  );
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--research-only', '--research-stdin', '--gate']),
    /never gate/
  );
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--research-only', '--research-stdin', '--json', 'out.json']),
    /never persisted/
  );
});
