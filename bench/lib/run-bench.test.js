'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { DEFAULT_EXPORT_URL } = require('./research-import');
const { parseArgs, selectHostedSmokeSamples } = require('../run-bench');

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

test('hosted smoke mode is explicit, HTTPS-only, and fixes its safe workload', () => {
  const args = parseArgs([
    'node', 'run-bench.js',
    '--hosted-smoke',
    '--server', 'https://fcaptcha.example.com',
    '--site-key', 'demo-site-key',
    '--origin', 'https://demo.example.com',
  ]);
  assert.equal(args.hostedSmoke, true);
  assert.equal(args.derive, 0);
  assert.equal(args.concurrency, 1);
  assert.equal(args.siteKey, 'demo-site-key');
  assert.equal(args.origin, 'https://demo.example.com');

  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--hosted-smoke', '--site-key', 'key']),
    /explicit --server/
  );
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--hosted-smoke', '--server', 'http://example.com', '--site-key', 'key']),
    /HTTPS/
  );
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--hosted-smoke', '--server', 'https://example.com']),
    /requires --site-key/
  );
  for (const extra of [['--gate'], ['--json', 'out.json'], ['--derive', '1'], ['--concurrency', '2']]) {
    assert.throws(
      () => parseArgs([
        'node', 'run-bench.js', '--hosted-smoke', '--server', 'https://example.com',
        '--site-key', 'key', ...extra,
      ]),
      /hosted-smoke/
    );
  }
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--site-key', 'key']),
    /only valid/
  );
  assert.throws(
    () => parseArgs(['node', 'run-bench.js', '--origin', 'https://demo.example.com']),
    /only valid/
  );
  for (const origin of ['http://demo.example.com', 'https://demo.example.com/path', 'not-a-url']) {
    assert.throws(
      () => parseArgs([
        'node', 'run-bench.js', '--hosted-smoke', '--server', 'https://example.com',
        '--site-key', 'key', '--origin', origin,
      ]),
      /--origin requires/
    );
  }
});

test('hosted smoke selects one human and agent for each scoring endpoint', () => {
  const sample = (label, endpoint, index) => ({
    id: `${label}/${index}`,
    label,
    group: `${label}-${index}`,
    provenance: 'captured',
    capture: endpoint ? { endpoint } : undefined,
  });
  const corpus = [
    sample('human', null, 0),
    sample('human', null, 1),
    sample('agent', null, 2),
    sample('human', '/api/score', 3),
    sample('agent', '/api/score', 4),
  ];
  const selected = selectHostedSmokeSamples(corpus);
  assert.deepEqual(selected.map((entry) => entry.id), [
    'human/0',
    'agent/2',
    'human/3',
    'agent/4',
  ]);
});
