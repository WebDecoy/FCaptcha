'use strict';

// Tests for HTTP header analysis (run: `node detection.test.js`).
//
// These cover a false positive the bench human panel surfaced: forwarding
// headers were scored as suspicious unconditionally, so every visitor to every
// deployment behind a reverse proxy carried a permanent bot detection.

const assert = require('assert');
const { analyzeHeaders } = require('./detection');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

const browserHeaders = {
  accept: 'text/html,application/xhtml+xml',
  'accept-language': 'en-US,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
};

const suspicious = (dets) =>
  dets.filter((d) => d.reason.startsWith('Suspicious header present')).map((d) => d.reason.split(': ')[1]);

test('forwarding headers are not suspicious from a trusted proxy', () => {
  const dets = analyzeHeaders(
    { ...browserHeaders, 'x-forwarded-for': '203.0.113.9' },
    { peerTrusted: true }
  );
  assert.deepStrictEqual(suspicious(dets), [], 'a proxy adding XFF is doing its job');
});

test('forwarding headers ARE suspicious from an untrusted peer', () => {
  // Nothing legitimate about a direct client claiming to forward for someone.
  const dets = analyzeHeaders(
    { ...browserHeaders, 'x-forwarded-for': '203.0.113.9' },
    { peerTrusted: false }
  );
  assert.deepStrictEqual(suspicious(dets), ['x-forwarded-for']);
});

test('defaults to the stricter behaviour when the caller does not say', () => {
  const dets = analyzeHeaders({ ...browserHeaders, 'x-real-ip': '203.0.113.9' });
  assert.deepStrictEqual(suspicious(dets), ['x-real-ip']);
});

// Cloudflare alone adds three of these. Unconditionally scoring them meant a
// Cloudflare-fronted deployment scored three bot detections on every request.
test('a full CDN header set is clean behind a trusted proxy', () => {
  const dets = analyzeHeaders(
    {
      ...browserHeaders,
      'x-forwarded-for': '203.0.113.9',
      'cf-connecting-ip': '203.0.113.9',
      'true-client-ip': '203.0.113.9',
      via: '1.1 cloudflare',
    },
    { peerTrusted: true }
  );
  assert.deepStrictEqual(suspicious(dets), []);
});

test('x-requested-with stays suspicious regardless of the peer', () => {
  // Set by XHR libraries, not by proxies — trusting the peer says nothing
  // about it, so the trust gate must not cover it.
  for (const peerTrusted of [true, false]) {
    const dets = analyzeHeaders(
      { ...browserHeaders, 'x-requested-with': 'XMLHttpRequest' },
      { peerTrusted }
    );
    assert.deepStrictEqual(
      suspicious(dets),
      ['x-requested-with'],
      `should fire with peerTrusted=${peerTrusted}`
    );
  }
});

test('unrelated header detections still work', () => {
  const dets = analyzeHeaders({ 'user-agent': 'curl/8.0' }, { peerTrusted: true });
  assert.ok(
    dets.some((d) => /Missing \d+ expected browser headers/.test(d.reason)),
    'missing-header detection should be unaffected by the trust gate'
  );
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL ${name}\n       ${err.message}`);
  }
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed === 0 ? 0 : 1);
