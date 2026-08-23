/**
 * Tests for trusted-proxy client IP resolution.
 *
 * Run: node clientip.test.js
 */

const assert = require('assert');
const { ProxyTrust, networkIdentity } = require('./clientip');

const DEFAULT_SPEC = '127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16';

// Minimal stand-in for an Express request.
function request(remoteAddress, headers = {}) {
  const lowered = {};
  for (const [k, v] of Object.entries(headers)) lowered[k.toLowerCase()] = v;
  return { socket: { remoteAddress }, headers: lowered };
}

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

test('challenge network identity uses IPv4 /24 and IPv6 /56', () => {
  assert.strictEqual(networkIdentity('192.0.2.1'), networkIdentity('192.0.2.254'));
  assert.notStrictEqual(networkIdentity('192.0.2.1'), networkIdentity('192.0.3.1'));
  assert.strictEqual(networkIdentity('2001:db8:abcd:1200::1'), networkIdentity('2001:db8:abcd:12ff::2'));
  assert.notStrictEqual(networkIdentity('2001:db8:abcd:1200::1'), networkIdentity('2001:db8:abcd:1300::1'));
});

// The bypass this file exists to prevent: a caller reaching the server directly
// claims a residential IP and expects the datacenter/Tor/rate-limit checks to
// see it. 159.65.1.1 is a DigitalOcean range in detection.js's list.
test('headers from an untrusted peer are ignored', () => {
  const trust = new ProxyTrust(DEFAULT_SPEC);
  const spoofs = [
    { 'X-Real-IP': '73.15.22.100' },
    { 'X-Forwarded-For': '73.15.22.100' },
    { 'X-Real-IP': '73.15.22.100', 'X-Forwarded-For': '8.8.8.8' },
    { 'X-Forwarded-For': '73.15.22.100, 1.1.1.1, 2.2.2.2' }
  ];
  for (const headers of spoofs) {
    assert.strictEqual(
      trust.clientIP(request('159.65.1.1', headers)),
      '159.65.1.1',
      `spoofed header honoured: ${JSON.stringify(headers)}`
    );
  }
});

test('headers from a trusted proxy are honoured', () => {
  const trust = new ProxyTrust(DEFAULT_SPEC);
  const cases = [
    ['x-real-ip from loopback nginx', '127.0.0.1', { 'X-Real-IP': '73.15.22.100' }, '73.15.22.100'],
    ['x-forwarded-for from private proxy', '10.0.1.5', { 'X-Forwarded-For': '73.15.22.100' }, '73.15.22.100'],
    // The client prepended a fake hop; the rightmost untrusted entry is still
    // the address our edge actually accepted.
    ['client-prepended chain', '127.0.0.1', { 'X-Forwarded-For': '1.2.3.4, 73.15.22.100' }, '73.15.22.100'],
    // Two real proxies in front of us: skip our own, keep the client.
    ['trusted hops skipped right to left', '10.0.1.5', { 'X-Forwarded-For': '73.15.22.100, 10.0.1.9, 192.168.1.2' }, '73.15.22.100'],
    ['x-real-ip wins over x-forwarded-for', '127.0.0.1', { 'X-Real-IP': '73.15.22.100', 'X-Forwarded-For': '1.2.3.4' }, '73.15.22.100'],
    ['malformed hop falls back to peer', '127.0.0.1', { 'X-Forwarded-For': '73.15.22.100, unknown' }, '127.0.0.1'],
    ['no headers falls back to peer', '127.0.0.1', {}, '127.0.0.1'],
    ['entirely trusted chain falls back to peer', '10.0.1.5', { 'X-Forwarded-For': '10.0.1.9' }, '10.0.1.5']
  ];
  for (const [name, peer, headers, want] of cases) {
    assert.strictEqual(trust.clientIP(request(peer, headers)), want, name);
  }
});

// The value handed to isDatacenterIP has to be a bare, dotted address or CIDR
// matching silently fails.
test('addresses are normalized', () => {
  const trust = new ProxyTrust(DEFAULT_SPEC);
  assert.strictEqual(trust.clientIP(request('::ffff:159.65.1.1')), '159.65.1.1');
  assert.strictEqual(trust.clientIP(request('2001:db8::1')), '2001:db8::1');
  // An IPv4-mapped loopback peer must still be recognised as trusted.
  assert.strictEqual(
    trust.clientIP(request('::ffff:127.0.0.1', { 'X-Real-IP': '73.15.22.100' })),
    '73.15.22.100'
  );
  // An IPv6 peer is not matched against IPv4 ranges (and must not throw).
  assert.strictEqual(trust.clientIP(request('2001:db8::1', { 'X-Real-IP': '73.15.22.100' })), '2001:db8::1');
});

test('spec forms: wildcard, none, empty, bare IP, invalid entries', () => {
  const headers = { 'X-Real-IP': '73.15.22.100' };

  assert.strictEqual(new ProxyTrust('*').clientIP(request('159.65.1.1', headers)), '73.15.22.100');
  assert.strictEqual(new ProxyTrust('none').clientIP(request('127.0.0.1', headers)), '127.0.0.1');
  assert.strictEqual(new ProxyTrust('').clientIP(request('127.0.0.1', headers)), '127.0.0.1');

  const single = new ProxyTrust('203.0.113.7');
  assert.strictEqual(single.clientIP(request('203.0.113.7', headers)), '73.15.22.100');
  assert.strictEqual(single.clientIP(request('203.0.113.8', headers)), '203.0.113.8');

  // A typo in one entry must not discard the valid ones.
  const mixed = new ProxyTrust('not-an-ip, 999.0.0.1/8, 127.0.0.0/8');
  assert.strictEqual(mixed.clientIP(request('127.0.0.1', headers)), '73.15.22.100');
});

test('fromEnv distinguishes unset from empty', () => {
  const headers = { 'X-Real-IP': '73.15.22.100' };

  // Unset: private/loopback defaults apply.
  const unset = ProxyTrust.fromEnv({});
  assert.strictEqual(unset.clientIP(request('127.0.0.1', headers)), '73.15.22.100');
  assert.strictEqual(unset.clientIP(request('159.65.1.1', headers)), '159.65.1.1');

  // Explicitly empty: trust nothing.
  const empty = ProxyTrust.fromEnv({ TRUSTED_PROXIES: '' });
  assert.strictEqual(empty.clientIP(request('127.0.0.1', headers)), '127.0.0.1');
});

// A client that can set its own JA3 presents a stock Chrome fingerprint and
// erases the signal, so the header is only read from a trusted proxy.
test('trustedHeader gates JA3', () => {
  const trust = new ProxyTrust(DEFAULT_SPEC);
  const ja3 = 'cd08e31494f9531f560d64c695473da9';
  assert.strictEqual(trust.trustedHeader(request('159.65.1.1', { 'X-JA3-Hash': ja3 }), 'x-ja3-hash'), '');
  assert.strictEqual(trust.trustedHeader(request('127.0.0.1', { 'X-JA3-Hash': ja3 }), 'x-ja3-hash'), ja3);
});

// The misconfiguration hint: an unlisted reverse proxy and a spoofing client look
// identical here, and the silent failure (every visitor collapsing onto one
// address) is the expensive one, so it must be logged and bounded.
test('untrusted forwarding headers are warned about, once, boundedly', () => {
  const trust = new ProxyTrust(DEFAULT_SPEC);
  const lines = [];
  const original = console.warn;
  console.warn = (msg) => lines.push(msg);
  try {
    // No forwarding headers, and the normal trusted path: both silent.
    trust.clientIP(request('159.65.1.1'));
    trust.clientIP(request('127.0.0.1', { 'X-Real-IP': '73.15.22.100' }));
    assert.strictEqual(lines.length, 0, `warned unexpectedly: ${lines[0]}`);

    // Untrusted peer sending forwarding headers: name the peer and the remedy.
    trust.clientIP(request('159.65.1.1', { 'X-Real-IP': '73.15.22.100' }));
    assert.strictEqual(lines.length, 1);
    assert.ok(lines[0].includes('159.65.1.1'), 'warning omits the peer');
    assert.ok(lines[0].includes('TRUSTED_PROXIES'), 'warning omits the remedy');

    // Bounded: a directly exposed server sees spoofing constantly.
    for (let i = 0; i < 50; i++) {
      trust.clientIP(request('159.65.1.1', { 'X-Forwarded-For': '73.15.22.100' }));
    }
    assert.strictEqual(lines.length, 10, 'warning cap not enforced');
    assert.ok(lines[9].includes('further warnings suppressed'));
  } finally {
    console.warn = original;
  }
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
