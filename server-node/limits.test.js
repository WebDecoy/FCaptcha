'use strict';

// Tests for state bounds on client-keyed data (run: `node limits.test.js`).

const assert = require('assert');
const {
  BoundedMap,
  BoundedSet,
  SiteKeyGuard,
  OVERFLOW_SITE_KEY,
} = require('./limits');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

test('BoundedMap evicts least-recently-used, not everything', () => {
  const m = new BoundedMap(3);
  m.set('a', 1).set('b', 2).set('c', 3);
  assert.strictEqual(m.size, 3);

  // Touch 'a' so 'b' becomes the oldest.
  assert.strictEqual(m.get('a'), 1);
  m.set('d', 4);

  assert.strictEqual(m.size, 3, 'must stay at the cap');
  assert.strictEqual(m.has('b'), false, 'LRU victim should be b');
  for (const k of ['a', 'c', 'd']) {
    assert.strictEqual(m.has(k), true, `${k} should survive`);
  }
  assert.strictEqual(m.evictions, 1);
});

// The failure mode being replaced: `if (size > N) clear()` throws away every
// legitimate entry at once, which is the flush an attacker wants.
test('BoundedMap never drops everything at once', () => {
  const m = new BoundedMap(100);
  for (let i = 0; i < 1000; i++) m.set(`k${i}`, i);
  assert.strictEqual(m.size, 100, 'holds exactly the cap');
  assert.strictEqual(m.has('k999'), true, 'most recent retained');
  assert.strictEqual(m.has('k0'), false, 'oldest evicted');
  assert.strictEqual(m.evictions, 900);
});

test('BoundedMap.prune drops only what fails the predicate', () => {
  const m = new BoundedMap(10);
  m.set('keep1', { exp: 100 }).set('drop', { exp: 1 }).set('keep2', { exp: 100 });
  m.prune((v) => v.exp > 50);
  assert.strictEqual(m.size, 2);
  assert.strictEqual(m.has('drop'), false);
});

test('BoundedSet bounds replay-guard membership', () => {
  const s = new BoundedSet(2);
  s.add('x').add('y').add('z');
  assert.strictEqual(s.size, 2);
  assert.strictEqual(s.has('x'), false, 'oldest evicted');
  assert.strictEqual(s.has('z'), true);
});

// The demonstrated behavior: 22 requests from one IP escalate difficulty with a
// fixed siteKey but stay pinned when the siteKey varies, because each new key
// allocates a fresh bucket. After the cap, rotation stops buying fresh state.
test('SiteKeyGuard caps distinct siteKeys per IP', () => {
  const g = new SiteKeyGuard({ maxPerIp: 3 });
  const ip = '203.0.113.9';

  assert.strictEqual(g.normalize('a', ip), 'a');
  assert.strictEqual(g.normalize('b', ip), 'b');
  assert.strictEqual(g.normalize('c', ip), 'c');

  // Beyond the cap everything collapses into one bucket.
  assert.strictEqual(g.normalize('d', ip), OVERFLOW_SITE_KEY);
  assert.strictEqual(g.normalize('e', ip), OVERFLOW_SITE_KEY);

  // Keys already seen keep working — a real tenant is not punished.
  assert.strictEqual(g.normalize('b', ip), 'b');

  // A different IP has its own budget.
  assert.strictEqual(g.normalize('z', '198.51.100.4'), 'z');
  assert.ok(g.overflows >= 2);
});

test('SiteKeyGuard rotation collapses into one shared bucket', () => {
  const g = new SiteKeyGuard({ maxPerIp: 4 });
  const ip = '203.0.113.10';
  const buckets = new Set();
  for (let i = 0; i < 200; i++) buckets.add(g.normalize(`rotate-${i}`, ip));

  // 4 real buckets + the overflow bucket, not 200.
  assert.strictEqual(buckets.size, 5, `expected 5 distinct buckets, got ${buckets.size}`);
  assert.strictEqual(buckets.has(OVERFLOW_SITE_KEY), true);
});

test('SiteKeyGuard allowlist is opt-in and off by default', () => {
  // Unset: any key accepted (zero-config self-hosting preserved).
  const open = SiteKeyGuard.fromEnv({});
  assert.strictEqual(open.allowlist, null);
  assert.strictEqual(open.normalize('anything', '203.0.113.1'), 'anything');

  // Set: unlisted keys never allocate their own state.
  const closed = SiteKeyGuard.fromEnv({ FCAPTCHA_SITE_KEYS: 'real-site, other-site' });
  assert.strictEqual(closed.normalize('real-site', '203.0.113.2'), 'real-site');
  assert.strictEqual(closed.normalize('other-site', '203.0.113.2'), 'other-site');
  assert.strictEqual(closed.normalize('junk', '203.0.113.2'), OVERFLOW_SITE_KEY);
  assert.strictEqual(closed.rejectedByAllowlist, 1);
});

test('SiteKeyGuard tracking table is itself bounded', () => {
  const g = new SiteKeyGuard({ maxPerIp: 2, maxTrackedIps: 10 });
  for (let i = 0; i < 500; i++) g.normalize('site', `198.51.100.${i}`);
  assert.strictEqual(g.seen.size, 10, 'the guard must not become the leak it prevents');
});

test('SiteKeyGuard handles missing/blank input without throwing', () => {
  const g = new SiteKeyGuard();
  assert.strictEqual(g.normalize(undefined, '203.0.113.3'), 'default');
  assert.strictEqual(g.normalize('', '203.0.113.3'), 'default');
  assert.strictEqual(g.normalize('k', undefined), 'k', 'no IP: pass through, nothing to bound');
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
