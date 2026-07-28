'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { neutralIpAt, neutralIpFor, NEUTRAL_POOL_SIZE } = require('./replay');

// These exist because the harness had no tests, and the defect they guard
// against was invisible for exactly that reason.
//
// Sample addresses used to be a hash of the sample id, which put 180 samples
// into a 508-address space. By the birthday bound they collided constantly: 25
// shared addresses, 24 of them putting an agent and a human on the same IP. The
// corpus was manufacturing shared egress its labels never claimed, so every
// per-source measurement was being taken against a fiction — and nothing
// noticed until a per-source signal existed to notice.

test('every position gets a distinct address', () => {
  const seen = new Set();
  for (let i = 0; i < NEUTRAL_POOL_SIZE; i++) {
    const ip = neutralIpAt(i);
    assert.ok(!seen.has(ip), `position ${i} reused ${ip}`);
    seen.add(ip);
  }
  assert.strictEqual(seen.size, NEUTRAL_POOL_SIZE);
});

test('addresses stay inside the RFC 5737 documentation ranges', () => {
  // Reserved, routable nowhere, and in no datacenter CIDR list — so an address
  // never becomes a signal by accident.
  const allowed = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.(\d{1,3})$/;
  for (let i = 0; i < NEUTRAL_POOL_SIZE; i++) {
    const m = allowed.exec(neutralIpAt(i));
    assert.ok(m, `${neutralIpAt(i)} is outside the documentation ranges`);
    const host = Number(m[2]);
    assert.ok(host >= 1 && host <= 254, `${neutralIpAt(i)} is a network or broadcast address`);
  }
});

// Silently wrapping around would reintroduce the collisions this replaced.
test('outgrowing the pool throws rather than wrapping', () => {
  assert.throws(() => neutralIpAt(NEUTRAL_POOL_SIZE), /outgrown the neutral address pool/);
});

test('assignment is stable across calls', () => {
  assert.strictEqual(neutralIpAt(0), neutralIpAt(0));
  assert.strictEqual(neutralIpAt(700), neutralIpAt(700));
});

// Kept for one-off replays, and collision-prone by construction. The test
// records that it is not safe for a panel, so nobody reaches for it there.
test('the hashed variant is deterministic but may collide', () => {
  assert.strictEqual(neutralIpFor('a/b/0000'), neutralIpFor('a/b/0000'));

  const seen = new Map();
  let collisions = 0;
  for (let i = 0; i < 200; i++) {
    const ip = neutralIpFor(`sample/${i}`);
    if (seen.has(ip)) collisions++;
    seen.set(ip, i);
  }
  assert.ok(
    collisions > 0,
    'if this stops colliding the pool grew; prefer neutralIpAt for corpora regardless'
  );
});
