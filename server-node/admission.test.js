'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { AdmissionLimiter, ChallengeMap } = require('./admission');
const { ipBinding } = require('./ip-binding');

test('source quota survives key churn and capacity recovers after expiration', () => {
  let now = 0;
  const limiter = new AdmissionLimiter({ maxEntries: 2, now: () => now });
  assert.equal(limiter.allow('victim', 1), true);
  assert.equal(limiter.allow('attacker', 1), true);
  assert.equal(limiter.allow('rotated', 1), false);
  assert.equal(limiter.allow('victim', 1), false);
  now = 60001;
  assert.equal(limiter.allow('rotated', 1), true);
});

test('full challenge store preserves a live challenge and prunes expired ones', () => {
  const store = new ChallengeMap(1);
  store.set('live', { expiresAt: Date.now() + 60000 });
  assert.throws(() => store.set('flood', { expiresAt: Date.now() + 60000 }), /store_full/);
  assert.ok(store.has('live'));
  store.get('live').expiresAt = 0;
  store.set('new', { expiresAt: Date.now() + 60000 });
  assert.equal(store.size, 1);
  assert.ok(store.has('new'));
});

test('IP binding is canonical, keyed and full length', () => {
  assert.equal(ipBinding('first', '::ffff:192.0.2.1'), ipBinding('first', '192.0.2.1'));
  assert.equal(ipBinding('first', '2001:0db8:0:0::1'), ipBinding('first', '2001:db8::1'));
  assert.notEqual(ipBinding('first', '192.0.2.1'), ipBinding('second', '192.0.2.1'));
  assert.equal(ipBinding('first', '192.0.2.1').length, 64);
});
