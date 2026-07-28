'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  SuspicionLedger,
  computeChallengeCost,
  BASE_DIFFICULTY,
  BASE_MIN_AGE_MS,
  MAX_MIN_AGE_MS
} = require('./suspicion');

// --- what a clean visitor pays ----------------------------------------------

// The property that matters most: a visitor who has done nothing wrong pays
// exactly what everyone paid before adaptive cost existed. If this drifts, the
// feature has started taxing the people it was designed not to touch.
test('a clean source pays the baseline', () => {
  const cost = computeChallengeCost(0, false, 0, false);
  assert.strictEqual(cost.difficulty, BASE_DIFFICULTY);
  assert.strictEqual(cost.minAgeMs, BASE_MIN_AGE_MS);
});

test('cost escalates with strong verdicts', () => {
  const cases = [
    [0, 4, 1500],
    [1, 4, 4000],
    [2, 4, 4000],
    [3, 5, 8000],
    [5, 5, 8000],
    [6, 5, 15000],
    [50, 5, 15000]
  ];
  for (const [hits, difficulty, minAgeMs] of cases) {
    assert.deepStrictEqual(
      computeChallengeCost(hits, false, 0, false),
      { difficulty, minAgeMs },
      `${hits} strong verdicts`
    );
  }
});

// The escalation must stay on the knob an attacker cannot buy their way out of.
// Difficulty 6 costs a native solver about a millisecond and a budget phone
// about sixteen seconds, so reaching it would be a tax on slow devices and
// nothing else.
test('difficulty never exceeds 5 and minAge never exceeds its cap', () => {
  for (let hits = 0; hits < 100; hits++) {
    for (const dc of [false, true]) {
      for (const ex of [false, true]) {
        const cost = computeChallengeCost(hits, dc, 1000, ex);
        assert.ok(cost.difficulty <= 5, `difficulty reached ${cost.difficulty}`);
        assert.ok(cost.minAgeMs <= MAX_MIN_AGE_MS, `minAge reached ${cost.minAgeMs}`);
      }
    }
  }
});

// A datacenter address used to jump straight to difficulty 5, which charges a
// real person on a corporate VPN or iCloud Private Relay several seconds of
// blocked hashing for having a shared IP.
test('a datacenter address moves time, not difficulty', () => {
  const cost = computeChallengeCost(0, true, 0, false);
  assert.strictEqual(cost.difficulty, BASE_DIFFICULTY);
  assert.ok(cost.minAgeMs > BASE_MIN_AGE_MS);
});

test('rate signals raise only the time floor', () => {
  const busy = computeChallengeCost(0, false, 50, false);
  assert.strictEqual(busy.difficulty, BASE_DIFFICULTY);
  assert.ok(busy.minAgeMs > BASE_MIN_AGE_MS);

  const limited = computeChallengeCost(0, false, 50, true);
  assert.strictEqual(limited.difficulty, BASE_DIFFICULTY);
  assert.ok(limited.minAgeMs > busy.minAgeMs);
});

// --- the ledger --------------------------------------------------------------

// Marginal verdicts are exactly the case where the scoring might be wrong about
// a real person. Recording them would make the next visitor from that address
// wait for a guess.
test('only strong verdicts are recorded', () => {
  const l = new SuspicionLedger();
  for (const score of [0, 0.3, 0.5, 0.7, 0.79]) l.record('site', '203.0.113.7', score);
  assert.strictEqual(l.count('site', '203.0.113.7'), 0);

  l.record('site', '203.0.113.7', 0.8);
  l.record('site', '203.0.113.7', 0.95);
  assert.strictEqual(l.count('site', '203.0.113.7'), 2);
});

// Suspicion is per site key as well as per address, so one site's abusers do
// not price another site's visitors.
test('the ledger is scoped per site and address', () => {
  const l = new SuspicionLedger();
  for (let i = 0; i < 6; i++) l.record('site-a', '203.0.113.7', 0.95);

  assert.strictEqual(l.count('site-b', '203.0.113.7'), 0);
  assert.strictEqual(l.count('site-a', '203.0.113.8'), 0);
  assert.strictEqual(l.count('site-a', '203.0.113.7'), 6);
});

test('an empty address never accumulates', () => {
  const l = new SuspicionLedger();
  l.record('site', '', 0.99);
  assert.strictEqual(l.count('site', ''), 0);
});

test('a non-numeric score is ignored rather than coerced', () => {
  const l = new SuspicionLedger();
  l.record('site', '203.0.113.7', undefined);
  l.record('site', '203.0.113.7', null);
  l.record('site', '203.0.113.7', '0.99');
  assert.strictEqual(l.count('site', '203.0.113.7'), 0);
});

test('retained hits are bounded and still reach the top tier', () => {
  const l = new SuspicionLedger();
  for (let i = 0; i < 48; i++) l.record('site', '203.0.113.7', 0.99);
  const n = l.count('site', '203.0.113.7');
  assert.strictEqual(n, 16);
  assert.strictEqual(computeChallengeCost(n, false, 0, false).minAgeMs, MAX_MIN_AGE_MS);
});

// --- integration with the scoring engine ------------------------------------

test('the engine prices a challenge from the ledger, and the sig covers minAgeMs', () => {
  const fcaptcha = require('./index');
  const engine = fcaptcha.createScoringEngine({ secret: 'test-secret' });

  const clean = engine.generateChallenge('site', '203.0.113.20');
  assert.strictEqual(clean.difficulty, BASE_DIFFICULTY);
  assert.strictEqual(clean.minAgeMs, BASE_MIN_AGE_MS);

  for (let i = 0; i < 6; i++) engine.suspicion.record('site', '203.0.113.21', 0.95);
  const suspicious = engine.generateChallenge('site', '203.0.113.21');
  assert.ok(suspicious.minAgeMs > clean.minAgeMs);
  assert.ok(suspicious.difficulty <= 5);

  // Signing the same challenge with the delay talked down must not reproduce
  // the signature it was issued with.
  const crypto = require('crypto');
  const sign = (minAgeMs) => {
    const { sig, ...rest } = suspicious;
    return crypto
      .createHmac('sha256', 'test-secret')
      .update(JSON.stringify({ ...rest, minAgeMs }))
      .digest('hex');
  };
  assert.strictEqual(
    sign(suspicious.minAgeMs),
    suspicious.sig,
    'the test is not reproducing the server signing input; fix it before trusting the assertion below'
  );
  assert.notStrictEqual(
    sign(BASE_MIN_AGE_MS),
    suspicious.sig,
    'minAgeMs is not covered by the challenge signature — a client could talk its own delay down'
  );
});

// The library was missed by the pass that removed HMAC truncation elsewhere, so
// its tokens carried a 64-bit signature while Go, Python and the standalone
// server all used the full digest.
test('token signatures are full-length', () => {
  const fcaptcha = require('./index');
  const engine = fcaptcha.createScoringEngine({ secret: 'test-secret' });

  const token = engine._generateToken('203.0.113.40', 'site', 0.1);
  const decoded = JSON.parse(Buffer.from(token, 'base64url').toString());
  assert.strictEqual(decoded.sig.length, 64, 'expected a full SHA-256 HMAC, not a truncation');
  assert.strictEqual(engine.verifyToken(token).valid, true);
});
