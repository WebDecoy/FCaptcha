'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { evaluateExperimental } = require('./experimental');
const { createScoringEngine } = require('./index');
const { experimentalBlockingEnabled } = require('./config');
const fixtures = require('../test/fixtures/experimental-scoring.json');

for (const fixture of fixtures.cases) {
  test(`experimental parity: ${fixture.name}`, () => {
    const before = JSON.stringify(fixture);
    assert.deepEqual(evaluateExperimental(fixture.signals, fixture.productionScore, fixture.detections), fixture.expected);
    assert.deepEqual(evaluateExperimental(fixture.signals, fixture.productionScore, fixture.detections, true),
      { ...fixture.expected, mode: 'block' });
    assert.equal(JSON.stringify(fixture), before, 'observations must not mutate production inputs');
  });
}

test('experimental blocking requires the current policy and library options override the environment', () => {
  const policy = 'stealth-corroboration-v1';
  const enabledEnv = { FCAPTCHA_EXPERIMENTAL_BLOCKING: policy };
  assert.equal(experimentalBlockingEnabled(undefined, {}), false);
  for (const name of [policy, ` ${policy} `]) {
    assert.equal(experimentalBlockingEnabled(undefined, { FCAPTCHA_EXPERIMENTAL_BLOCKING: name }), true);
    assert.equal(experimentalBlockingEnabled(name, {}), true);
  }
  for (const name of ['', '0', 'false', 'no', 'off', 'garbage', '1', 'true', 'yes', 'on', ' TRUE ',
    'stealth-corroboration-v0', 'stealth-corroboration-v2', 'STEALTH-CORROBORATION-V1', '*', `${policy},other`]) {
    assert.equal(experimentalBlockingEnabled(undefined, { FCAPTCHA_EXPERIMENTAL_BLOCKING: name }), false);
    assert.equal(experimentalBlockingEnabled(name, enabledEnv), false);
  }
  assert.equal(experimentalBlockingEnabled(false, enabledEnv), false);
  for (const invalid of [true, 1, null, [], {}]) {
    assert.throws(() => experimentalBlockingEnabled(invalid, enabledEnv), /must be a policy name or false/);
  }
  const saved = process.env.FCAPTCHA_EXPERIMENTAL_BLOCKING;
  try {
    process.env.FCAPTCHA_EXPERIMENTAL_BLOCKING = policy;
    const options = { secret: 'experimental-test-secret-0123456789abcdef0123456789' };
    assert.equal(createScoringEngine(options).experimentalBlocking, true);
    assert.equal(createScoringEngine({ ...options, experimentalBlocking: false }).experimentalBlocking, false);
    assert.equal(createScoringEngine({ ...options, experimentalBlocking: 'stealth-corroboration-v0' }).experimentalBlocking, false);
    process.env.FCAPTCHA_EXPERIMENTAL_BLOCKING = 'stealth-corroboration-v2';
    assert.equal(createScoringEngine(options).experimentalBlocking, false);
    assert.equal(createScoringEngine({ ...options, experimentalBlocking: policy }).experimentalBlocking, true);
  } finally {
    if (saved === undefined) delete process.env.FCAPTCHA_EXPERIMENTAL_BLOCKING;
    else process.env.FCAPTCHA_EXPERIMENTAL_BLOCKING = saved;
  }
});

for (const blocking of [false, true]) {
  test(`experimental blocking=${blocking}: gate follows config; score and challenge cost stay unchanged`, () => {
    const engine = createScoringEngine({ secret: 'experimental-test-secret-0123456789abcdef0123456789', experimentalBlocking: blocking ? 'stealth-corroboration-v1' : false });
    const ip = '203.0.113.87';
    const site = 'experimental';
    const challenge = engine.generateChallenge(site, ip, { difficulty: 1, scaleByReputation: false });
    engine.powStore.challenges.get(challenge.id).timestamp -= 2000;
    const signals = {
      behavioral: { totalPoints: 60, trajectoryLength: 400, approachPoints: 12,
        approachDirectness: 0.4, microTremorScore: 0.5, velocityVariance: 0.5,
        interactionDuration: 4200, inputForensics: { coalescedSamples: 30, coalescedMax: 1 } },
      environmental: fixtures.cases[0].signals.environmental,
      experimental: { mode: blocking ? 'observe' : 'block', wouldBlock: !blocking },
      meta: { challengeNonce: challenge.nonce },
    };
    const raw = JSON.stringify(signals);
    const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
    const signalsHash = sha(raw);
    let nonce = 0;
    const hash = () => sha(`${challenge.prefix}:${signalsHash}:${nonce}`);
    while (!hash().startsWith('0')) nonce++;
    const result = engine.verify(signals, ip, site, 'Mozilla/5.0', {
      accept: 'text/html', 'accept-language': 'en-US', 'accept-encoding': 'gzip', connection: 'keep-alive',
    }, { challengeId: challenge.id, nonce, hash: hash(), signalsHash }, raw);
    assert.equal(result.experimental.wouldBlock, true);
    assert.equal(result.experimental.score, 0.6);
    assert.equal(result.experimental.mode, blocking ? 'block' : 'observe');
    assert.ok(result.score < 0.5);
    assert.equal(result.success, !blocking);
    if (blocking) {
      assert.equal(result.token, null);
      assert.equal(result.reason, 'experimental_detection');
      assert.equal(result.recommendation, 'block');
    } else {
      assert.ok(result.token);
      const claims = JSON.parse(Buffer.from(result.token, 'base64url'));
      assert.equal(claims.score, Math.round(result.score * 1000) / 1000);
      assert.equal(claims.experimental, undefined);
      assert.equal(engine.verifyToken(result.token).valid, true);
    }
    assert.equal(engine.suspicion.count(site, ip), 0);
    const next = engine.generateChallenge(site, ip);
    assert.equal(next.minAgeMs, 1500);
    assert.equal(next.difficulty, 4);
    assert.ok(result.detections.every((d) => !d.id), 'experimental evidence leaked into production detections');
  });
}
