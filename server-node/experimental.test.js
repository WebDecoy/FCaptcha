'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  evaluateExperimental,
  EXTERNAL_CDP_INPUT_POLICY,
  externalCdpInputObservation,
} = require('./experimental');
const { createScoringEngine } = require('./index');
const { experimentalBlockingEnabled } = require('./config');
const fixtures = require('../test/fixtures/experimental-scoring.json');

for (const fixture of fixtures.cases) {
  test(`experimental parity: ${fixture.name}`, () => {
    const before = JSON.stringify(fixture);
    const observe = evaluateExperimental(fixture.signals, fixture.productionScore, fixture.detections);
    const block = evaluateExperimental(fixture.signals, fixture.productionScore, fixture.detections, true);
    const withoutExternalCdp = (result) => {
      const { [EXTERNAL_CDP_INPUT_POLICY]: observation, ...observations } = result.observations;
      assert.equal(observation.mode, 'observe');
      return { ...result, observations };
    };
    assert.deepEqual(withoutExternalCdp(observe), fixture.expected);
    assert.deepEqual(withoutExternalCdp(block), { ...fixture.expected, mode: 'block' });
    assert.equal(JSON.stringify(fixture), before, 'observations must not mutate production inputs');
  });
}

const inputShape = ({
  inputEvents = 13,
  inputsWithoutKeys = 1,
  inputsWithoutInputType = 1,
  selectAllShortcuts = 1,
  pasteEvents = 0,
  pasteInputs = 0,
  gestures = 2,
  instantRatio = 1,
} = {}) => ({
  formAnalysis: { typing: {
    inputEvents,
    inputsWithoutKeys,
    inputsWithoutInputType,
    selectAllShortcuts,
    pasteEvents,
    pasteInputs,
  } },
  behavioral: { scrollMorphology: { gestures, instantRatio } },
});

test('external CDP input observation detects only the full paired Browser Harness shape', () => {
  const observation = externalCdpInputObservation(inputShape());
  assert.equal(observation.mode, 'observe');
  assert.equal(observation.status, 'detected');
  assert.deepEqual(observation.detections.map((row) => row.id), ['external-cdp-form-input-shape']);
  assert.match(observation.detections[0].reason, /assistive input/);
});

test('accessibility-adjacent partial input shapes stay clear', () => {
  const controls = [
    inputShape({ selectAllShortcuts: 0 }), // dictation, autofill, or a password manager
    inputShape({ inputsWithoutKeys: 0, inputsWithoutInputType: 0 }), // keyboard/screen-reader select-all
    inputShape({ pasteEvents: 1 }), // explicit assistive or ordinary paste
    inputShape({ gestures: 1 }), // anchor, switch, or reduced-motion navigation
    inputShape({ instantRatio: 0.5 }), // paired manual-control ceiling
  ];
  for (const signals of controls) {
    assert.equal(externalCdpInputObservation(signals).status, 'clear');
  }
});

test('missing old-client telemetry is unknown, never detected', () => {
  assert.deepEqual(externalCdpInputObservation({}), {
    mode: 'observe', status: 'unknown', detections: [],
  });
  assert.equal(externalCdpInputObservation({
    formAnalysis: { typing: {} }, behavioral: { scrollMorphology: {} },
  }).status, 'unknown');
});

test('external CDP observation never changes score, gate, or production detections', () => {
  const result = evaluateExperimental(inputShape(), 0.1, []);
  assert.equal(result.observations[EXTERNAL_CDP_INPUT_POLICY].status, 'detected');
  assert.equal(result.score, 0.1);
  assert.equal(result.wouldBlock, false);
  assert.deepEqual(result.detections, []);
});

test('experimental blocking requires the current policy and library options override the environment', () => {
  const policy = 'stealth-corroboration-v1';
  const enabledEnv = { FCAPTCHA_EXPERIMENTAL_BLOCKING: policy };
  assert.equal(experimentalBlockingEnabled(undefined, {}), false);
  for (const name of [policy, ` ${policy} `]) {
    assert.equal(experimentalBlockingEnabled(undefined, { FCAPTCHA_EXPERIMENTAL_BLOCKING: name }), true);
    assert.equal(experimentalBlockingEnabled(name, {}), true);
  }
  for (const name of ['', '0', 'false', 'no', 'off', 'garbage', '1', 'true', 'yes', 'on', ' TRUE ',
    'stealth-corroboration-v0', 'stealth-corroboration-v2', 'animation-consistency-v1', 'STEALTH-CORROBORATION-V1', '*', `${policy},other`]) {
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
 for (const animationOnly of [false, true]) {
  test(`experimental blocking=${blocking}, animationOnly=${animationOnly}: gate follows config; score and challenge cost stay unchanged`, () => {
    const engine = createScoringEngine({ secret: 'experimental-test-secret-0123456789abcdef0123456789', experimentalBlocking: blocking ? 'stealth-corroboration-v1' : false });
    const ip = '203.0.113.87';
    const site = 'experimental';
    const challenge = engine.generateChallenge(site, ip, { difficulty: 1, scaleByReputation: false });
    engine.powStore.challenges.get(challenge.id).timestamp -= 2000;
    const signals = {
      behavioral: { totalPoints: 60, trajectoryLength: 400, approachPoints: 12,
        approachDirectness: 0.4, microTremorScore: 0.5, velocityVariance: 0.5,
        interactionDuration: 4200, inputForensics: { coalescedSamples: 30, coalescedMax: 1 } },
      environmental: animationOnly ? fixtures.cases.find((c) => c.name === 'animation-observed').signals.environmental
        : fixtures.cases[0].signals.environmental,
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
    assert.equal(result.experimental.wouldBlock, !animationOnly);
    assert.equal(result.experimental.score, animationOnly ? result.score : 0.6);
    assert.equal(result.experimental.observations['animation-consistency-v1'].mode, 'observe');
    assert.equal(result.experimental.observations['animation-consistency-v1'].status, animationOnly ? 'detected' : 'unknown');
    assert.equal(result.experimental.mode, blocking ? 'block' : 'observe');
    assert.ok(result.score < 0.5);
    assert.equal(result.success, !(blocking && !animationOnly));
    if (blocking && !animationOnly) {
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
}
