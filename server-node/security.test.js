'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { createScoringEngine, createMiddleware } = require('./index');
const { FingerprintStore } = require('./fingerprint-store');
const { TokenStore } = require('./token-store');
const { reasonToErrorCode } = require('./siteverify');

const signals = () => ({ behavioral: { totalPoints: 60, trajectoryLength: 400,
  microTremorScore: 0.5, velocityVariance: 0.5, approachPoints: 12,
  approachDirectness: 0.4, explorationRatio: 0.35, overshootCorrections: 2,
  interactionDuration: 4200 }, environmental: { automationFlags: {} } });
const headers = { accept: 'text/html', 'accept-language': 'en-US',
  'accept-encoding': 'gzip, deflate, br', connection: 'keep-alive' };
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');

test('independent tokens are unique and each can only be spent once', () => {
  const engine = createScoringEngine({ secret: 'test-secret' });
  const first = engine._generateToken('203.0.113.1', 'site', 0.1);
  const second = engine._generateToken('203.0.113.1', 'site', 0.1);
  assert.notEqual(first, second);
  assert.equal(engine.verifyToken(first).valid, true);
  assert.equal(engine.verifyToken(first).valid, false);
  assert.equal(engine.verifyToken(second).valid, true);
});

test('full replay store fails closed and recovers after retention expires', () => {
  let now = 0;
  const store = new TokenStore({ maxEntries: 1, now: () => now });
  assert.equal(store.markUsed('first'), true);
  assert.equal(store.markUsed('second'), false);
  assert.equal(store.markUsed('first'), false);
  now = 600001;
  assert.equal(store.markUsed('second'), true);
});

test('capacity errors are distinct from replays in token verification', () => {
  const engine = createScoringEngine({ secret: 'test-secret', tokenStore: new TokenStore({ maxEntries: 1 }) });
  const first = engine._generateToken('ip', 'site', 0.1);
  const second = engine._generateToken('ip', 'site', 0.1);
  assert.equal(engine.verifyToken(first).valid, true);
  assert.deepEqual(engine.verifyToken(second), { valid: false, reason: 'token_store_full' });
  assert.deepEqual(engine.verifyToken(first), { valid: false, reason: 'token_already_used' });
  assert.equal(reasonToErrorCode('token_store_full'), 'internal-error');
});

test('issued nonces are required for both committed and legacy proofs', () => {
  for (const committed of [false, true]) {
    for (const nonceMode of ['correct', 'missing', 'wrong']) {
      const engine = createScoringEngine({ secret: 'test-secret' });
      const challenge = engine.generateChallenge('site', '203.0.113.1', { difficulty: 1, scaleByReputation: false });
      engine.powStore.challenges.get(challenge.id).timestamp -= 2000;
      const body = signals();
      if (nonceMode !== 'missing') body.meta = { challengeNonce: nonceMode === 'correct' ? challenge.nonce : 'wrong' };
      const raw = JSON.stringify(body);
      const signalsHash = committed ? sha(raw) : null;
      const prefix = committed ? `${challenge.prefix}:${signalsHash}` : challenge.prefix;
      let nonce = 0;
      while (!sha(`${prefix}:${nonce}`).startsWith('0')) nonce++;
      const result = engine.verify(body, '203.0.113.1', 'site', 'Mozilla/5.0', headers,
        { challengeId: challenge.id, nonce, hash: sha(`${prefix}:${nonce}`), signalsHash }, committed ? raw : null);
      assert.equal(result.success, nonceMode === 'correct', `${committed}/${nonceMode}`);
      assert.equal(result.detections.some((d) => d.reason.startsWith('Challenge nonce mismatch')), nonceMode !== 'correct');
    }
  }
});

test('widget-format proofs pass middleware and cannot be reused or altered', () => {
  for (const mode of ['valid', 'mismatch', 'missing', 'early', 'elevated']) {
    const middleware = createMiddleware({ secret: 'test-secret', trustedProxies: 'none' });
    const engine = middleware.engine;
    const req = { query: { siteKey: 'site' }, headers, socket: { remoteAddress: '203.0.113.1' } };
    let challenge;
    middleware.challengeHandler(req, { json: (value) => { challenge = value; } });
    assert.ok(challenge.nonce);
    assert.ok(challenge.minAgeMs >= 1500);
    const stored = engine.powStore.challenges.get(challenge.challengeId);
    // Exercise timing gates deterministically without sleeping or costly PoW.
    stored.difficulty = 1;
    stored.timestamp = Date.now() - (mode === 'early' ? 0 : 2000);
    if (mode === 'elevated') stored.minAgeMs = 60000;
    const body = signals();
    body.meta = { challengeNonce: challenge.nonce };
    const raw = JSON.stringify(body);
    const hashOfSignals = sha(mode === 'mismatch' ? 'other payload' : raw);
    let nonce = 0;
    while (!sha(`${challenge.prefix}:${hashOfSignals}:${nonce}`).startsWith('0')) nonce++;
    req.body = { siteKey: 'site', signals: body, signalsJson: mode === 'missing' ? null : raw,
      powSolution: { challengeId: challenge.challengeId, nonce, signalsHash: hashOfSignals,
        hash: sha(`${challenge.prefix}:${hashOfSignals}:${nonce}`) } };
    let result;
    middleware.verifyHandler(req, { json: (value) => { result = value; } });
    assert.equal(result.success, mode === 'valid', `${mode}: ${JSON.stringify(result)}`);
    if (mode === 'valid') {
      middleware.verifyHandler(req, { json: (value) => { result = value; } });
      assert.equal(result.success, false, 'spent proof cannot mint another token');
    }
  }
});

test('fingerprint churn is bounded and old suspicion expires', () => {
  let now = 0;
  const store = new FingerprintStore({ maxEntries: 32, now: () => now });
  for (let i = 0; i < 10000; i++) store.record(`fp-${i}`, 'ip', 'site');
  assert.equal(store.getIpFpCount('ip'), 16);
  assert.equal(store.fingerprints.size, 16);
  for (let i = 0; i < 1000; i++) store.record('shared', `ip-${i}`, 'site');
  assert.equal(store.getFpIpCount('shared', 'site'), 16);
  assert.ok(store.ipFingerprints.size <= 32);
  now = 900001;
  assert.equal(store.getFpIpCount('shared', 'site'), 0);
  store.record('fresh', 'ip', 'site');
  assert.equal(store.getIpFpCount('ip'), 1);
});

test('malformed public requests return errors while the server stays available', async () => {
  process.env.FCAPTCHA_SECRET = 'test-secret';
  process.env.REDIS_URL = '';
  const { app } = require('./server');
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const path of ['/api/verify', '/api/score']) {
      assert.equal((await fetch(base + path)).status, 404, 'GET does not run POST validation');
      for (const body of [{}, { signals: null }, { signals: [] }, { signals: { behavioral: [] } },
        { signals: {}, signalsJson: 'null', powSolution: { signalsHash: sha('null') } }]) {
        const response = await fetch(base + path, { method: 'POST',
          headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        assert.equal(response.status, 400, JSON.stringify(body));
        assert.equal((await response.json()).error, 'invalid_request');
        assert.equal((await fetch(base + '/health')).status, 200);
      }
      // Exercise a rejection *inside* the async scoring handler as well as
      // the explicit request-validation middleware above.
      const response = await fetch(base + path, { method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ signals: { environmental: { webglInfo: { renderer: {} } } } }) });
      assert.equal(response.status, 500);
      assert.deepEqual(await response.json(), { error: 'internal_error' });
      assert.equal((await fetch(base + '/health')).status, 200);
    }
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
