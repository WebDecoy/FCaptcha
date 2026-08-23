#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { buildVerifyBody } = require('../bench/lib/pow');

const A = process.argv[2] || 'http://localhost:3101';
const B = process.argv[3] || 'http://localhost:3102';
const SECRET = process.env.FCAPTCHA_SECRET;
if (!SECRET) throw new Error('FCAPTCHA_SECRET is required');
const VISITOR = '203.0.113.25';
const HEADERS = {
  'content-type': 'application/json', 'x-real-ip': VISITOR,
  origin: 'https://example.com', 'user-agent': 'Mozilla/5.0 Chrome/120.0.0.0',
  'accept-language': 'en-US,en;q=0.9', 'accept-encoding': 'gzip, deflate, br'
};
const HUMAN_SIGNALS = {
  behavioral: {
    totalPoints: 80, trajectoryLength: 350, interactionDuration: 2000,
    velocityVariance: 0.8, microTremorScore: 0.6, directionChanges: 15,
    mouseEventRate: 60, approachPoints: 12
  }
};

async function post(server, path, body, headers = HEADERS) {
  const response = await fetch(`${server}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() };
}

async function mintAcrossInstances(siteKey) {
  const { body } = await buildVerifyBody(A, siteKey, HUMAN_SIGNALS, HEADERS);
  const result = await post(B, '/api/verify', body);
  assert.strictEqual(result.status, 200);
  assert.strictEqual(result.body.success, true, JSON.stringify(result.body));
  assert.ok(result.body.token);
  return result.body.token;
}

(async () => {
  const token = await mintAcrossInstances('redis-cross-instance-token');
  const first = await post(A, '/api/token/verify', { token, secret: SECRET });
  assert.strictEqual(first.body.valid, true, JSON.stringify(first.body));
  const replay = await post(B, '/api/token/verify', { token, secret: SECRET });
  assert.strictEqual(replay.body.valid, false);
  assert.strictEqual(replay.body.reason, 'token_already_used');

  const retryToken = await mintAcrossInstances('redis-cross-instance-idempotency');
  const request = { secret: SECRET, response: retryToken, idempotency_key: 'cross-instance-retry' };
  const original = await post(A, '/siteverify', request);
  assert.strictEqual(original.body.success, true, JSON.stringify(original.body));
  const retry = await post(B, '/siteverify', request);
  assert.deepStrictEqual(retry.body, original.body);

  console.log('cross-instance Redis conformance passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
