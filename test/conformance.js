#!/usr/bin/env node
'use strict';

// Language-neutral black-box contract tests. These deliberately assert security
// invariants and wire shapes, not detector scores: detection parity is useful,
// but a score difference is not the same class of failure as issuing a token
// without PoW or accepting a replay.

const assert = require('assert');
const crypto = require('crypto');
const { buildVerifyBody } = require('../bench/lib/pow');

const SERVER = process.argv[2] || 'http://localhost:3000';
const SECRET = process.env.FCAPTCHA_VERIFY_SECRET || process.env.FCAPTCHA_SECRET;
if (!SECRET) throw new Error('FCAPTCHA_SECRET is required for conformance tests');

let passed = 0;

async function request(path, { method = 'POST', headers = {}, body, rawBody } = {}) {
  const response = await fetch(`${SERVER}${path}`, {
    method,
    headers: rawBody === undefined
      ? { 'content-type': 'application/json', ...headers }
      : headers,
    body: rawBody === undefined
      ? (body === undefined ? undefined : JSON.stringify(body))
      : rawBody,
  });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch {}
  return { status: response.status, headers: response.headers, json, text };
}

function ok(condition, message) {
  assert.ok(condition, message);
  passed++;
  console.log(`  ok  ${message}`);
}

async function mint({ siteKey, ip, action = '', cdata = '', origin = 'https://example.test' }) {
  const headers = {
    'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'X-Real-IP': ip,
    Origin: origin,
  };
  const { body } = await buildVerifyBody(SERVER, siteKey, {
    behavioral: {
      totalPoints: 80,
      trajectoryLength: 350,
      interactionDuration: 2000,
      velocityVariance: 0.8,
      microTremorScore: 0.6,
      directionChanges: 15,
      mouseEventRate: 60,
      approachPoints: 12,
    },
  }, headers);
  const result = await request('/api/verify', {
    headers,
    body: { ...body, action, cdata },
  });
  assert.strictEqual(result.status, 200);
  assert.strictEqual(result.json.success, true, JSON.stringify(result.json));
  assert.ok(result.json.token, JSON.stringify(result.json));
  return { token: result.json.token, headers };
}

async function run() {
  console.log(`FCaptcha cross-server conformance: ${SERVER}`);

  const health = await request('/health', { method: 'GET' });
  ok(health.status === 200 && health.json?.status === 'ok', 'health contract');

  const head = await request('/health', { method: 'HEAD' });
  ok(head.status === 200 && head.text === '', 'HEAD health contract');

  const missing = await request('/api/verify', {
    body: { siteKey: 'missing-pow', signals: {} },
  });
  ok(
    missing.status === 200 && missing.json?.success === false &&
      !missing.json?.token && missing.json?.reason === 'pow_not_satisfied',
    'missing PoW cannot mint a token'
  );

  const forged = await request('/api/verify', {
    body: {
      siteKey: 'forged-pow',
      signals: {},
      powSolution: { challengeId: 'not-issued', nonce: 0, hash: '0'.repeat(64) },
    },
  });
  ok(forged.json?.success === false && !forged.json?.token, 'forged PoW cannot mint a token');

  const native = await mint({
    siteKey: 'native-token', ip: '203.0.113.10', action: 'login', cdata: 'native-cdata',
  });
  const wrongSecret = await request('/api/token/verify', {
    body: { token: native.token, secret: 'wrong-secret' },
  });
  ok(wrongSecret.status === 401 && wrongSecret.json?.reason === 'invalid_secret', 'native verification requires the correct secret');

  const nativeVerified = await request('/api/token/verify', {
    body: { token: native.token, secret: SECRET },
  });
  ok(
    nativeVerified.json?.valid === true && nativeVerified.json?.hostname === 'example.test' &&
      nativeVerified.json?.action === 'login' && nativeVerified.json?.cdata === 'native-cdata',
    'native verification reports signed hostname, action, and cdata'
  );

  const replay = await request('/api/token/verify', {
    body: { token: native.token, secret: SECRET },
  });
  ok(replay.json?.valid === false && replay.json?.reason === 'token_already_used', 'native token is single-use');

  const bound = await mint({ siteKey: 'remote-ip', ip: '203.0.113.20' });
  const ipMismatch = await request('/api/token/verify', {
    body: { token: bound.token, secret: SECRET, remoteip: '198.51.100.20' },
  });
  ok(ipMismatch.json?.valid === false && ipMismatch.json?.reason === 'ip_mismatch', 'explicit visitor remoteip is enforced');

  const compatible = await mint({
    siteKey: 'siteverify-token', ip: '203.0.113.30', action: 'checkout', cdata: 'compat-cdata',
  });
  const idem = crypto.randomUUID();
  const form = new URLSearchParams({
    secret: SECRET,
    response: compatible.token,
    idempotency_key: idem,
  }).toString();
  const siteverify = await request('/turnstile/v0/siteverify', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' }, rawBody: form,
  });
  ok(
    siteverify.json?.success === true && siteverify.json?.hostname === 'example.test' &&
      siteverify.json?.action === 'checkout' && siteverify.json?.cdata === 'compat-cdata' &&
      Array.isArray(siteverify.json?.['error-codes']),
    'Siteverify compatibility shape and signed claims'
  );

  const retry = await request('/turnstile/v0/siteverify', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' }, rawBody: form,
  });
  ok(retry.json?.success === true && retry.json?.action === 'checkout', 'Siteverify idempotent retry preserves the first result');

  const committedHeaders = {
    'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0',
    'Accept-Language': 'en-US,en;q=0.9',
    'X-Real-IP': '203.0.113.40',
  };
  const committed = await buildVerifyBody(SERVER, 'commitment-test', {}, committedHeaders);
  committed.body.signalsJson = JSON.stringify({ meta: { challengeNonce: 'tampered' } });
  const tampered = await request('/api/verify', { headers: committedHeaders, body: committed.body });
  ok(
    tampered.json?.success === false && !tampered.json?.token &&
      (tampered.json?.detections || []).some((d) => /Signals tampered/.test(d.reason || '')),
    'signal commitment tampering cannot mint a token'
  );

  const oversized = await request('/api/verify', {
    body: { padding: 'x'.repeat(64 * 1024) },
  });
  ok(oversized.status === 413 && oversized.json?.error === 'request_too_large', 'oversized body returns the shared 413 contract');

  console.log(`${passed} conformance checks passed`);
}

run().catch((error) => {
  console.error(error.stack || error);
  process.exit(1);
});
