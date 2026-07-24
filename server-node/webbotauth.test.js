'use strict';

// Framework-free tests for webbotauth.js (run: `node webbotauth.test.js`),
// matching the repo's plain-node test style. Covers the SSRF guard, header
// parsing, and the full verified / forged / fail-open verdict paths driven
// through real Ed25519 signatures (crypto is exercised, not mocked). The
// directory cache is seeded so resolveKey needs no network — the SSRF guard
// would otherwise refuse the loopback address a local server would use.

const assert = require('assert');
const { signatureHeaders } = require('web-bot-auth');
const { Ed25519Signer } = require('web-bot-auth/crypto');
const wba = require('./webbotauth');

const AGENT_ORIGIN = 'https://agent.example';
const SIGNATURE_AGENT_VALUE = `"${AGENT_ORIGIN}"`; // RFC 8941 bare string form

async function generateSigner() {
  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const signer = await Ed25519Signer.fromJWK(privJwk);
  return { signer, pubJwk };
}

// Signs message and returns headers ready to place on an inbound request.
async function sign(signer, message) {
  const created = new Date();
  const expires = new Date(created.getTime() + 5 * 60 * 1000);
  const headers = await signatureHeaders(message, signer, { created, expires });
  return { signature: headers.Signature, 'signature-input': headers['Signature-Input'] };
}

function fakeReq({ host, path = '/api/verify', method = 'POST', extraHeaders = {} }) {
  return {
    method,
    originalUrl: path,
    protocol: 'https',
    headers: { host, 'x-forwarded-proto': 'https', ...extraHeaders },
  };
}

function testGuard() {
  const { isPublicUnicast } = wba._internal;
  // Public unicast — allowed.
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
    assert.strictEqual(isPublicUnicast(ip), true, `${ip} should be allowed`);
  }
  // Internal / special — refused. 169.254.169.254 is the cloud metadata IP.
  for (const ip of [
    '127.0.0.1',
    '10.0.0.1',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '::1',
    'fc00::1',
    'fe80::1',
    '::ffff:10.0.0.1',
    'not-an-ip',
  ]) {
    assert.strictEqual(isPublicUnicast(ip), false, `${ip} should be refused`);
  }
  console.log('  ✓ SSRF guard classifies addresses correctly');
}

function testParsing() {
  const { directoryOriginFromHeader, displayAgent } = wba._internal;
  assert.strictEqual(directoryOriginFromHeader('"https://a.example"'), 'https://a.example');
  assert.strictEqual(directoryOriginFromHeader('sig1="https://a.example"'), 'https://a.example');
  assert.strictEqual(directoryOriginFromHeader('"http://a.example"'), null, 'http must be refused');
  assert.strictEqual(directoryOriginFromHeader('garbage'), null);
  assert.strictEqual(directoryOriginFromHeader(undefined), null);
  assert.strictEqual(displayAgent('"https://a.example"'), 'https://a.example');
  assert.strictEqual(displayAgent(undefined), 'unknown');
  console.log('  ✓ Signature-Agent header parsing (bare + dictionary + rejects)');
}

async function testVerified() {
  const { signer, pubJwk } = await generateSigner();
  wba._internal.seedDirectoryCache(AGENT_ORIGIN, [pubJwk]);

  const message = {
    method: 'POST',
    url: 'https://example.com/api/verify',
    headers: { host: 'example.com', 'signature-agent': SIGNATURE_AGENT_VALUE },
  };
  const sigHeaders = await sign(signer, message);
  const req = fakeReq({
    host: 'example.com',
    extraHeaders: { 'signature-agent': SIGNATURE_AGENT_VALUE, ...sigHeaders },
  });

  const dets = await wba.checkWebBotAuth(req);
  assert.strictEqual(dets.length, 1);
  assert.strictEqual(dets[0].category, 'declared_ai');
  assert.strictEqual(dets[0].details.verified, true, 'expected verified:true');
  console.log('  ✓ verified signature → declared_ai (verified:true)');
}

async function testForged() {
  const { signer, pubJwk } = await generateSigner();
  wba._internal.seedDirectoryCache(AGENT_ORIGIN, [pubJwk]);

  const message = {
    method: 'POST',
    url: 'https://example.com/api/verify',
    headers: { host: 'example.com', 'signature-agent': SIGNATURE_AGENT_VALUE },
  };
  const sigHeaders = await sign(signer, message);
  // Present the signed headers on a request whose authority differs from what
  // was signed → @authority mismatch → ed25519 verification genuinely fails.
  const req = fakeReq({
    host: 'attacker.example',
    extraHeaders: { 'signature-agent': SIGNATURE_AGENT_VALUE, ...sigHeaders },
  });

  const dets = await wba.checkWebBotAuth(req);
  assert.strictEqual(dets.length, 1);
  assert.strictEqual(dets[0].category, 'bot', 'crypto failure must score as bot');
  assert.strictEqual(dets[0].details.verified, false);
  console.log('  ✓ forged signature (authority mismatch) → bot');
}

async function testFailOpen() {
  // A validly-signed request that covers only @authority (no signature-agent):
  // checkWebBotAuth has no directory to resolve, so it cannot verify and must
  // fail open to presence-only rather than accuse. Deterministic, no network.
  const { signer } = await generateSigner();
  const message = {
    method: 'POST',
    url: 'https://example.com/api/verify',
    headers: { host: 'example.com' },
  };
  const sigHeaders = await sign(signer, message);
  const req = fakeReq({ host: 'example.com', extraHeaders: sigHeaders });

  const dets = await wba.checkWebBotAuth(req);
  assert.strictEqual(dets.length, 1);
  assert.strictEqual(dets[0].category, 'declared_ai');
  assert.strictEqual(dets[0].details.verified, false, 'fail-open must be verified:false');
  assert.ok(/unverified/.test(dets[0].reason));
  console.log('  ✓ unresolvable signer → fail open to presence-only');
}

async function testNoSignature() {
  const req = fakeReq({ host: 'example.com' }); // no signature headers
  const dets = await wba.checkWebBotAuth(req);
  assert.strictEqual(dets.length, 0, 'no signature → no detection');
  console.log('  ✓ no signature headers → no detection');
}

async function main() {
  console.log('webbotauth.js');
  testGuard();
  testParsing();
  await testVerified();
  await testForged();
  await testFailOpen();
  await testNoSignature();
  console.log('All webbotauth tests passed.');
}

main().catch((e) => {
  console.error('FAIL:', e);
  process.exit(1);
});
