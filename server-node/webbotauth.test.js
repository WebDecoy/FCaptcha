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

const WELL_KNOWN = '/.well-known/http-message-signatures-directory';

function testParsing() {
  const { keySourceFromHeader, parseSignatureAgent, displayAgent } = wba._internal;
  const src = (h) => keySourceFromHeader(h);

  // Pre-00 forms must keep working — signers migrate on their own schedule.
  assert.deepStrictEqual(src('"https://a.example"'), {
    url: 'https://a.example' + WELL_KNOWN,
    type: 'directory',
  });
  assert.deepStrictEqual(src('sig1="https://a.example"'), {
    url: 'https://a.example' + WELL_KNOWN,
    type: 'directory',
  });

  // protocol-00 typed discovery — the exact shapes that regressed.
  assert.deepStrictEqual(src('sig1="https://a.example";type=directory'), {
    url: 'https://a.example' + WELL_KNOWN,
    type: 'directory',
  });
  assert.deepStrictEqual(src('sig1="https://a.example/jwks.json";type=jwks_uri'), {
    url: 'https://a.example/jwks.json',
    type: 'jwks_uri',
  });
  assert.deepStrictEqual(src('sig1="https://a.example/card";type=cimd'), {
    url: 'https://a.example/card',
    type: 'cimd',
  });

  // jwks_uri/cimd keep path AND query; directory collapses to origin.
  assert.strictEqual(
    src('sig1="https://a.example/k?v=2";type=jwks_uri').url,
    'https://a.example/k?v=2',
  );
  assert.strictEqual(src('sig1="https://a.example/ignored";type=directory').url,
    'https://a.example' + WELL_KNOWN);

  // Tolerated variations.
  assert.strictEqual(src('sig1="https://a.example/j" ; type="jwks_uri"').type, 'jwks_uri');
  assert.strictEqual(src('sig1="https://a.example/j";type=JWKS_URI').type, 'jwks_uri');
  assert.strictEqual(src('sig1="https://a.example", sig2="https://b.example"').url,
    'https://a.example' + WELL_KNOWN, 'first dictionary member wins');

  // Rejections.
  assert.strictEqual(src('"http://a.example"'), null, 'http must be refused');
  assert.strictEqual(src('sig1="https://a.example";type=telepathy'), null,
    'unknown discovery type must not be guessed');
  assert.strictEqual(src('garbage'), null);
  assert.strictEqual(src('sig1=""'), null);
  assert.strictEqual(src(undefined), null);

  assert.strictEqual(parseSignatureAgent('sig1="https://a.example"').type, 'directory',
    'absent type parameter defaults to directory');

  assert.strictEqual(displayAgent('"https://a.example"'), 'https://a.example');
  assert.strictEqual(displayAgent('sig1="https://a.example/j";type=jwks_uri'),
    'https://a.example/j');
  assert.strictEqual(displayAgent(undefined), 'unknown');
  console.log('  ✓ Signature-Agent parsing (pre-00 bare/dict + protocol-00 typed + rejects)');
}

function testSignatureParams() {
  const { assertWebBotAuthParams, REQUIRED_TAG, MAX_SIGNATURE_LIFETIME_S } = wba._internal;
  const now = Math.floor(Date.now() / 1000);
  const ok = { tag: REQUIRED_TAG, created: now, expires: now + 300 };

  assert.doesNotThrow(() => assertWebBotAuthParams(ok));

  // protocol-00: tag MUST be web-bot-auth.
  assert.throws(() => assertWebBotAuthParams({ ...ok, tag: 'something-else' }), /tag/);
  assert.throws(() => assertWebBotAuthParams({ ...ok, tag: undefined }), /tag/);

  // An unbounded signature is replayable forever.
  assert.throws(() => assertWebBotAuthParams({ ...ok, expires: undefined }), /expires/);

  // 24h ceiling.
  assert.doesNotThrow(() =>
    assertWebBotAuthParams({ ...ok, expires: now + MAX_SIGNATURE_LIFETIME_S }));
  assert.throws(
    () => assertWebBotAuthParams({ ...ok, expires: now + MAX_SIGNATURE_LIFETIME_S + 1 }),
    /24h/,
  );

  // Regression: web-bot-auth hands the verifier `Date` objects, not epoch
  // seconds. Treating those as numbers yields milliseconds, making every
  // signature longer than ~86 seconds look like it exceeds 24h. A normal
  // 5-minute Date-valued signature must verify.
  const dNow = new Date();
  assert.doesNotThrow(
    () =>
      assertWebBotAuthParams({
        tag: REQUIRED_TAG,
        created: dNow,
        expires: new Date(dNow.getTime() + 5 * 60 * 1000),
      }),
    'Date-valued params must not be mis-read as milliseconds',
  );
  // …and the ceiling still bites when the Dates really are far apart.
  assert.throws(
    () =>
      assertWebBotAuthParams({
        tag: REQUIRED_TAG,
        created: dNow,
        expires: new Date(dNow.getTime() + 48 * 60 * 60 * 1000),
      }),
    /24h/,
  );
  console.log('  ✓ signature params (tag enforced, 24h ceiling, Date/seconds units)');
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

// The regression Phase G exists to close: a signer using protocol-00 typed
// discovery must still reach a *verified* verdict. Before the fix the header
// failed to parse, resolveKey threw, and this silently degraded to
// presence-only — no error, no false positive, just a lost signal.
async function testTypedDiscoveryVerified() {
  for (const [label, agentValue, seedUrl] of [
    [
      'jwks_uri',
      `sig1="${AGENT_ORIGIN}/jwks.json";type=jwks_uri`,
      `${AGENT_ORIGIN}/jwks.json`,
    ],
    ['explicit directory', `sig1="${AGENT_ORIGIN}";type=directory`, null],
  ]) {
    const { signer, pubJwk } = await generateSigner();
    wba._internal.seedDirectoryCache(AGENT_ORIGIN, [pubJwk], seedUrl);

    const message = {
      method: 'POST',
      url: 'https://example.com/api/verify',
      headers: { host: 'example.com', 'signature-agent': agentValue },
    };
    const sigHeaders = await sign(signer, message);
    const req = fakeReq({
      host: 'example.com',
      extraHeaders: { 'signature-agent': agentValue, ...sigHeaders },
    });

    const dets = await wba.checkWebBotAuth(req);
    assert.strictEqual(dets.length, 1, `${label}: expected one detection`);
    assert.strictEqual(dets[0].category, 'declared_ai', `${label}: category`);
    assert.strictEqual(
      dets[0].details.verified,
      true,
      `${label}: expected verified:true (this is the protocol-00 regression)`,
    );
  }
  console.log('  ✓ protocol-00 typed discovery (jwks_uri, directory) → verified');
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
  testSignatureParams();
  await testVerified();
  await testTypedDiscoveryVerified();
  await testForged();
  await testFailOpen();
  await testNoSignature();
  console.log('All webbotauth tests passed.');
}

main().catch((e) => {
  console.error('FAIL:', e);
  process.exit(1);
});
