import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes, createHmac } from 'node:crypto';
import { createRequire } from 'node:module';
import { createApp } from './app.mjs';

for (const key of Object.keys(process.env)) {
  if (key.startsWith('FCAPTCHA_') || ['REDIS_URL', 'TRUSTED_PROXIES'].includes(key)) delete process.env[key];
}
process.env.FCAPTCHA_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_VERIFY_SECRET = randomBytes(32).toString('hex');
process.env.TRUSTED_PROXIES = 'none';
const require = createRequire(import.meta.url);
const { app: verifier } = require('../../server-node/server.js');
const captcha = verifier.listen(0, '127.0.0.1');
await once(captcha, 'listening');
after(() => { captcha.closeAllConnections(); captcha.close(); });
const origin = 'http://127.0.0.1:8794';
const settings = { origin, captchaOrigin: `http://127.0.0.1:${captcha.address().port}`,
  verifySecret: process.env.FCAPTCHA_VERIFY_SECRET, page: '<p>demo</p>', script: '// demo' };
const app = createApp(settings);
function token(overrides = {}) {
  const data = { site_key: 'hono-demo', jti: randomBytes(16).toString('hex'),
    timestamp: Math.floor(Date.now()/1000), score: 0.05, ip_hash: '',
    hostname: '127.0.0.1', action: 'contact', cdata: '', ...overrides };
  data.sig = createHmac('sha256', process.env.FCAPTCHA_SECRET)
    .update(JSON.stringify(data, Object.keys(data).sort())).digest('hex');
  return Buffer.from(JSON.stringify(data)).toString('base64url');
}
function post(body, instance = app, requestOrigin = origin) {
  return instance.request('/contact', { method: 'POST', headers: { Origin: requestOrigin,
    'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
test('actual verifier accepts a valid token once and rejects replay', async () => {
  const body = { message: 'sample', token: token() };
  const response = await post(body);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { accepted: true, demoOnly: true });
  assert.equal((await post(body)).status, 403);
});
for (const [name, overrides] of [['wrong hostname', { hostname: 'other.example' }],
  ['wrong action', { action: 'login' }], ['missing action', { action: '' }], ['expired', { timestamp: 1 }]]) {
  test(name, async () => assert.equal((await post({ message: 'sample', token: token(overrides) })).status, 403));
}
test('forged token and wrong verification credential rejected', async () => {
  assert.equal((await post({ message: 'sample', token: 'forged' })).status, 403);
  const wrong = createApp({ ...settings, verifySecret: 'wrong' });
  assert.equal((await post({ message: 'sample', token: token() }, wrong)).status, 403);
});
test('input and browser origin validation', async () => {
  for (const body of [null, {}, { message: 'sample' }, { message: '', token: 'x' },
    { message: 'x'.repeat(2001), token: 'x' }, { message: 'x', token: 'x'.repeat(8193) }]) {
    assert.equal((await post(body)).status, 400);
  }
  assert.equal((await post({ message: 'x', token: 'x' }, app, 'https://other.example')).status, 403);
  assert.equal((await app.request('/contact', { method: 'GET' })).status, 405);
  assert.equal((await app.request('/contact', { method: 'POST', headers: { Origin: origin }, body: 'x' })).status, 415);
  assert.equal((await app.request('/contact', { method: 'POST', headers: { Origin: origin,
    'Content-Type': 'application/json' }, body: '{' })).status, 400);
});
test('oversized fixed and streamed bodies rejected before verification', async () => {
  assert.equal((await post({ message: 'x'.repeat(17000), token: 'x' })).status, 413);
  const stream = new ReadableStream({ start(c) {
    c.enqueue(new Uint8Array(9000)); c.enqueue(new Uint8Array(9000)); c.close();
  } });
  const response = await app.fetch(new Request(`${origin}/contact`, { method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json' }, body: stream, duplex: 'half' }));
  assert.equal(response.status, 413);
});
test('outages and malformed verification replies fail closed', async () => {
  for (const [fetchImpl, expected] of [
    [async () => { throw new DOMException('timeout', 'TimeoutError'); }, 503],
    [async () => new Response('unavailable', { status: 500 }), 503],
    [async () => new Response('not json'), 503],
    [async () => Response.json({ success: 'true' }), 503],
    [async () => Response.json({ success: true, hostname: 'other.example', action: 'contact' }), 403],
  ]) {
    const other = createApp({ ...settings, fetchImpl });
    const response = await post({ message: 'x', token: 'x' }, other);
    assert.equal(response.status, expected);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  }
});
test('verification transport uses private credentials, timeout and redirect protection', async () => {
  const other = createApp({ ...settings, fetchImpl: async (url, options) => {
    assert.equal(url, `${settings.captchaOrigin}/siteverify`);
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal);
    assert.equal(options.body.get('secret'), settings.verifySecret);
    assert.equal(options.body.get('response'), 'x');
    return Response.json({ success: true, hostname: '127.0.0.1', action: 'contact' });
  } });
  assert.equal((await post({ message: 'x', token: 'x' }, other)).status, 200);
});
test('public config has no secrets; source files unavailable', async () => {
  const response = await app.request('/config');
  assert.deepEqual(await response.json(), { captchaOrigin: settings.captchaOrigin, siteKey: 'hono-demo' });
  assert.equal((await app.request('/app.mjs')).status, 404);
});
