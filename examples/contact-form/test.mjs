import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes, createHmac } from 'node:crypto';
import { createRequire } from 'node:module';
import { createContactServer } from './server.mjs';

// Sign fixtures with an ephemeral test key. This tests the real siteverify
// contract, not browser detection or the human experience of solving a CAPTCHA.
process.env.FCAPTCHA_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_VERIFY_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_LEGACY_UNAUTH_VERIFY = 'false';
process.env.REDIS_URL = '';
const require = createRequire(import.meta.url);
const { app } = require('../../server-node/server.js');
const captcha = app.listen(0, '127.0.0.1');
await once(captcha, 'listening');
const captchaOrigin = `http://127.0.0.1:${captcha.address().port}`;
const origin = 'http://127.0.0.1:8787';
let unavailable = false;
const contact = createContactServer({ origin, captchaOrigin,
  verifySecret: process.env.FCAPTCHA_VERIFY_SECRET,
  fetchImpl: (...args) => { if (unavailable) throw new Error('offline'); return fetch(...args); }
});
contact.listen(0, '127.0.0.1');
await once(contact, 'listening');
const url = `http://127.0.0.1:${contact.address().port}`;
after(() => { contact.closeAllConnections(); captcha.closeAllConnections(); contact.close(); captcha.close(); });
function token(overrides = {}) {
  const data = { site_key: 'contact-form', jti: randomBytes(16).toString('hex'),
    timestamp: Math.floor(Date.now()/1000), score: 0.05, ip_hash: '',
    hostname: '127.0.0.1', action: 'contact', cdata: '', ...overrides };
  const payload = JSON.stringify(data, Object.keys(data).sort());
  data.sig = createHmac('sha256', process.env.FCAPTCHA_SECRET).update(payload).digest('hex');
  return Buffer.from(JSON.stringify(data)).toString('base64url');
}
function post(data, from = origin) {
  return fetch(`${url}/contact`, { method: 'POST',
    headers: { Origin: from, 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
}
test('valid signed token passes once; replay fails', async () => {
  const body = { message: 'test', token: token() };
  const response = await post(body);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { accepted: true, demoOnly: true });
  assert.equal((await post(body)).status, 403);
});
for (const [name, overrides] of [['wrong hostname', { hostname: 'evil.example' }],
  ['wrong action', { action: 'login' }], ['expired token', { timestamp: 1 }]]) {
  test(name, async () => assert.equal((await post({ message: 'test', token: token(overrides) })).status, 403));
}
test('forged token rejected', async () => {
  assert.equal((await post({ message: 'test', token: 'forged' })).status, 403);
});
test('missing token and invalid message rejected', async () => {
  for (const body of [{ message: 'test' }, { message: '', token: token() }, null]) {
    assert.equal((await post(body)).status, 400);
  }
});
test('cross-origin submission rejected', async () => {
  assert.equal((await post({ message: 'test', token: token() }, 'https://evil.example')).status, 403);
});
test('body size bounded', async () => {
  assert.equal((await post({ message: 'x'.repeat(20000), token: token() })).status, 413);
});
test('verification outage fails closed', async () => {
  unavailable = true;
  try { assert.equal((await post({ message: 'test', token: token() })).status, 503); }
  finally { unavailable = false; }
});
test('public config contains no secrets; static page available', async () => {
  const config = await (await fetch(`${url}/config`)).json();
  assert.deepEqual(config, { captchaOrigin, siteKey: 'contact-form' });
  const page = await (await fetch(url)).text();
  assert.match(page, /lang="ja"/);
  assert.ok(!page.includes(process.env.FCAPTCHA_SECRET));
});
