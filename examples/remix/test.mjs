import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { after, before, test } from 'node:test';
import { createContactRouter } from './server.mjs';

const appOrigin = 'http://127.0.0.1:8796';
const secret = 'test-only-verification-marker';
const accepted = { success: true, hostname: '127.0.0.1', action: 'contact' };
const results = {
  valid: accepted,
  wrongHostname: { ...accepted, hostname: 'other.example' },
  wrongAction: { ...accepted, action: 'signup' },
  expired: { success: false, 'error-codes': ['timeout-or-duplicate'] },
  rejected: { success: false, 'error-codes': ['invalid-input-response'] },
  wrongSecret: { success: false, 'error-codes': ['invalid-input-secret'] },
  malformed: { hostname: '127.0.0.1' },
};

const verifier = createServer(async (request, response) => {
  let body = '';
  for await (const chunk of request) body += chunk;
  const data = new URLSearchParams(body);
  const result = results[data.get('response')];
  if (request.url !== '/turnstile/v0/siteverify' || request.method !== 'POST' ||
      data.get('secret') !== secret || !result) {
    return response.writeHead(503).end();
  }
  response.setHeader('Content-Type', 'application/json');
  response.end(JSON.stringify(result));
});

let router;
let verifierOrigin;

before(async () => {
  verifier.listen(0, '127.0.0.1');
  await once(verifier, 'listening');
  verifierOrigin = 'http://127.0.0.1:' + verifier.address().port;
  router = createContactRouter({ appOrigin, verifierOrigin, secret });
});

after(async () => {
  await new Promise(resolve => verifier.close(resolve));
});

function submit(token, origin = appOrigin, message = 'Demo message') {
  return router.fetch(new Request(appOrigin + '/contact', {
    method: 'POST',
    headers: { origin },
    body: new URLSearchParams({ message, fcaptcha_token: token }),
  }));
}

test('serves the form and widget URL with no verification secret', async () => {
  const response = await router.fetch(appOrigin);
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.ok(body.includes(verifierOrigin + '/fcaptcha.js'));
  assert.ok(!body.includes(secret));
});

for (const [token, status] of [
  ['', 403],
  ['valid', 200],
  ['wrongHostname', 403],
  ['wrongAction', 403],
  ['expired', 403],
  ['rejected', 403],
  ['wrongSecret', 503],
  ['malformed', 503],
  ['unavailable', 503],
]) {
  test('returns ' + status + ' for ' + (token || 'missing token'), async () => {
    const response = await submit(token);
    assert.equal(response.status, status);
    assert.equal((await response.text()).includes('Demo submission accepted.'), status === 200);
  });
}

test('rejects a different request origin', async () => {
  const response = await submit('valid', 'https://different.example');
  assert.equal(response.status, 403);
  assert.match(await response.text(), /origin refused/);
});

test('middleware leaves the body readable for input validation', async () => {
  const response = await submit('valid', appOrigin, '');
  assert.equal(response.status, 400);
});
