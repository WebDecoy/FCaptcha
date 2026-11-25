import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { after, before, test } from 'node:test';

const secret = 'local-verifier-test-marker';
const successfulResult = { success: true, hostname: '127.0.0.1', action: 'contact' };
const responses = {
  valid: successfulResult,
  wrongHostname: { ...successfulResult, hostname: 'different.example' },
  wrongAction: { ...successfulResult, action: 'signup' },
  rejected: { success: false },
  malformed: { hostname: '127.0.0.1' },
};

const verifier = createServer(async (request, response) => {
  let payload = '';
  for await (const chunk of request) payload += chunk;
  const form = new URLSearchParams(payload);
  if (request.url !== '/siteverify' || request.method !== 'POST' || form.get('secret') !== secret) {
    response.writeHead(400).end();
    return;
  }
  const outcome = responses[form.get('response')];
  if (!outcome) {
    response.writeHead(503).end();
    return;
  }
  response.setHeader('Content-Type', 'application/json');
  response.end(JSON.stringify(outcome));
});

const app = createServer();
let origin;

async function bind(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return 'http://127.0.0.1:' + server.address().port;
}

before(async () => {
  process.env.FCAPTCHA_ORIGIN = await bind(verifier);
  process.env.FCAPTCHA_PUBLIC_ORIGIN = process.env.FCAPTCHA_ORIGIN;
  process.env.FCAPTCHA_VERIFY_SECRET = secret;
  origin = await bind(app);
  process.env.ORIGIN = origin;
  const { handler } = await import('./build/handler.js');
  app.on('request', handler);
});

after(async () => {
  await Promise.all([app, verifier].map(server => new Promise(resolve => server.close(resolve))));
});

test('loads the form and public widget URL without serializing the secret', async () => {
  const result = await fetch(origin);
  assert.equal(result.status, 200);
  const html = await result.text();
  assert.ok(html.includes(process.env.FCAPTCHA_PUBLIC_ORIGIN + '/fcaptcha.js'));
  assert.ok(!html.includes(secret));
});

for (const [token, status] of [
  ['', 400],
  ['valid', 200],
  ['wrongHostname', 403],
  ['wrongAction', 403],
  ['rejected', 403],
  ['malformed', 503],
  ['unavailable', 503],
]) {
  test('form action returns ' + status + ' for ' + (token || 'missing token'), async () => {
    const result = await fetch(origin, {
      method: 'POST',
      headers: { origin, accept: 'text/html' },
      body: new URLSearchParams({ message: 'Example message', fcaptcha_token: token }),
    });
    const html = await result.text();
    assert.equal(result.status, status);
    assert.equal(html.includes('Demo submission accepted.'), status === 200);
    assert.ok(!html.includes(secret));
  });
}
