import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { serve } from '@hono/node-server';
import { createApp } from './app.mjs';

// Local-only demo: do not inherit production secrets, Redis, or proxy settings.
for (const key of Object.keys(process.env)) {
  if (key.startsWith('FCAPTCHA_') || ['REDIS_URL', 'TRUSTED_PROXIES'].includes(key)) delete process.env[key];
}
process.env.FCAPTCHA_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_VERIFY_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_ALLOWED_HOSTNAMES = '127.0.0.1';
process.env.FCAPTCHA_SITE_KEYS = 'hono-demo';
process.env.TRUSTED_PROXIES = 'none';
const require = createRequire(import.meta.url);
const { app: verifier } = require('../../server-node/server.js');
const captcha = verifier.listen(8795, '127.0.0.1');
await once(captcha, 'listening');
// Reuse the existing sample form; only the visible framework name changes.
const assets = await Promise.all(['index.html', 'app.js'].map(async name =>
  (await readFile(new URL(`../fastapi/static/${name}`, import.meta.url), 'utf8')).replaceAll('FastAPI', 'Hono')));
const app = createApp({ origin: 'http://127.0.0.1:8794', captchaOrigin: 'http://127.0.0.1:8795',
  verifySecret: process.env.FCAPTCHA_VERIFY_SECRET, page: assets[0], script: assets[1] });
const server = serve({ fetch: app.fetch, hostname: '127.0.0.1', port: 8794 }, () => {
  console.log('Open http://127.0.0.1:8794. Local demo: messages are neither stored nor sent.');
});
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  server.closeAllConnections(); server.close();
  captcha.closeAllConnections(); captcha.close();
  process.exit(0);
});
