// Local demo only. Supabase CLI runs the Edge Function separately in Docker.
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { once } from 'node:events';

for (const key of Object.keys(process.env)) {
  if (key.startsWith('FCAPTCHA_') || ['REDIS_URL', 'TRUSTED_PROXIES'].includes(key)) delete process.env[key];
}
process.env.FCAPTCHA_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_VERIFY_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_SITE_KEYS = 'supabase-demo';
process.env.FCAPTCHA_ALLOWED_HOSTNAMES = '127.0.0.1';
process.env.TRUSTED_PROXIES = 'none';
const require = createRequire(import.meta.url);
const { app } = require('../../server-node/server.js');
const captcha = app.listen(8793, '127.0.0.1');
await once(captcha, 'listening');
await writeFile(new URL('.env.local', import.meta.url), [
  'APP_ORIGIN=http://127.0.0.1:8792',
  'FCAPTCHA_ORIGIN=http://host.docker.internal:8793',
  `FCAPTCHA_VERIFY_SECRET=${process.env.FCAPTCHA_VERIFY_SECRET}`,
  '',
].join('\n'), { mode: 0o600 });
const page = await readFile(new URL('index.html', import.meta.url));
const frontend = createServer((request, response) => {
  if (request.method !== 'GET' || request.url !== '/') {
    response.writeHead(404).end(); return;
  }
  response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(page);
});
frontend.listen(8792, '127.0.0.1');
await once(frontend, 'listening');
console.log('Demo: http://127.0.0.1:8792. Fresh private verification credentials written to .env.local.');
console.log('Next: npx supabase functions serve fcaptcha-contact --env-file .env.local');
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  frontend.closeAllConnections(); frontend.close();
  captcha.closeAllConnections(); captcha.close();
  process.exit(0);
});
