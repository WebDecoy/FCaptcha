import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { serve } from '@hono/node-server';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { captcha } from 'better-auth/plugins';
import { Hono } from 'hono';

const hostname = '127.0.0.1';
const port = 8796;
const origin = `http://${hostname}:${port}`;
const captchaOrigin = `http://${hostname}:8797`;
const verifySecret = process.env.FCAPTCHA_VERIFY_SECRET;
if (!verifySecret) throw new Error('Set FCAPTCHA_VERIFY_SECRET before starting the demo.');

const auth = betterAuth({
  baseURL: origin,
  secret: randomBytes(32).toString('hex'),
  telemetry: { enabled: false },
  database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
  emailAndPassword: { enabled: true },
  plugins: [captcha({
    provider: 'cloudflare-turnstile',
    siteVerifyURLOverride: `${captchaOrigin}/turnstile/v0/siteverify`,
    secretKey: verifySecret,
    allowedHostnames: [hostname],
    expectedAction: 'auth',
  })],
});

const app = new Hono();
const page = await readFile(new URL('./index.html', import.meta.url), 'utf8');
app.get('/', (c) => c.html(page));
app.on(['GET', 'POST'], '/api/auth/*', (c) => auth.handler(c.req.raw));

serve({ fetch: app.fetch, hostname, port }, () => console.log(`Open ${origin}`));
