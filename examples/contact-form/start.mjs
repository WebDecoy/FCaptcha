import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { once } from 'node:events';
import { createContactServer } from './server.mjs';

// Local-only example: ephemeral, separate credentials, no inherited Redis/proxy setup.
process.env.FCAPTCHA_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_VERIFY_SECRET = randomBytes(32).toString('hex');
process.env.FCAPTCHA_ALLOWED_HOSTNAMES = '127.0.0.1';
process.env.FCAPTCHA_SITE_KEYS = 'contact-form';
process.env.TRUSTED_PROXIES = 'none';
process.env.REDIS_URL = '';
process.env.FCAPTCHA_LEGACY_UNAUTH_VERIFY = 'false';
process.env.FCAPTCHA_INSECURE_DEV_MODE = 'false';
process.env.FCAPTCHA_LOG_VERDICTS = 'false';
const require = createRequire(import.meta.url);
const { app } = require('../../server-node/server.js');
const captcha = app.listen(8788, '127.0.0.1');
await once(captcha, 'listening');
const contact = createContactServer({
  origin: 'http://127.0.0.1:8787',
  captchaOrigin: 'http://127.0.0.1:8788',
  verifySecret: process.env.FCAPTCHA_VERIFY_SECRET
});
contact.listen(8787, '127.0.0.1');
await once(contact, 'listening');
console.log('Contact form: http://127.0.0.1:8787');
console.log('Local demo only: messages are neither sent nor stored. Ctrl+C to stop.');
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  contact.close(); captcha.close();
  contact.closeAllConnections(); captcha.closeAllConnections();
  process.exit(0);
});
