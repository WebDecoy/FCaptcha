import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createApi } from './angular/api.mjs';
const framework = process.argv[2];
if (!['angular', 'next'].includes(framework)) throw new Error('Choose angular or next');
Object.assign(process.env, {
  FCAPTCHA_SECRET: randomBytes(32).toString('hex'), FCAPTCHA_VERIFY_SECRET: randomBytes(32).toString('hex'),
  FCAPTCHA_ALLOWED_HOSTNAMES: '127.0.0.1', FCAPTCHA_SITE_KEYS: 'framework-contact',
  TRUSTED_PROXIES: 'none', REDIS_URL: '', FCAPTCHA_LEGACY_UNAUTH_VERIFY: 'false',
  FCAPTCHA_INSECURE_DEV_MODE: 'false', FCAPTCHA_LOG_VERDICTS: 'false',
  APP_ORIGIN: framework === 'angular' ? 'http://127.0.0.1:4200' : 'http://127.0.0.1:3000',
  FCAPTCHA_ORIGIN: 'http://127.0.0.1:8788'
});
const require = createRequire(import.meta.url);
const { app } = require('../../server-node/server.js');
const captcha = app.listen(8788, '127.0.0.1'); await once(captcha, 'listening');
let api;
if (framework === 'angular') {
  api = createApi({ origin: process.env.APP_ORIGIN, captchaOrigin: process.env.FCAPTCHA_ORIGIN,
    verifySecret: process.env.FCAPTCHA_VERIFY_SECRET }).listen(4201, '127.0.0.1');
  await once(api, 'listening');
}
const child = spawn('npm', ['run', framework === 'angular' ? 'start' : 'dev'], {
  cwd: new URL(framework === 'angular' ? './angular/' : './nextjs/', import.meta.url), stdio: 'inherit', env: process.env
});
console.log('Open ' + process.env.APP_ORIGIN + ' — local demo; no messages stored or sent.');
function stop() { child.kill('SIGTERM'); captcha.closeAllConnections(); captcha.close(); api?.closeAllConnections(); api?.close(); }
for (const signal of ['SIGINT','SIGTERM']) process.once(signal, stop);
child.once('exit', () => { stop(); process.exit(0); });
