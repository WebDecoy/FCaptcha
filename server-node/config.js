'use strict';

const { EXPERIMENTAL_POLICY } = require('./experimental');

const INSECURE_DEFAULT_SECRET = 'dev-secret-change-in-production';

// The library constructs the secret more than once per process (the challenge
// store and the scoring engine each resolve it), which printed the dev-mode
// warning twice. Once is the warning; twice is noise that trains people to
// scroll past it.
let devModeWarned = false;

function signingSecretFromEnv(env = process.env) {
  const secret = String(env.FCAPTCHA_SECRET || '').trim();
  if (Buffer.byteLength(secret) >= 32 && new Set(secret).size >= 8 && secret !== INSECURE_DEFAULT_SECRET) return secret;
  if (/^(1|true|yes|on)$/i.test(String(env.FCAPTCHA_INSECURE_DEV_MODE || '').trim())) {
    if (!devModeWarned) {
      devModeWarned = true;
      console.warn('WARNING: FCAPTCHA_INSECURE_DEV_MODE enabled; tokens use a public signing key. Never expose this server to a network.');
    }
    return INSECURE_DEFAULT_SECRET;
  }
  throw new Error('FCAPTCHA_SECRET is required: use at least 32 random bytes (openssl rand -hex 32), not a short or repetitive password. For local-only development, explicitly set FCAPTCHA_INSECURE_DEV_MODE=1.');
}

function signingSecret(explicit, env = process.env) {
  if (explicit !== undefined && explicit !== null) {
    return signingSecretFromEnv({ ...env, FCAPTCHA_SECRET: explicit });
  }
  return signingSecretFromEnv(env);
}

function experimentalBlockingEnabled(explicit, env = process.env) {
  if (explicit !== undefined && explicit !== false && typeof explicit !== 'string') {
    throw new TypeError('experimentalBlocking must be a policy name or false');
  }
  const policy = explicit === undefined ? env.FCAPTCHA_EXPERIMENTAL_BLOCKING : explicit;
  return typeof policy === 'string' && policy.trim() === EXPERIMENTAL_POLICY;
}

module.exports = { INSECURE_DEFAULT_SECRET, signingSecret, signingSecretFromEnv, experimentalBlockingEnabled };
