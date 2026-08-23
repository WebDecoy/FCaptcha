'use strict';

const INSECURE_DEFAULT_SECRET = 'dev-secret-change-in-production';

// The library constructs the secret more than once per process (the challenge
// store and the scoring engine each resolve it), which printed the dev-mode
// warning twice. Once is the warning; twice is noise that trains people to
// scroll past it.
let devModeWarned = false;

function signingSecretFromEnv(env = process.env) {
  const secret = String(env.FCAPTCHA_SECRET || '').trim();
  if (secret && secret !== INSECURE_DEFAULT_SECRET) return secret;
  if (/^(1|true|yes|on)$/i.test(String(env.FCAPTCHA_INSECURE_DEV_MODE || '').trim())) {
    if (!devModeWarned) {
      devModeWarned = true;
      console.warn('WARNING: FCAPTCHA_INSECURE_DEV_MODE enabled; tokens use a public signing key. Never expose this server to a network.');
    }
    return INSECURE_DEFAULT_SECRET;
  }
  throw new Error('FCAPTCHA_SECRET is required and must not be the public development key. For local-only development, explicitly set FCAPTCHA_INSECURE_DEV_MODE=1.');
}

function signingSecret(explicit, env = process.env) {
  if (explicit !== undefined && explicit !== null) {
    return signingSecretFromEnv({ ...env, FCAPTCHA_SECRET: explicit });
  }
  return signingSecretFromEnv(env);
}

module.exports = { INSECURE_DEFAULT_SECRET, signingSecret, signingSecretFromEnv };
