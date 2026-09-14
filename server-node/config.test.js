'use strict';

const assert = require('assert');
const { INSECURE_DEFAULT_SECRET, signingSecret, signingSecretFromEnv } = require('./config');

assert.throws(() => signingSecretFromEnv({}), /FCAPTCHA_SECRET is required/);
assert.throws(() => signingSecretFromEnv({ FCAPTCHA_SECRET: INSECURE_DEFAULT_SECRET }), /FCAPTCHA_SECRET is required/);
assert.strictEqual(signingSecretFromEnv({ FCAPTCHA_SECRET: 'a-real-deployment-secret-0123456789abcdef0123456789abcdef' }), 'a-real-deployment-secret-0123456789abcdef0123456789abcdef');
assert.strictEqual(signingSecretFromEnv({ FCAPTCHA_INSECURE_DEV_MODE: 'true' }), INSECURE_DEFAULT_SECRET);
assert.strictEqual(signingSecret('explicit-library-secret-0123456789abcdef0123456789abcdef', {}), 'explicit-library-secret-0123456789abcdef0123456789abcdef');
assert.throws(() => signingSecret(undefined, {}), /FCAPTCHA_SECRET is required/);
for (const secret of ['x', 'my-secret', 'a'.repeat(64), 'abcd'.repeat(16)]) {
  assert.throws(() => signingSecretFromEnv({ FCAPTCHA_SECRET: secret }), /FCAPTCHA_SECRET is required/);
}

console.log('signing-secret configuration tests passed');
