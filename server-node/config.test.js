'use strict';

const assert = require('assert');
const { INSECURE_DEFAULT_SECRET, signingSecret, signingSecretFromEnv } = require('./config');

assert.throws(() => signingSecretFromEnv({}), /FCAPTCHA_SECRET is required/);
assert.throws(() => signingSecretFromEnv({ FCAPTCHA_SECRET: INSECURE_DEFAULT_SECRET }), /FCAPTCHA_SECRET is required/);
assert.strictEqual(signingSecretFromEnv({ FCAPTCHA_SECRET: 'a-real-deployment-secret' }), 'a-real-deployment-secret');
assert.strictEqual(signingSecretFromEnv({ FCAPTCHA_INSECURE_DEV_MODE: 'true' }), INSECURE_DEFAULT_SECRET);
assert.strictEqual(signingSecret('explicit-library-secret', {}), 'explicit-library-secret');
assert.throws(() => signingSecret(undefined, {}), /FCAPTCHA_SECRET is required/);

console.log('signing-secret configuration tests passed');
