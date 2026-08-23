'use strict';

const assert = require('assert');
const { RedisState } = require('./redis-state');

class FakeRedis {
  constructor() {
    this.isOpen = true;
    this.values = new Map();
  }
  on() {}
  async ping() { return 'PONG'; }
  async set(key, value) { this.values.set(key, value); return 'OK'; }
  async get(key) { return this.values.get(key) || null; }
  async eval(_script, { keys }) {
    if (!this.values.has(keys[0])) return 0;
    if (this.values.has(keys[1])) return -1;
    this.values.set(keys[1], '1');
    this.values.delete(keys[0]);
    return 1;
  }
}

(async () => {
  const fake = new FakeRedis();
  const issuer = new RedisState('redis://unused', fake);
  const verifier = new RedisState('redis://unused', fake);
  const challenge = {
    id: 'challenge-1', siteKey: 'site', timestamp: Date.now(),
    expiresAt: Date.now() + 60_000, difficulty: 4, prefix: 'prefix',
    minAgeMs: 1500, nonce: 'binding', sig: 'signature', ip: '203.0.113.5'
  };

  await issuer.putChallenge(challenge);
  const loaded = await verifier.getChallenge(challenge.id);
  assert.strictEqual(loaded.id, challenge.id);
  assert.strictEqual(loaded.ip, challenge.ip);
  assert.strictEqual(JSON.parse(fake.values.values().next().value).challengeId, challenge.id);

  assert.deepStrictEqual(await verifier.claimChallenge(challenge.id, 'challenge-1:7'), { claimed: true });
  assert.deepStrictEqual(
    await issuer.claimChallenge(challenge.id, 'challenge-1:7'),
    { claimed: false, reason: 'challenge_not_found' }
  );
  console.log('redis shared-state tests passed');
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
