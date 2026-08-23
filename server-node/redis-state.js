'use strict';

const { createClient } = require('redis');

const PREFIX = 'fcaptcha:v1:';
const POW_TTL_MS = 5 * 60 * 1000;
const SPENT_TTL_MS = 10 * 60 * 1000;

const CLAIM_CHALLENGE = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[1]) == false then return -1 end
redis.call('DEL', KEYS[1])
return 1
`;

class RedisState {
  constructor(url, client = null) {
    this.client = client || createClient({ url });
    this.client.on?.('error', (err) => console.error('[redis]', err.message));
  }

  async connect() {
    if (!this.client.isOpen) await this.client.connect();
    await this.client.ping();
  }

  challengeKey(id) {
    return `${PREFIX}pow:challenge:${id}`;
  }

  async putChallenge(challenge) {
    const ttl = challenge.expiresAt - Date.now();
    if (ttl <= 0) throw new Error('challenge already expired');
    // challengeId is the canonical cross-runtime field used by Go and Node.
    const stored = { ...challenge, challengeId: challenge.id };
    delete stored.id;
    await this.client.set(this.challengeKey(challenge.id), JSON.stringify(stored), { PX: ttl });
  }

  async getChallenge(id) {
    const payload = await this.client.get(this.challengeKey(id));
    if (!payload) return null;
    const challenge = JSON.parse(payload);
    return { ...challenge, id: challenge.challengeId };
  }

  async claimChallenge(challengeId, solutionKey) {
    const result = Number(await this.client.eval(CLAIM_CHALLENGE, {
      keys: [this.challengeKey(challengeId), `${PREFIX}pow:spent:${solutionKey}`],
      arguments: [String(SPENT_TTL_MS)]
    }));
    if (result === 1) return { claimed: true };
    return {
      claimed: false,
      reason: result === -1 ? 'solution_already_used' : 'challenge_not_found'
    };
  }
}

module.exports = { RedisState, PREFIX, POW_TTL_MS, SPENT_TTL_MS };
