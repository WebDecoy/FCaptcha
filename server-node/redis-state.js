'use strict';

const crypto = require('crypto');
const { createClient } = require('redis');

const PREFIX = 'fcaptcha:v1:';
const POW_TTL_MS = 5 * 60 * 1000;
const SPENT_TTL_MS = 10 * 60 * 1000;
const IDEMPOTENCY_TTL_MS = 5 * 60 * 1000;
const DETECTION_TTL_MS = 15 * 60 * 1000;

const CLAIM_CHALLENGE = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[1]) == false then return -1 end
redis.call('DEL', KEYS[1])
return 1
`;
const RATE_CHECK = `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
local count = redis.call('ZCARD', KEYS[1])
local added = 0
if count < tonumber(ARGV[3]) then
  redis.call('ZADD', KEYS[1], ARGV[2], ARGV[4])
  count = count + 1
  added = 1
end
redis.call('PEXPIRE', KEYS[1], ARGV[5])
return {count, added}
`;
const SITEKEY_CLAIM = `
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
  return 1
end
if redis.call('SCARD', KEYS[1]) >= tonumber(ARGV[2]) then return 0 end
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
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

  opaqueKey(kind, value) {
    const digest = crypto.createHash('sha256').update(value).digest('hex');
    return `${PREFIX}${kind}:${digest}`;
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

  async claimToken(signature) {
    return Boolean(await this.client.set(
      `${PREFIX}token:spent:${signature}`,
      '1',
      { NX: true, PX: SPENT_TTL_MS }
    ));
  }

  idempotencyKey(idempotencyKey, token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex').slice(0, 32);
    const composite = `${idempotencyKey}:${tokenHash}`;
    const opaque = crypto.createHash('sha256').update(composite).digest('hex');
    return `${PREFIX}siteverify:idempotency:${opaque}`;
  }

  async getIdempotency(idempotencyKey, token) {
    if (!idempotencyKey) return null;
    const payload = await this.client.get(this.idempotencyKey(idempotencyKey, token));
    return payload ? JSON.parse(payload) : null;
  }

  async setIdempotency(idempotencyKey, token, response) {
    if (!idempotencyKey) return;
    await this.client.set(
      this.idempotencyKey(idempotencyKey, token),
      JSON.stringify(response),
      { PX: IDEMPOTENCY_TTL_MS }
    );
  }

  async rateCheck(key, windowSeconds, maxRequests) {
    const now = Date.now();
    const result = await this.client.eval(RATE_CHECK, {
      keys: [this.opaqueKey('rate', key)],
      arguments: [
        String(now - windowSeconds * 1000), String(now), String(maxRequests),
        `${now}:${crypto.randomBytes(8).toString('hex')}`, String(windowSeconds * 1000 + 1000)
      ]
    });
    return [Number(result[1]) === 0, Number(result[0])];
  }

  async recordSuspicion(siteKey, ip) {
    const now = Date.now();
    const key = this.opaqueKey('suspicion', `${siteKey}|${ip}`);
    await this.client.multi()
      .zRemRangeByScore(key, '-inf', now - DETECTION_TTL_MS)
      .zAdd(key, { score: now, value: `${now}:${crypto.randomBytes(8).toString('hex')}` })
      .zRemRangeByRank(key, 0, -17)
      .pExpire(key, DETECTION_TTL_MS)
      .exec();
  }

  async suspicionCount(siteKey, ip) {
    const key = this.opaqueKey('suspicion', `${siteKey}|${ip}`);
    await this.client.zRemRangeByScore(key, '-inf', Date.now() - DETECTION_TTL_MS);
    return Number(await this.client.zCard(key));
  }

  async recordFingerprint(fingerprint, ip, siteKey) {
    const fpKey = this.opaqueKey('fingerprint:ips', `${siteKey}|${fingerprint}`);
    const ipKey = this.opaqueKey('fingerprint:fps', ip);
    await this.client.multi()
      .sAdd(fpKey, this.opaqueKey('value:ip', ip)).pExpire(fpKey, DETECTION_TTL_MS)
      .sAdd(ipKey, this.opaqueKey('value:fp', fingerprint)).pExpire(ipKey, DETECTION_TTL_MS)
      .exec();
  }

  async ipFingerprintCount(ip) {
    return Number(await this.client.sCard(this.opaqueKey('fingerprint:fps', ip)));
  }

  async fingerprintIpCount(fingerprint, siteKey) {
    return Number(await this.client.sCard(this.opaqueKey('fingerprint:ips', `${siteKey}|${fingerprint}`)));
  }

  async claimSiteKey(siteKey, ip, maxPerIp) {
    return Number(await this.client.eval(SITEKEY_CLAIM, {
      keys: [this.opaqueKey('sitekeys', ip)],
      arguments: [this.opaqueKey('value:sitekey', siteKey), String(maxPerIp), String(60 * 60 * 1000)]
    })) === 1;
  }
}

module.exports = { RedisState, PREFIX, POW_TTL_MS, SPENT_TTL_MS, IDEMPOTENCY_TTL_MS };
