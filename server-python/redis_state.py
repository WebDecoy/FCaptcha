"""Redis-backed security state shared with the Go and Node servers."""

import hashlib
import json
import secrets
import time

import redis

PREFIX = "fcaptcha:v1:"
POW_TTL_MS = 300_000
SPENT_TTL_MS = 600_000
IDEMPOTENCY_TTL_MS = 300_000
DETECTION_TTL_MS = 900_000

CLAIM = """
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[1]) == false then return -1 end
redis.call('DEL', KEYS[1])
return 1
"""
RATE = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
local count = redis.call('ZCARD', KEYS[1]); local added = 0
if count < tonumber(ARGV[3]) then
 redis.call('ZADD', KEYS[1], ARGV[2], ARGV[4]); count=count+1; added=1
end
redis.call('PEXPIRE', KEYS[1], ARGV[5]); return {count, added}
"""
SITEKEY = """
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then
 redis.call('PEXPIRE', KEYS[1], ARGV[3]); return 1
end
if redis.call('SCARD', KEYS[1]) >= tonumber(ARGV[2]) then return 0 end
redis.call('SADD', KEYS[1], ARGV[1]); redis.call('PEXPIRE', KEYS[1], ARGV[3]); return 1
"""


class RedisState:
    def __init__(self, url: str, client=None):
        self.client = client or redis.Redis.from_url(url, decode_responses=True)
        self.client.ping()

    @staticmethod
    def opaque(kind: str, value: str) -> str:
        return f"{PREFIX}{kind}:{hashlib.sha256(value.encode()).hexdigest()}"

    @staticmethod
    def challenge_key(challenge_id: str) -> str:
        return f"{PREFIX}pow:challenge:{challenge_id}"

    def put_challenge(self, challenge: dict) -> None:
        ttl = challenge["expiresAt"] - int(time.time() * 1000)
        if ttl <= 0:
            raise RuntimeError("challenge already expired")
        stored = {**challenge, "challengeId": challenge["id"]}
        stored.pop("id", None)
        self.client.set(self.challenge_key(challenge["id"]), json.dumps(stored), px=ttl)

    def get_challenge(self, challenge_id: str):
        payload = self.client.get(self.challenge_key(challenge_id))
        if not payload:
            return None
        challenge = json.loads(payload)
        challenge["id"] = challenge.get("challengeId", challenge_id)
        return challenge

    def claim_challenge(self, challenge_id: str, solution_key: str):
        result = int(self.client.eval(
            CLAIM, 2, self.challenge_key(challenge_id),
            f"{PREFIX}pow:spent:{solution_key}", SPENT_TTL_MS,
        ))
        return result == 1, "solution_already_used" if result == -1 else "challenge_not_found"

    def claim_token(self, signature: str) -> bool:
        return bool(self.client.set(f"{PREFIX}token:spent:{signature}", "1", nx=True, px=SPENT_TTL_MS))

    def idempotency_key(self, key: str, token: str) -> str:
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:32]
        return self.opaque("siteverify:idempotency", f"{key}:{token_hash}")

    def get_idempotency(self, key: str, token: str):
        if not key:
            return None
        payload = self.client.get(self.idempotency_key(key, token))
        return json.loads(payload) if payload else None

    def set_idempotency(self, key: str, token: str, response: dict) -> None:
        if key:
            self.client.set(self.idempotency_key(key, token), json.dumps(response), px=IDEMPOTENCY_TTL_MS)

    def rate_check(self, key: str, window: int, maximum: int):
        now = int(time.time() * 1000)
        count, added = self.client.eval(
            RATE, 1, self.opaque("rate", key), now-window*1000, now, maximum,
            f"{now}:{secrets.token_hex(8)}", window*1000+1000,
        )
        return int(added) == 0, int(count)

    def record_suspicion(self, site_key: str, ip: str) -> None:
        now = int(time.time() * 1000); key = self.opaque("suspicion", f"{site_key}|{ip}")
        with self.client.pipeline(transaction=True) as p:
            p.zremrangebyscore(key, "-inf", now-DETECTION_TTL_MS)
            p.zadd(key, {f"{now}:{secrets.token_hex(8)}": now})
            p.zremrangebyrank(key, 0, -17).pexpire(key, DETECTION_TTL_MS).execute()

    def suspicion_count(self, site_key: str, ip: str) -> int:
        key = self.opaque("suspicion", f"{site_key}|{ip}")
        self.client.zremrangebyscore(key, "-inf", int(time.time()*1000)-DETECTION_TTL_MS)
        return int(self.client.zcard(key))

    def record_fingerprint(self, fp: str, ip: str, site_key: str) -> None:
        fp_key = self.opaque("fingerprint:ips", f"{site_key}|{fp}")
        ip_key = self.opaque("fingerprint:fps", ip)
        with self.client.pipeline(transaction=True) as p:
            p.sadd(fp_key, self.opaque("value:ip", ip)).pexpire(fp_key, DETECTION_TTL_MS)
            p.sadd(ip_key, self.opaque("value:fp", fp)).pexpire(ip_key, DETECTION_TTL_MS).execute()

    def ip_fingerprint_count(self, ip: str) -> int:
        return int(self.client.scard(self.opaque("fingerprint:fps", ip)))

    def fingerprint_ip_count(self, fp: str, site_key: str) -> int:
        return int(self.client.scard(self.opaque("fingerprint:ips", f"{site_key}|{fp}")))

    def claim_site_key(self, site_key: str, ip: str, maximum: int) -> bool:
        return int(self.client.eval(
            SITEKEY, 1, self.opaque("sitekeys", ip), self.opaque("value:sitekey", site_key),
            maximum, 3_600_000,
        )) == 1
