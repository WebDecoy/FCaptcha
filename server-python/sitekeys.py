"""
Bounds on server-side state keyed by client-supplied values.

FCaptcha partitions rate-limit, fingerprint and challenge state by site_key,
which no server validates against any registry - the only existing check is that
a PoW solution's site_key matches its own challenge, which is internal
consistency, not registration. Every partition key therefore begins with a string
the caller chose:

    pow:{site_key}:{ip}   PoW difficulty escalation
    {site_key}:{ip}       rate-abuse detection
    {site_key}:{fp}       fingerprint reuse

A caller varying site_key per request allocates unbounded map entries. This is
not a detection bypass - obtaining a challenge for site X requires asking with
site_key=X, which lands in X's bucket - but it is a memory-exhaustion vector.

SiteKeyGuard caps how many distinct site_keys one IP may allocate state for and
folds the excess into a single overflow bucket. Folding rather than rejecting has
a useful property: a caller rotating site_keys to dodge rate limiting ends up
sharing one bucket, so requests accumulate against it faster than with a single
honest key. The evasion makes the limit bite harder.

Mirrors server-node/limits.js and server-go/sitekeys.go.
"""

import os
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Set

# Distinct site_keys one IP may allocate state for. A browser uses exactly one;
# a shared NAT egress or CDN might carry a handful.
DEFAULT_MAX_SITE_KEYS_PER_IP = 8

# Where excess or unlisted site_keys are filed. Deliberately not a valid key
# shape so it cannot collide with a real one.
OVERFLOW_SITE_KEY = " overflow"

# Bound on the tracking table itself, so the guard cannot become the leak it
# prevents.
MAX_TRACKED_IPS = 50_000
SITE_KEY_WINDOW_S = 3600


class BoundedLRU:
    """An insertion-ordered dict with a maximum size and LRU eviction.

    Replaces the `if len(x) > N: x.clear()` pattern, which discards every
    legitimate entry at once - precisely the flush an attacker wants.
    """

    def __init__(self, max_entries: int):
        self.max_entries = max_entries
        self.evictions = 0
        self._d: "OrderedDict[str, object]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._d)

    def __contains__(self, key: str) -> bool:
        return key in self._d

    def get(self, key: str, default=None):
        if key not in self._d:
            return default
        self._d.move_to_end(key)
        return self._d[key]

    def set(self, key: str, value) -> None:
        if key in self._d:
            self._d.move_to_end(key)
        self._d[key] = value
        while len(self._d) > self.max_entries:
            self._d.popitem(last=False)
            self.evictions += 1

    def delete(self, key: str) -> None:
        self._d.pop(key, None)

    def prune(self, keep) -> None:
        """Drop entries failing keep(value, key). Expiry sweep without a clear."""
        for key in [k for k, v in self._d.items() if not keep(v, k)]:
            del self._d[key]


class SiteKeyGuard:
    """Caps distinct site_keys per source IP, with an optional allowlist."""

    def __init__(
        self,
        allowlist: Optional[List[str]] = None,
        max_per_ip: int = DEFAULT_MAX_SITE_KEYS_PER_IP,
        window_s: int = SITE_KEY_WINDOW_S,
        max_tracked_ips: int = MAX_TRACKED_IPS,
    ):
        cleaned = [k.strip() for k in (allowlist or []) if k and k.strip()]
        self.allowlist: Optional[Set[str]] = set(cleaned) if cleaned else None
        self.max_per_ip = max_per_ip if max_per_ip > 0 else DEFAULT_MAX_SITE_KEYS_PER_IP
        self.window_s = window_s
        self.seen = BoundedLRU(max_tracked_ips)
        self.overflows = 0
        self.rejected_by_allowlist = 0

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "SiteKeyGuard":
        """FCAPTCHA_SITE_KEYS (comma-separated, unset = any) and
        FCAPTCHA_MAX_SITE_KEYS_PER_IP."""
        env = os.environ if env is None else env
        raw = env.get("FCAPTCHA_SITE_KEYS")
        allowlist = raw.split(",") if raw else None
        max_per_ip = DEFAULT_MAX_SITE_KEYS_PER_IP
        raw_max = env.get("FCAPTCHA_MAX_SITE_KEYS_PER_IP")
        if raw_max:
            try:
                parsed = int(raw_max.strip())
                if parsed > 0:
                    max_per_ip = parsed
            except ValueError:
                print(f'warning: ignoring invalid FCAPTCHA_MAX_SITE_KEYS_PER_IP "{raw_max}"')
        return cls(allowlist=allowlist, max_per_ip=max_per_ip)

    def describe(self) -> str:
        listing = f"{len(self.allowlist)} allowlisted" if self.allowlist else "any (no allowlist)"
        return f"{listing}, max {self.max_per_ip} distinct per IP"

    def normalize(self, site_key: Optional[str], ip: Optional[str]) -> str:
        """Return the site_key state should be filed under.

        Never rejects a request: an over-quota caller is folded into the overflow
        bucket, which bounds state while leaving the request answerable.
        """
        key = site_key if isinstance(site_key, str) and site_key else "default"

        if self.allowlist is not None and key not in self.allowlist:
            self.rejected_by_allowlist += 1
            return OVERFLOW_SITE_KEY
        if not ip:
            return key

        now = time.time()
        record = self.seen.get(ip)
        if record is None or now - record["since"] > self.window_s:
            record = {"since": now, "keys": set()}
            self.seen.set(ip, record)

        if key in record["keys"]:
            return key
        if len(record["keys"]) >= self.max_per_ip:
            self.overflows += 1
            return OVERFLOW_SITE_KEY
        record["keys"].add(key)
        return key
