"""Adaptive challenge cost: what a source pays is a function of what that source
has recently been caught doing, rather than a constant.

Why the cost is mostly time, not hashing
----------------------------------------
A constant difficulty is strictly dominated: it either fails to inconvenience an
attacker or it does hurt real users. The measurements behind that claim: browser
JS runs 1-3M hash/s, native code 100-500M/s, so difficulty 6 costs a native
solver about a millisecond and a budget Android phone about sixteen seconds.
Raising difficulty is close to a pure tax on the slowest legitimate devices.

Wall-clock is the knob that does not have that property. Nobody can make less
time pass, so a minimum challenge age caps how fast one source can mint tokens
no matter what hardware it brings. So suspicion moves the time floor first and
difficulty barely at all.

What this deliberately is not
-----------------------------
This is not Workstream F 10.1 (cross-session correlation). It stores strong-
verdict timestamps per source, nothing else: no behavioral vectors, no
per-fingerprint history, no traces that survive the window. It is the same shape
and the same privacy class as the rate limiter sitting next to it, and it should
stay that way - 10.1 has a privacy load this does not, and the two should not be
conflated because they happen to both be "server-side memory".
"""

import threading
import time
from collections import OrderedDict
from typing import Dict, List, Tuple

# The verdict score at or above which a verification counts as evidence.
# Deliberately high: a marginal verdict is exactly the case where the scoring
# might be wrong about a real person, and making the next person from that
# address wait is not worth the guess.
STRONG_SCORE = 0.8

# How long a strong verdict keeps counting. Short enough that a shared egress
# address recovers on its own within a coffee break.
WINDOW_MS = 15 * 60 * 1000

# Only the count matters and every tier saturates well below this.
MAX_HITS = 16

# Bounds the table. Sources with no strong verdicts never get an entry at all,
# so this only has to cover addresses actively failing verification.
MAX_SOURCES = 50_000


class SuspicionLedger:
    """Records recent strong verdicts per source.

    Entries are created only when a source produces a strong verdict, so the
    common case - a legitimate visitor - allocates nothing and looks up nothing
    but a miss.
    """

    def __init__(self) -> None:
        self._hits: "OrderedDict[str, List[int]]" = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(site_key: str, ip: str) -> str:
        return f"{site_key}|{ip}"

    def record(self, site_key: str, ip: str, score: float) -> None:
        """Note a verdict.

        Scores below the strong threshold are ignored entirely rather than
        recorded and weighted, so a source that merely looks unusual never
        accumulates anything.
        """
        if not ip or score is None or score < STRONG_SCORE:
            return

        key = self._key(site_key, ip)
        now = int(time.time() * 1000)
        cutoff = now - WINDOW_MS

        with self._lock:
            kept = [t for t in self._hits.get(key, []) if t > cutoff]
            kept.append(now)
            self._hits[key] = kept[-MAX_HITS:]
            # move_to_end makes this the most recently touched key, so the
            # eviction below drops the stalest source rather than an active one.
            self._hits.move_to_end(key)

            while len(self._hits) > MAX_SOURCES:
                self._hits.popitem(last=False)

    def count(self, site_key: str, ip: str) -> int:
        """How many strong verdicts this source produced inside the window.

        Counted from the timestamps rather than from the entry's existence, so
        an old hit actually decays while newer ones keep the entry alive.
        """
        if not ip:
            return 0

        key = self._key(site_key, ip)
        cutoff = int(time.time() * 1000) - WINDOW_MS

        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return 0
            n = sum(1 for t in hits if t > cutoff)
            if n == 0:
                self._hits.pop(key, None)
            return n


# Baseline cost. A clean visitor pays exactly this, which is what the server has
# always charged everyone.
BASE_DIFFICULTY = 4
BASE_MIN_AGE_MS = 1500

# Caps the compute knob at 5, below the 6 this server used to reach. Difficulty
# 6 buys about a millisecond of attacker time and spends about sixteen seconds
# of a budget phone's; the escalation belongs in min_age_ms where an attacker
# cannot buy their way out of it.
MAX_DIFFICULTY = 5

# Caps the time knob at 15s. At the 1.5s baseline one address can mint roughly
# 40 tokens a minute; at 15s, four. Pushing further buys little and is felt by
# anyone sharing a poisoned egress address.
MAX_MIN_AGE_MS = 15_000


def compute_challenge_cost(
    strong_hits: int,
    is_datacenter: bool = False,
    request_count: int = 0,
    rate_exceeded: bool = False,
) -> Tuple[int, int]:
    """Map accumulated suspicion onto a cost, as ``(difficulty, min_age_ms)``.

    Note what does NOT raise difficulty here: being on a datacenter address.
    That used to jump straight to difficulty 5, which charges a real person on a
    corporate VPN or iCloud Private Relay several seconds of blocked hashing on
    a slow phone for the offence of having a shared IP. It now moves the time
    floor instead, which a datacenter-hosted scraper feels as reduced throughput
    and a person filling in a form does not feel at all.
    """
    difficulty = BASE_DIFFICULTY
    min_age_ms = BASE_MIN_AGE_MS

    if strong_hits >= 6:
        difficulty, min_age_ms = 5, 15_000
    elif strong_hits >= 3:
        difficulty, min_age_ms = 5, 8_000
    elif strong_hits >= 1:
        min_age_ms = 4_000

    # Floors from signals that are suggestive rather than damning. They raise
    # the time floor and never the difficulty.
    if is_datacenter:
        min_age_ms = max(min_age_ms, 3_000)
    if request_count > 10:
        min_age_ms = max(min_age_ms, 6_000)
    if rate_exceeded:
        min_age_ms = max(min_age_ms, 10_000)

    return min(difficulty, MAX_DIFFICULTY), min(min_age_ms, MAX_MIN_AGE_MS)
