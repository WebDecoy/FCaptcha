'use strict';

/**
 * Adaptive challenge cost: what a source pays is a function of what that source
 * has recently been caught doing, rather than a constant.
 *
 * Why the cost is mostly time, not hashing
 * ----------------------------------------
 * A constant difficulty is strictly dominated: it either fails to inconvenience
 * an attacker or it does hurt real users. The measurements behind that claim:
 * browser JS runs 1-3M hash/s, native code 100-500M/s, so difficulty 6 costs a
 * native solver about a millisecond and a budget Android phone about sixteen
 * seconds. Raising difficulty is close to a pure tax on the slowest legitimate
 * devices.
 *
 * Wall-clock is the knob that does not have that property. Nobody can make less
 * time pass, so a minimum challenge age caps how fast one source can mint
 * tokens no matter what hardware it brings. So suspicion moves the time floor
 * first and difficulty barely at all.
 *
 * What this deliberately is not
 * -----------------------------
 * This is not Workstream F 10.1 (cross-session correlation). It stores strong-
 * verdict timestamps per source, nothing else: no behavioral vectors, no
 * per-fingerprint history, no traces that survive the window. It is the same
 * shape and the same privacy class as the rate limiter sitting next to it, and
 * it should stay that way — 10.1 has a privacy load this does not, and the two
 * should not be conflated because they happen to both be "server-side memory".
 */

// The verdict score at or above which a verification counts as evidence.
// Deliberately high: a marginal verdict is exactly the case where the scoring
// might be wrong about a real person, and making the next person from that
// address wait is not worth the guess.
const STRONG_SCORE = 0.8;

// How long a strong verdict keeps counting. Short enough that a shared egress
// address recovers on its own within a coffee break.
const WINDOW_MS = 15 * 60 * 1000;

// Only the count matters and every tier saturates well below this.
const MAX_HITS = 16;

// Bounds the table. Sources with no strong verdicts never get an entry at all,
// so this only has to cover addresses actively failing verification.
const MAX_SOURCES = 50000;

/**
 * Records recent strong verdicts per source.
 *
 * Entries are created only when a source produces a strong verdict, so the
 * common case — a legitimate visitor — allocates nothing and looks up nothing
 * but a miss.
 */
class SuspicionLedger {
  constructor() {
    this.hits = new Map();
  }

  static _key(siteKey, ip) {
    return `${siteKey}|${ip}`;
  }

  /**
   * Note a verdict. Scores below the strong threshold are ignored entirely
   * rather than recorded and weighted, so a source that merely looks unusual
   * never accumulates anything.
   */
  record(siteKey, ip, score) {
    if (!ip || typeof score !== 'number' || score < STRONG_SCORE) return;

    const key = SuspicionLedger._key(siteKey, ip);
    const now = Date.now();
    const cutoff = now - WINDOW_MS;

    const kept = (this.hits.get(key) || []).filter((t) => t > cutoff);
    kept.push(now);

    // Map preserves insertion order, so re-inserting makes this the most
    // recently touched key and the eviction below drops the stalest source.
    this.hits.delete(key);
    this.hits.set(key, kept.length > MAX_HITS ? kept.slice(-MAX_HITS) : kept);

    if (this.hits.size > MAX_SOURCES) {
      this.hits.delete(this.hits.keys().next().value);
    }
  }

  /**
   * How many strong verdicts this source produced inside the window. Counted
   * from the timestamps rather than from the entry's existence, so an old hit
   * actually decays while newer ones keep the entry alive.
   */
  count(siteKey, ip) {
    if (!ip) return 0;
    const hits = this.hits.get(SuspicionLedger._key(siteKey, ip));
    if (!hits) return 0;

    const cutoff = Date.now() - WINDOW_MS;
    const n = hits.filter((t) => t > cutoff).length;
    if (n === 0) this.hits.delete(SuspicionLedger._key(siteKey, ip));
    return n;
  }
}

// Baseline cost. A clean visitor pays exactly this, which is what the server
// has always charged everyone.
const BASE_DIFFICULTY = 4;
const BASE_MIN_AGE_MS = 1500;

// Caps the compute knob at 5, below the 6 this server used to reach. Difficulty
// 6 buys about a millisecond of attacker time and spends about sixteen seconds
// of a budget phone's; the escalation belongs in minAgeMs where an attacker
// cannot buy their way out of it.
const MAX_DIFFICULTY = 5;

// Caps the time knob at 15s. At the 1.5s baseline one address can mint roughly
// 40 tokens a minute; at 15s, four. Pushing further buys little and is felt by
// anyone sharing a poisoned egress address.
const MAX_MIN_AGE_MS = 15000;

/**
 * Maps accumulated suspicion onto a cost.
 *
 * Note what does NOT raise difficulty here: being on a datacenter address. That
 * used to jump straight to difficulty 5, which charges a real person on a
 * corporate VPN or iCloud Private Relay several seconds of blocked hashing on a
 * slow phone for the offence of having a shared IP. It now moves the time floor
 * instead, which a datacenter-hosted scraper feels as reduced throughput and a
 * person filling in a form does not feel at all.
 *
 * @returns {{difficulty: number, minAgeMs: number}}
 */
function computeChallengeCost(strongHits, isDatacenter, requestCount, rateExceeded) {
  let difficulty = BASE_DIFFICULTY;
  let minAgeMs = BASE_MIN_AGE_MS;

  if (strongHits >= 6) {
    difficulty = 5;
    minAgeMs = 15000;
  } else if (strongHits >= 3) {
    difficulty = 5;
    minAgeMs = 8000;
  } else if (strongHits >= 1) {
    minAgeMs = 4000;
  }

  // Floors from signals that are suggestive rather than damning. They raise the
  // time floor and never the difficulty.
  const raiseTo = (ms) => {
    if (minAgeMs < ms) minAgeMs = ms;
  };
  if (isDatacenter) raiseTo(3000);
  if (requestCount > 10) raiseTo(6000);
  if (rateExceeded) raiseTo(10000);

  return {
    difficulty: Math.min(difficulty, MAX_DIFFICULTY),
    minAgeMs: Math.min(minAgeMs, MAX_MIN_AGE_MS)
  };
}

module.exports = {
  SuspicionLedger,
  computeChallengeCost,
  STRONG_SCORE,
  WINDOW_MS,
  BASE_DIFFICULTY,
  BASE_MIN_AGE_MS,
  MAX_DIFFICULTY,
  MAX_MIN_AGE_MS
};
