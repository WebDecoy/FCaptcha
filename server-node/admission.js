'use strict';

// Fixed windows bound both request work and limiter memory. A full table denies
// new sources; it never evicts a source that still has a live quota.
class AdmissionLimiter {
  constructor({ maxEntries = 100000, now = Date.now } = {}) {
    this.entries = new Map();
    this.maxEntries = maxEntries;
    this.now = now;
    this.nextCleanup = 0;
  }

  allow(key, maximum, seconds = 60) {
    const now = this.now();
    if (now >= this.nextCleanup) {
      for (const [k, entry] of this.entries) if (entry.expires <= now) this.entries.delete(k);
      this.nextCleanup = now + 60000;
    }
    let entry = this.entries.get(key);
    if (entry && entry.expires <= now) { this.entries.delete(key); entry = null; }
    if (!entry) {
      if (this.entries.size >= this.maxEntries) return false;
      entry = { count: 0, expires: now + seconds * 1000 };
      this.entries.set(key, entry);
    }
    if (entry.count >= maximum) return false;
    entry.count++;
    return true;
  }
}

// Insertion order is expiry order (all challenges have the same lifetime).
// Cleanup only visits expired entries, rather than scanning the live map.
class ChallengeMap extends Map {
  constructor(maxEntries = 100000) { super(); this.maxEntries = maxEntries; }
  pruneExpired(now = Date.now()) {
    for (const [id, challenge] of this) {
      if (challenge.expiresAt > now) break;
      this.delete(id);
    }
  }
  set(id, challenge) {
    this.pruneExpired();
    if (!this.has(id) && this.size >= this.maxEntries) throw new Error('challenge_store_full');
    return super.set(id, challenge);
  }
  prune() { this.pruneExpired(); }
}

module.exports = { AdmissionLimiter, ChallengeMap };
