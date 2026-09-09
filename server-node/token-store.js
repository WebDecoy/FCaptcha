'use strict';

// Spent tokens must not be evicted while they can still verify. If capacity is
// exhausted, refuse new claims rather than reopening replay of older tokens.
class TokenStore {
  constructor({ maxEntries = 100000, now = Date.now } = {}) {
    this.entries = new Map();
    this.maxEntries = maxEntries;
    this.now = now;
    this.nextCleanup = 0;
  }

  markUsed(signature) {
    return this.claim(signature).claimed;
  }

  claim(signature) {
    const now = this.now();
    if (now >= this.nextCleanup) {
      for (const [key, expiresAt] of this.entries) {
        if (expiresAt <= now) this.entries.delete(key);
      }
      this.nextCleanup = now + 60000;
    }
    if (this.entries.has(signature)) return { claimed: false, reason: 'token_already_used' };
    if (this.entries.size >= this.maxEntries) return { claimed: false, reason: 'token_store_full' };
    this.entries.set(signature, now + 10 * 60 * 1000);
    return { claimed: true };
  }
}

module.exports = { TokenStore };
