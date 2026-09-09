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
    const now = this.now();
    if (now >= this.nextCleanup) {
      for (const [key, expiresAt] of this.entries) {
        if (expiresAt <= now) this.entries.delete(key);
      }
      this.nextCleanup = now + 60000;
    }
    if (this.entries.has(signature) || this.entries.size >= this.maxEntries) return false;
    this.entries.set(signature, now + 10 * 60 * 1000);
    return true;
  }
}

module.exports = { TokenStore };
