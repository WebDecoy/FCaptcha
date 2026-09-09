'use strict';

const { BoundedMap } = require('./limits');

const WINDOW_MS = 15 * 60 * 1000;
// Detectors only distinguish >5 and >10. Saturating at 16 preserves those
// decisions without retaining every attacker-selected value.
const MAX_MEMBERS = 16;

class FingerprintStore {
  constructor({ maxEntries = 100000, ttlMs = WINDOW_MS, now = Date.now } = {}) {
    this.fingerprints = new BoundedMap(maxEntries);
    this.ipFingerprints = new BoundedMap(maxEntries);
    this.ttlMs = ttlMs;
    this.now = now;
  }

  _get(store, key) {
    const entry = store.get(key);
    if (entry && entry.expiresAt <= this.now()) {
      store.delete(key);
      return undefined;
    }
    return entry;
  }

  _add(store, key, value) {
    let entry = this._get(store, key);
    if (!entry) {
      entry = { values: new Set(), expiresAt: this.now() + this.ttlMs };
      store.set(key, entry);
    }
    if (entry.values.size < MAX_MEMBERS) entry.values.add(value);
  }

  record(fp, ip, siteKey) {
    const entry = this._get(this.ipFingerprints, ip);
    // Do not allocate more fingerprint keys once this source has saturated.
    if (entry && entry.values.size >= MAX_MEMBERS && !entry.values.has(fp)) return;
    this._add(this.ipFingerprints, ip, fp);
    this._add(this.fingerprints, `${siteKey}:${fp}`, ip);
  }

  getIpFpCount(ip) {
    return this._get(this.ipFingerprints, ip)?.values.size || 0;
  }

  getFpIpCount(fp, siteKey) {
    return this._get(this.fingerprints, `${siteKey}:${fp}`)?.values.size || 0;
  }
}

module.exports = { FingerprintStore, WINDOW_MS, MAX_MEMBERS };
