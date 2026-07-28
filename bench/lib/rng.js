'use strict';

/**
 * Deterministic randomness.
 *
 * A benchmark that produces different numbers on every run cannot gate CI, and
 * a benchmark you cannot reproduce cannot be argued with. Every varied value in
 * this harness comes from a seeded generator, so `--seed 1` today and `--seed 1`
 * next year draw the identical corpus.
 */

/** mulberry32 — small, fast, good enough for fixture jitter. */
function makeRng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  return {
    next,

    /** Uniform in [min, max). */
    range(min, max) {
      return min + next() * (max - min);
    },

    /** Integer in [min, max]. */
    int(min, max) {
      return Math.floor(min + next() * (max - min + 1));
    },

    /**
     * Normal via Box-Muller, clamped to ±3σ.
     *
     * Human timing and movement distributions are roughly normal in the middle
     * and long-tailed at the edges. Clamping trades away the tail deliberately:
     * an unclamped draw occasionally emits a value so extreme it would be
     * flagged for being extreme, and a fixture that fails because the generator
     * rolled a 6σ outlier teaches nothing.
     */
    gaussian(mean, stddev) {
      const u = Math.max(next(), Number.EPSILON);
      const v = next();
      const z = Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
      return mean + stddev * Math.max(-3, Math.min(3, z));
    },

    /** Multiplies by 1 ± pct, for jittering a captured value. */
    jitter(value, pct) {
      if (typeof value !== 'number' || !Number.isFinite(value)) return value;
      return value * (1 + this.range(-pct, pct));
    },

    pick(arr) {
      return arr[Math.floor(next() * arr.length)];
    },

    bool(pTrue = 0.5) {
      return next() < pTrue;
    },
  };
}

module.exports = { makeRng };
