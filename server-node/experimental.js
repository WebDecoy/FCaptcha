'use strict';

const { calculateCategoryScores, BEHAVIOURAL_CATEGORIES, CORROBORATION_AGREE_AT,
  CORROBORATION_FLOOR } = require('./engine');

// Change this ID whenever the policy's evidence, thresholds, or scoring semantics
// change. An old selector must never silently opt an operator into a new policy.
const EXPERIMENTAL_POLICY = 'stealth-corroboration-v1';

// Observe by default. This intentionally measures a known-ambiguous hypothesis:
// #87's stealth session and a DevTools hardware override can look identical.
// Never merge these detections into production scoring or state updates. The
// server's explicit blocking option adds a separate token gate.
function evaluateExperimental(signals, productionScore, detections, blocking = false) {
  const worker = signals.environmental?.workerConsistency;
  const mismatch = worker?.supported === true && worker.consistent === false &&
    Array.isArray(worker.mismatches) && worker.mismatches.includes('hardwareConcurrency');
  const categoryScores = calculateCategoryScores(detections.filter((d) => !d.nonCorroborating));
  const corroboratingCategories = BEHAVIOURAL_CATEGORIES.filter(
    (c) => (categoryScores[c] || 0) >= CORROBORATION_AGREE_AT - 1e-9);
  const score = mismatch && corroboratingCategories.length > 0
    ? Math.max(productionScore, CORROBORATION_FLOOR) : productionScore;
  return {
    mode: blocking ? 'block' : 'observe',
    policy: EXPERIMENTAL_POLICY,
    score,
    // Score threshold only; this is not a hypothetical PoW/hostname/rate verdict.
    wouldBlock: score >= 0.5,
    detections: mismatch ? [{
      id: 'worker-hardware-concurrency-mismatch',
      reason: 'Page and Worker disagree on hardwareConcurrency; also possible with DevTools or privacy tools',
    }] : [],
    corroboratingCategories,
  };
}

module.exports = { evaluateExperimental, EXPERIMENTAL_POLICY };
