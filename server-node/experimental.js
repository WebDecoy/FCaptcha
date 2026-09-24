'use strict';

const { calculateCategoryScores, BEHAVIOURAL_CATEGORIES, CORROBORATION_AGREE_AT,
  CORROBORATION_FLOOR } = require('./engine');

// Change this ID whenever the policy's evidence, thresholds, or scoring semantics
// change. An old selector must never silently opt an operator into a new policy.
const EXPERIMENTAL_POLICY = 'stealth-corroboration-v1';
const ANIMATION_POLICY = 'animation-consistency-v1';

function animationObservation(signals) {
  const probe = signals.environmental?.animationConsistency;
  const realm = (value) => {
    if (value?.status !== 'ok' || !Array.isArray(value.specified) || value.specified.length !== 3 ||
        !value.specified.every((n) => n === 1000) || !Array.isArray(value.durations) || value.durations.length !== 3 ||
        !value.durations.every((row) => Array.isArray(row) && row.length === 4 &&
          row.every((n) => typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= 1e9))) return null;
    return value.durations.every((row, i) => row.every((n) => n === (i === 2 ? 1000 : 0)));
  };
  const main = probe?.version === 1 ? realm(probe.main) : null;
  const frame = probe?.version === 1 ? realm(probe.iframe) : null;
  const status = main === null || frame === null ? 'unknown' : main && frame ? 'detected' : 'clear';
  // Always observe: existing policy selectors must never enable new evidence.
  return { mode: 'observe', status, detections: status === 'detected' ? [{
    id: 'animation-timing-inconsistency',
    reason: 'Browser API timing inconsistency; experimental observation, not proof of automation',
  }] : [] };
}

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
    observations: { [ANIMATION_POLICY]: animationObservation(signals) },
  };
}

module.exports = { evaluateExperimental, EXPERIMENTAL_POLICY };
