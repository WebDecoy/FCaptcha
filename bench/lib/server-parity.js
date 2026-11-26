'use strict';

const FLOAT_DIGITS = 8;

function canonical(value, key = '') {
  if (typeof value === 'number') return Number(value.toFixed(FLOAT_DIGITS));
  if (Array.isArray(value)) {
    const rows = value.map((item) => canonical(item));
    if (key === 'detections') {
      rows.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    }
    return rows;
  }
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((child) => [child, canonical(value[child], child)])
  );
}

function normalizeReason(reason) {
  return String(reason || '')
    .replace(/\s*\([^)]*\)/g, '')
    .split(':')[0]
    .replace(/\b\d+(?:\.\d+)?(?:ms|s)?\b/gi, 'N')
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeCategoryScores(scores) {
  return Object.fromEntries(Object.entries(scores || {}).filter(([, score]) => score !== 0));
}

function normalizeDetection(detection) {
  return {
    category: detection.category || null,
    score: detection.score ?? null,
    confidence: detection.confidence ?? null,
    reason: normalizeReason(detection.reason),
    ...(detection.nonCorroborating ? { nonCorroborating: true } : {}),
  };
}

function normalizeExperimental(experimental) {
  if (!experimental) return null;
  const observations = {};
  for (const [name, observation] of Object.entries(experimental.observations || {})) {
    observations[name] = {
      mode: observation.mode,
      status: observation.status,
      detections: (observation.detections || []).map((detection) => ({ id: detection.id })),
    };
  }
  return {
    policy: experimental.policy,
    mode: experimental.mode,
    score: experimental.score,
    wouldBlock: experimental.wouldBlock,
    corroboratingCategories: [...(experimental.corroboratingCategories || [])].sort(),
    detections: (experimental.detections || []).map(normalizeDetection),
    observations,
  };
}

function verdict(row) {
  if (row.error) return { error: row.error };
  return canonical({
    score: row.score,
    recommendation: row.recommendation,
    detections: (row.detections || []).map(normalizeDetection),
    categoryScores: normalizeCategoryScores(row.categoryScores),
    experimental: normalizeExperimental(row.experimental),
  });
}

function decisionVerdict(row) {
  if (row.error) return { error: row.error };
  const observations = {};
  for (const [name, observation] of Object.entries(row.experimental?.observations || {})) {
    observations[name] = observation.status;
  }
  return canonical({
    recommendation: row.recommendation,
    experimental: row.experimental ? {
      policy: row.experimental.policy,
      mode: row.experimental.mode,
      wouldBlock: row.experimental.wouldBlock,
      observations,
    } : null,
  });
}

function compareServerResults(namedResults) {
  if (!Array.isArray(namedResults) || namedResults.length < 2) {
    throw new Error('at least two server result sets are required');
  }
  const [reference, ...peers] = namedResults;
  const referenceByID = new Map(reference.results.map((row) => [row.sample.id, row]));
  const mismatches = [];
  const decisionMismatches = [];

  for (const peer of peers) {
    const peerByID = new Map(peer.results.map((row) => [row.sample.id, row]));
    const ids = new Set([...referenceByID.keys(), ...peerByID.keys()]);
    for (const id of [...ids].sort()) {
      const expectedRow = referenceByID.get(id);
      const actualRow = peerByID.get(id);
      if (!expectedRow || !actualRow) {
        const mismatch = {
          sample: id,
          reference: reference.name,
          peer: peer.name,
          expected: expectedRow ? verdict(expectedRow) : '(missing)',
          actual: actualRow ? verdict(actualRow) : '(missing)',
        };
        mismatches.push(mismatch);
        decisionMismatches.push(mismatch);
        continue;
      }
      const expected = verdict(expectedRow);
      const actual = verdict(actualRow);
      if (JSON.stringify(expected) !== JSON.stringify(actual)) {
        mismatches.push({ sample: id, reference: reference.name, peer: peer.name, expected, actual });
      }
      const expectedDecision = decisionVerdict(expectedRow);
      const actualDecision = decisionVerdict(actualRow);
      if (JSON.stringify(expectedDecision) !== JSON.stringify(actualDecision)) {
        decisionMismatches.push({
          sample: id,
          reference: reference.name,
          peer: peer.name,
          expected: expectedDecision,
          actual: actualDecision,
        });
      }
    }
  }

  return {
    reference: reference.name,
    servers: namedResults.map((row) => row.name),
    decisionMismatches,
    detailMismatches: mismatches,
    // Backward-compatible alias for callers written before the two-tier gate.
    mismatches,
  };
}

module.exports = { canonical, compareServerResults, decisionVerdict, normalizeReason, verdict };
