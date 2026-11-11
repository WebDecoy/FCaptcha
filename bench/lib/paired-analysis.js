'use strict';

const DEFAULT_EXCLUDE = /(?:^|\.)(?:meta(?:\.|$)|challengeNonce|nonce|token|siteKey|widgetId|sessionId|requestId|timestamp|timeOrigin|hash)$/i;

function finite(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function mean(values) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
}

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function stddev(values) {
  if (!values.length) return null;
  const avg = mean(values);
  return Math.sqrt(values.reduce((sum, value) => sum + (value - avg) ** 2, 0) / values.length);
}

function summarizeNumericArray(values, path, out) {
  if (!values.length || !values.every(finite)) return;
  out[`${path}[]#count`] = values.length;
  out[`${path}[]#mean`] = mean(values);
  out[`${path}[]#min`] = Math.min(...values);
  out[`${path}[]#max`] = Math.max(...values);
  out[`${path}[]#stddev`] = stddev(values);
}

/**
 * Flattens replayable signal payloads into comparable scalar observations.
 * Numeric arrays are summarized rather than compared by index: event number 12
 * in one pointer trace has no semantic relationship to event number 12 in the
 * paired trace.
 */
function flattenSignals(node, options = {}, path = '', out = {}) {
  const exclude = options.exclude || DEFAULT_EXCLUDE;
  if (path && exclude.test(path)) return out;

  if (Array.isArray(node)) {
    summarizeNumericArray(node, path, out);
    if (node.length && node.every((value) => typeof value === 'string')) {
      out[`${path}[]#set`] = JSON.stringify([...new Set(node)].sort());
    }
    return out;
  }

  if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      flattenSignals(value, options, path ? `${path}.${key}` : key, out);
    }
    return out;
  }

  if (finite(node) || typeof node === 'boolean' || typeof node === 'string') out[path] = node;
  return out;
}

function sampleIndex(sample) {
  const part = String(sample.id || '').split('/').pop();
  if (!/^\d+$/.test(part)) throw new Error(`cannot pair sample without numeric id suffix: ${sample.id}`);
  return Number(part);
}

function pairKey(sample) {
  const mode = sample.capture?.mode || sample.capture?.endpoint || 'unknown';
  return `${mode}:${sampleIndex(sample)}`;
}

function buildPairs(samples, options = {}) {
  const agentGroup = options.agentGroup || 'browser-internal';
  const controlGroup = options.controlGroup || 'browser-internal-control';
  const captured = samples.filter((sample) => sample.provenance === 'captured' && !sample.unmeasured);
  const agents = captured.filter((sample) => sample.label === 'agent' && sample.group === agentGroup);
  const controls = captured.filter((sample) => sample.label === 'human' && sample.group === controlGroup);

  const index = (items, label) => {
    const result = new Map();
    for (const item of items) {
      const key = pairKey(item);
      if (result.has(key)) throw new Error(`duplicate ${label} pair key ${key}`);
      result.set(key, item);
    }
    return result;
  };

  const agentByKey = index(agents, 'agent');
  const controlByKey = index(controls, 'control');
  const keys = [...new Set([...agentByKey.keys(), ...controlByKey.keys()])].sort();
  const missing = keys.filter((key) => !agentByKey.has(key) || !controlByKey.has(key));
  if (missing.length) throw new Error(`unpaired capture(s): ${missing.join(', ')}`);
  if (!keys.length) throw new Error(`no captured pairs for ${agentGroup} and ${controlGroup}`);

  return keys.map((key) => ({ key, agent: agentByKey.get(key), control: controlByKey.get(key) }));
}

function cliffsDelta(agentValues, humanValues) {
  let greater = 0;
  let lower = 0;
  for (const agent of agentValues) {
    for (const human of humanValues) {
      if (agent > human) greater++;
      else if (agent < human) lower++;
    }
  }
  const comparisons = agentValues.length * humanValues.length;
  return comparisons ? (greater - lower) / comparisons : 0;
}

function rangeStats(agentValues, controlValues) {
  const agentMin = Math.min(...agentValues);
  const agentMax = Math.max(...agentValues);
  const controlMin = Math.min(...controlValues);
  const controlMax = Math.max(...controlValues);
  const overlap = Math.max(0, Math.min(agentMax, controlMax) - Math.max(agentMin, controlMin));
  const union = Math.max(agentMax, controlMax) - Math.min(agentMin, controlMin);
  let separation = 0;
  if (agentMin > controlMax) separation = agentMin - controlMax;
  else if (controlMin > agentMax) separation = controlMin - agentMax;
  return {
    agent: { min: agentMin, median: median(agentValues), max: agentMax },
    control: { min: controlMin, median: median(controlValues), max: controlMax },
    overlap,
    overlapRatio: union ? overlap / union : 1,
    separation,
  };
}

function numericDirection(pairs, path) {
  let higher = 0;
  let lower = 0;
  let equal = 0;
  for (const pair of pairs) {
    const agent = pair.agentFlat[path];
    const control = pair.controlFlat[path];
    if (agent > control) higher++;
    else if (agent < control) lower++;
    else equal++;
  }
  return { higher, lower, equal, consistency: Math.max(higher, lower) / pairs.length };
}

function evaluateNumericCandidate(path, pairs, humans) {
  const agentValues = pairs.map((pair) => pair.agentFlat[path]);
  const controlValues = pairs.map((pair) => pair.controlFlat[path]);
  const humanValues = humans.map((human) => human.flat[path]).filter(finite);
  if (!humanValues.length) return null;

  const choices = [
    {
      direction: 'high',
      threshold: Math.max(...humanValues),
      detects: (value, threshold) => value > threshold,
    },
    {
      direction: 'low',
      threshold: Math.min(...humanValues),
      detects: (value, threshold) => value < threshold,
    },
  ].map((choice) => {
    const caughtKeys = pairs
      .filter((pair) => choice.detects(pair.agentFlat[path], choice.threshold))
      .map((pair) => pair.key);
    let looCaught = 0;
    let looFalsePositives = 0;
    for (const pair of pairs) {
      const training = humans
        .filter((human) => human.sample.id !== pair.control.id)
        .map((human) => human.flat[path])
        .filter(finite);
      if (!training.length) continue;
      const threshold = choice.direction === 'high' ? Math.max(...training) : Math.min(...training);
      if (choice.detects(pair.agentFlat[path], threshold)) looCaught++;
      if (choice.detects(pair.controlFlat[path], threshold)) looFalsePositives++;
    }
    return { ...choice, caughtKeys, caught: caughtKeys.length, looCaught, looFalsePositives };
  });

  choices.sort((a, b) =>
    b.caught - a.caught ||
    b.looCaught - a.looCaught ||
    a.looFalsePositives - b.looFalsePositives
  );
  const best = choices[0];
  const directions = numericDirection(pairs, path);
  const ranges = rangeStats(agentValues, controlValues);
  const modes = Object.fromEntries(
    [...new Set(pairs.map((pair) => pair.key.split(':')[0]))].map((mode) => {
      const modePairs = pairs.filter((pair) => pair.key.startsWith(`${mode}:`));
      return [mode, {
        caught: modePairs.filter((pair) => best.detects(pair.agentFlat[path], best.threshold)).length,
        total: modePairs.length,
      }];
    })
  );

  return {
    path,
    kind: 'numeric',
    direction: best.direction,
    threshold: best.threshold,
    caught: best.caught,
    caughtKeys: best.caughtKeys,
    totalAgents: pairs.length,
    humanFalsePositives: 0,
    humanObserved: humanValues.length,
    humanTotal: humans.length,
    looCaught: best.looCaught,
    looFalsePositives: best.looFalsePositives,
    pairDirections: directions,
    cliffsDelta: cliffsDelta(agentValues, controlValues),
    ranges,
    modes,
    promotionCandidate:
      best.caught === pairs.length &&
      best.looCaught === pairs.length &&
      best.looFalsePositives === 0 &&
      directions.consistency === 1,
  };
}

function evaluateCategoricalCandidate(path, pairs, humans) {
  const observedHumanValues = humans
    .map((human) => human.flat[path])
    .filter((value) => value !== undefined);
  const humanValues = new Set(observedHumanValues);
  if (!humanValues.size) return null;
  const counts = new Map();
  for (const pair of pairs) {
    const value = pair.agentFlat[path];
    if (value !== undefined && !humanValues.has(value)) counts.set(value, (counts.get(value) || 0) + 1);
  }
  const agentOnlyValues = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const bestValue = agentOnlyValues[0]?.[0];
  const caughtKeys = pairs
    .filter((pair) => pair.agentFlat[path] === bestValue)
    .map((pair) => pair.key);
  let looCaught = 0;
  let looFalsePositives = 0;
  for (const pair of pairs) {
    const trainingHumans = new Set(
      humans
        .filter((human) => human.sample.id !== pair.control.id)
        .map((human) => human.flat[path])
        .filter((value) => value !== undefined)
    );
    const trainingAgentValues = new Set(
      pairs
        .filter((candidate) => candidate.key !== pair.key)
        .map((candidate) => candidate.agentFlat[path])
        .filter((value) => value !== undefined && !trainingHumans.has(value))
    );
    if (trainingAgentValues.has(pair.agentFlat[path])) looCaught++;
    if (trainingAgentValues.has(pair.controlFlat[path])) looFalsePositives++;
  }
  return {
    path,
    kind: 'categorical',
    value: bestValue,
    values: agentOnlyValues.map(([value, count]) => ({ value, count })),
    caught: caughtKeys.length,
    caughtKeys,
    totalAgents: pairs.length,
    humanFalsePositives: 0,
    humanObserved: observedHumanValues.length,
    humanTotal: humans.length,
    looCaught,
    looFalsePositives,
    promotionCandidate:
      caughtKeys.length === pairs.length &&
      looCaught === pairs.length &&
      looFalsePositives === 0,
  };
}

function analyzePairs(samples, options = {}) {
  const minCoverage = options.minCoverage ?? 1;
  const pairs = buildPairs(samples, options).map((pair) => ({
    ...pair,
    agentFlat: flattenSignals(pair.agent.signals, options),
    controlFlat: flattenSignals(pair.control.signals, options),
  }));
  const humans = samples
    .filter((sample) => sample.label === 'human' && sample.provenance === 'captured' && !sample.unmeasured)
    .map((sample) => ({ sample, flat: flattenSignals(sample.signals, options) }));
  const allPaths = new Set(pairs.flatMap((pair) => [
    ...Object.keys(pair.agentFlat),
    ...Object.keys(pair.controlFlat),
  ]));
  const required = Math.ceil(pairs.length * minCoverage);
  const features = [];

  for (const path of allPaths) {
    const covered = pairs.filter((pair) =>
      pair.agentFlat[path] !== undefined && pair.controlFlat[path] !== undefined
    );
    if (covered.length < required) continue;
    const values = covered.flatMap((pair) => [pair.agentFlat[path], pair.controlFlat[path]]);
    const allNumeric = values.every(finite);
    const feature = allNumeric
      ? evaluateNumericCandidate(path, covered, humans)
      : evaluateCategoricalCandidate(path, covered, humans);
    if (feature) {
      const coverage = covered.length / pairs.length;
      features.push({
        ...feature,
        coverage,
        promotionCandidate: feature.promotionCandidate && coverage === 1,
      });
    }
  }

  features.sort((a, b) =>
    Number(b.promotionCandidate) - Number(a.promotionCandidate) ||
    b.caught - a.caught ||
    (b.looCaught || 0) - (a.looCaught || 0) ||
    Math.abs(b.cliffsDelta || 0) - Math.abs(a.cliffsDelta || 0) ||
    a.path.localeCompare(b.path)
  );

  return {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    agentGroup: options.agentGroup || 'browser-internal',
    controlGroup: options.controlGroup || 'browser-internal-control',
    pairCount: pairs.length,
    pairKeys: pairs.map((pair) => pair.key),
    capturedHumanCount: humans.length,
    minCoverage,
    promotionCandidates: features.filter((feature) => feature.promotionCandidate),
    features,
  };
}

module.exports = {
  DEFAULT_EXCLUDE,
  analyzePairs,
  buildPairs,
  flattenSignals,
  mean,
  median,
  pairKey,
};
