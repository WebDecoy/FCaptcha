'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzePairs, buildPairs, flattenSignals } = require('./paired-analysis');

function sample(id, label, group, mode, value, extra = {}) {
  return {
    id,
    label,
    group,
    scenario: group,
    provenance: 'captured',
    capture: { mode },
    signals: {
      behavioral: {
        value,
        bool: extra.bool ?? false,
        trace: extra.trace || [value, value + 1],
      },
      meta: { timestamp: 123, challengeNonce: 'secret' },
    },
  };
}

test('flattens scalars and summarizes arrays without retaining volatile identifiers', () => {
  const flat = flattenSignals({
    metric: 4,
    enabled: true,
    trace: [1, 2, 3],
    meta: { timestamp: 123, challengeNonce: 'secret' },
  });
  assert.equal(flat.metric, 4);
  assert.equal(flat.enabled, true);
  assert.equal(flat['trace[]#count'], 3);
  assert.equal(flat['trace[]#mean'], 2);
  assert.equal(flat['meta.timestamp'], undefined);
  assert.equal(flat['meta.challengeNonce'], undefined);
});

test('excludes operational metadata and does not union unique categorical identifiers', () => {
  const samples = [
    sample('agent/a/0000', 'agent', 'browser-internal', 'widget', 1, { bool: true }),
    sample('agent/a/0001', 'agent', 'browser-internal', 'widget', 1, { bool: true }),
    sample('human/a/0000', 'human', 'browser-internal-control', 'widget', 1),
    sample('human/a/0001', 'human', 'browser-internal-control', 'widget', 1),
  ];
  samples[0].signals.identifier = 'agent-0';
  samples[1].signals.identifier = 'agent-1';
  samples[2].signals.identifier = 'human-0';
  samples[3].signals.identifier = 'human-1';
  samples.forEach((item, index) => { item.signals.meta.siteKey = `site-${index}`; });

  const result = analyzePairs(samples);
  assert.equal(result.features.some((item) => item.path.startsWith('meta.')), false);
  assert.equal(result.features.find((item) => item.path === 'identifier').caught, 1);
  assert.equal(result.features.find((item) => item.path === 'identifier').promotionCandidate, false);
  assert.equal(result.features.find((item) => item.path === 'behavioral.bool').promotionCandidate, true);
});

test('pairs captures by mode and numeric suffix and rejects missing controls', () => {
  const samples = [
    sample('agent/a/0000', 'agent', 'browser-internal', 'widget', 10),
    sample('human/a/0000', 'human', 'browser-internal-control', 'widget', 1),
  ];
  assert.equal(buildPairs(samples)[0].key, 'widget:0');
  assert.throws(
    () => buildPairs(samples.slice(0, 1)),
    /unpaired capture/
  );
});

test('promotes a complete zero-FP separator that survives leave-one-pair-out', () => {
  const samples = [
    sample('agent/a/0000', 'agent', 'browser-internal', 'widget', 10),
    sample('agent/a/0001', 'agent', 'browser-internal', 'widget', 11),
    sample('human/a/0000', 'human', 'browser-internal-control', 'widget', 1),
    sample('human/a/0001', 'human', 'browser-internal-control', 'widget', 2),
    sample('human/other/0000', 'human', 'trackpad', 'widget', 3),
  ];
  const result = analyzePairs(samples);
  const feature = result.features.find((item) => item.path === 'behavioral.value');
  assert.equal(feature.caught, 2);
  assert.equal(feature.looCaught, 2);
  assert.equal(feature.looFalsePositives, 0);
  assert.equal(feature.promotionCandidate, true);
});

test('rejects overlap and reports partial candidates without promoting them', () => {
  const samples = [
    sample('agent/a/0000', 'agent', 'browser-internal', 'widget', 4),
    sample('agent/a/0001', 'agent', 'browser-internal', 'widget', 9),
    sample('human/a/0000', 'human', 'browser-internal-control', 'widget', 5),
    sample('human/a/0001', 'human', 'browser-internal-control', 'widget', 6),
    sample('human/other/0000', 'human', 'trackpad', 'widget', 7),
  ];
  const result = analyzePairs(samples);
  const feature = result.features.find((item) => item.path === 'behavioral.value');
  assert.equal(feature.caught, 1);
  assert.equal(feature.promotionCandidate, false);
  assert.equal(result.promotionCandidates.length, 0);
});

test('never promotes a feature that is missing from any pair', () => {
  const samples = [
    sample('agent/a/0000', 'agent', 'browser-internal', 'widget', 10),
    sample('agent/a/0001', 'agent', 'browser-internal', 'widget', 11),
    sample('human/a/0000', 'human', 'browser-internal-control', 'widget', 1),
    sample('human/a/0001', 'human', 'browser-internal-control', 'widget', 2),
  ];
  samples[1].signals.behavioral.partial = 10;
  samples[3].signals.behavioral.partial = 1;

  const result = analyzePairs(samples, { minCoverage: 0.5 });
  const feature = result.features.find((item) => item.path === 'behavioral.partial');
  assert.equal(feature.coverage, 0.5);
  assert.equal(feature.promotionCandidate, false);
});
