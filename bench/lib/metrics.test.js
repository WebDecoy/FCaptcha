'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { computeMetrics, evaluateGate } = require('./metrics');

function result(id, group, scenario, score) {
  return {
    sample: {
      id,
      label: 'agent',
      group,
      scenario,
      provenance: 'captured',
      captureMethod: 'automated-browser',
      labelEvidence: 'simulated-agent',
    },
    score,
    detections: [],
  };
}

test('agent scenarios remain visible inside a shared class', () => {
  const metrics = computeMetrics([
    result('agent/stealth-wave/0000', 'stealth-cdp-agent', 'stealth-wave', 0.2),
    result('agent/stealth-humanized/0000', 'stealth-cdp-agent', 'stealth-humanized', 0.1),
  ]);

  assert.equal(metrics.agentCorpus.byClass.length, 1);
  assert.deepEqual(
    metrics.agentCorpus.byScenario.map((row) => row.group).sort(),
    ['stealth-humanized', 'stealth-wave']
  );
});

test('fixed-corpus agent regressions fail while known gaps remain warnings', () => {
  const metrics = computeMetrics([
    result('agent/local/0000', 'local-cdp-agent', 'local', 0.2),
    result('agent/stealth/0000', 'stealth-cdp-agent', 'stealth', 0.2),
  ]);
  const gate = evaluateGate(metrics, [], { 'local-cdp-agent': 0.9 });

  assert.equal(gate.passed, false);
  assert.match(gate.failures[0], /local-cdp-agent.*regression floor/);
  assert.ok(gate.warnings.some((warning) => warning.includes('stealth-cdp-agent')));
});

test('a regression-gated class cannot silently disappear from the corpus', () => {
  const metrics = computeMetrics([]);
  const gate = evaluateGate(metrics, [], { 'local-cdp-agent': 0.9 });

  assert.equal(gate.passed, false);
  assert.match(gate.failures[0], /local-cdp-agent.*missing/);
});

test('self-reported humans are measured but cannot create false-positive claims or gates', () => {
  const captured = {
    sample: {
      id: 'human/manual/0000',
      label: 'human',
      group: 'manual',
      provenance: 'captured',
      captureMethod: 'manual-browser',
      labelEvidence: 'verified-human',
    },
    score: 0.1,
    detections: [],
  };
  const selfReported = {
    sample: {
      id: 'human/hosted/0000',
      label: 'human',
      group: 'self-reported-chrome-macos-trackpad',
      provenance: 'self-reported',
      captureMethod: 'production-export',
      labelEvidence: 'self-reported-human',
    },
    score: 0.9,
    detections: [{ reason: 'Automation-like movement', category: 'behavioral' }],
  };
  const metrics = computeMetrics([captured, selfReported]);
  const gate = evaluateGate(metrics);

  assert.equal(metrics.humanPanel.all.total, 2);
  assert.equal(metrics.humanPanel.evidential.total, 1);
  assert.equal(metrics.humanPanel.excludedByEvidence[0].group, 'self-reported-human');
  assert.equal(metrics.perSignal.length, 0);
  assert.equal(metrics.humanPanel.exploratorySignals[0].signal, 'Automation-like movement');
  assert.equal(metrics.humanPanel.exploratorySignals[0].hits, 1);
  assert.equal(gate.passed, true);
  assert.ok(metrics.humanPanel.byPersona.some((row) => row.group === selfReported.sample.group));
});

test('experimental observations use base samples and stay outside every gate', () => {
  const observation = (status) => ({ observations: { 'animation-consistency-v1': { status } } });
  const human = {
    sample: { id: 'human/manual/0000', label: 'human', group: 'manual', provenance: 'captured', captureMethod: 'manual-browser', labelEvidence: 'verified-human' },
    score: 0.1, detections: [], experimental: observation('clear'),
  };
  const derived = {
    sample: { id: 'human/manual/derived-0000', label: 'human', group: 'manual', provenance: 'derived', source: 'human/manual/0000', captureMethod: 'manual-browser', labelEvidence: 'verified-human' },
    score: 0.1, detections: [], experimental: observation('detected'),
  };
  const research = {
    sample: { id: 'human/research/0000', label: 'human', group: 'research', provenance: 'self-reported', captureMethod: 'production-export', labelEvidence: 'self-reported-human' },
    score: 0.1, detections: [], experimental: observation('detected'),
  };
  const agent = {
    sample: { id: 'agent/stealth/0000', label: 'agent', group: 'stealth-cdp-agent', provenance: 'captured', captureMethod: 'external-cdp', labelEvidence: 'observed-agent' },
    score: 0.1, detections: [], experimental: observation('detected'),
  };
  const metrics = computeMetrics([human, derived, research, agent]);
  const policy = metrics.experimental.policies[0];

  assert.equal(policy.policy, 'animation-consistency-v1');
  assert.deepEqual(policy.humans, { total: 1, detected: 0, clear: 1, unknown: 0, known: 1, rate: 0 });
  assert.equal(policy.exploratoryHumans.detected, 1);
  assert.equal(policy.agents.detected, 1);
  assert.equal(policy.byGroup.find((row) => row.group === 'manual').total, 1, 'derived rows are excluded');
  assert.equal(evaluateGate(metrics).passed, true, 'experimental observations never gate');
});

test('simulated human personas remain regression fixtures but cannot support an FP claim', () => {
  const simulated = {
    sample: {
      id: 'human/screen-reader/0000', label: 'human', group: 'screen-reader',
      provenance: 'captured', captureMethod: 'automated-browser', labelEvidence: 'simulated-human',
    },
    score: 0.9,
    detections: [{ reason: 'Mechanical navigation', category: 'behavioral' }],
  };
  const metrics = computeMetrics([simulated]);

  assert.equal(metrics.humanPanel.evidential.total, 0);
  assert.equal(metrics.humanPanel.excludedByEvidence[0].group, 'simulated-human');
  assert.equal(metrics.humanPanel.exploratorySignals[0].signal, 'Mechanical navigation');
  assert.equal(metrics.perSignal.length, 0);
  assert.equal(evaluateGate(metrics).passed, true);
});

test('derived variants count once per capture family and never change the evidence denominator', () => {
  const base = {
    sample: {
      id: 'human/manual/0000', label: 'human', group: 'manual', provenance: 'captured',
      captureMethod: 'manual-browser', labelEvidence: 'verified-human',
    },
    score: 0.1,
    detections: [],
  };
  const variant = (index) => ({
    sample: {
      id: `human/manual/derived-${index}`, label: 'human', group: 'manual', provenance: 'derived',
      source: base.sample.id, captureMethod: 'manual-browser', labelEvidence: 'verified-human',
    },
    score: 0.6,
    detections: [{ reason: 'Boundary-sensitive signal (12ms)', category: 'behavioral' }],
  });

  const one = computeMetrics([base, variant(0)]);
  const many = computeMetrics([base, ...Array.from({ length: 8 }, (_, i) => variant(i))]);
  for (const metrics of [one, many]) {
    assert.equal(metrics.humanPanel.evidential.total, 1);
    assert.deepEqual(metrics.humanPanel.neighborhood, { total: 1, hits: 1, rate: 1 });
    assert.equal(metrics.perSignal[0].humanHits, 0);
    assert.equal(metrics.perSignal[0].familyHits, 1);
    assert.equal(metrics.perSignal[0].familyTotal, 1);
    assert.equal(evaluateGate(metrics).passed, false);
  }
});

test('community repeats count as one independent capture family', () => {
  const familyId = 'a'.repeat(64);
  const row = (id, score, detections) => ({
    sample: {
      id,
      label: 'human',
      group: 'community-trackpad',
      provenance: 'captured',
      captureMethod: 'manual-browser',
      labelEvidence: 'verified-human',
      capture: { community: { familyId } },
    },
    score,
    detections,
  });
  const metrics = computeMetrics([
    row('human/community/0000', 0.1, []),
    row('human/community/0001', 0.7, [
      { reason: 'Repeated-family signal', category: 'behavioral' },
    ]),
  ]);

  assert.equal(metrics.counts.humansEvidential, 2);
  assert.equal(metrics.counts.humanCaptureFamilies, 1);
  assert.deepEqual(metrics.humanPanel.evidential, {
    total: 1,
    hits: 1,
    rate: 1,
    captures: 2,
    captureHits: 1,
  });
  assert.equal(metrics.perSignal[0].humanHits, 1);
  assert.equal(metrics.perSignal[0].humanTotal, 2);
  assert.equal(metrics.perSignal[0].familyHits, 1);
  assert.equal(metrics.perSignal[0].familyTotal, 1);
});
