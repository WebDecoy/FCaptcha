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
