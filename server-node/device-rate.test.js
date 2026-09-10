'use strict';

// The per-device verification rate gate: a precondition on token issuance, not
// weighted evidence. Mirrors server-go/device_rate_test.go.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createScoringEngine } = require('./index');
const { widgetInstance, DEVICE_VERIFICATIONS_PER_MINUTE } = require('./engine');

const signals = (instance) => ({
  behavioral: { totalPoints: 60, trajectoryLength: 400, approachPoints: 12,
    approachDirectness: 0.4, microTremorScore: 0.5, velocityVariance: 0.5 },
  environmental: { automationFlags: {} },
  ...(instance ? { meta: { sessionId: instance } } : {}),
});
const headers = { accept: 'text/html', 'accept-language': 'en-US' };

test('the eleventh verification from one page instance is withheld as rate_limited', () => {
  const engine = createScoringEngine({ secret: 'test-secret' });
  for (let i = 0; i < DEVICE_VERIFICATIONS_PER_MINUTE; i++) {
    const r = engine.verify(signals('page-a'), '203.0.113.77', 'site', 'ua', headers);
    assert.notEqual(r.reason, 'rate_limited', `verification ${i + 1} was rate limited early`);
  }
  const r = engine.verify(signals('page-a'), '203.0.113.77', 'site', 'ua', headers);
  assert.equal(r.success, false);
  assert.equal(r.reason, 'rate_limited');
  assert.ok(r.detections.some((d) => /for this device/.test(d.reason)));

  // Another page instance on the same address and device has its own budget.
  const other = engine.verify(signals('page-b'), '203.0.113.77', 'site', 'ua', headers);
  assert.notEqual(other.reason, 'rate_limited');
});

test('no widget instance means no device gate', () => {
  const engine = createScoringEngine({ secret: 'test-secret' });
  for (let i = 0; i <= DEVICE_VERIFICATIONS_PER_MINUTE + 2; i++) {
    const r = engine.verify(signals(''), '203.0.113.78', 'site', 'ua', headers);
    assert.notEqual(r.reason, 'rate_limited');
  }
});

test('the instance id is bounded before it becomes a key', () => {
  assert.equal(widgetInstance({ meta: { widgetId: 'x'.repeat(500) } }).length, 64);
  assert.equal(widgetInstance({}), '');
  assert.equal(widgetInstance({ meta: { sessionId: 42 } }), '');
});
