'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { compareServerResults, verdict } = require('./server-parity');

function row(id, score = 0.4) {
  return {
    sample: { id },
    score,
    recommendation: 'allow',
    detections: [
      { category: 'behavioral', score: 0.30000000001, confidence: 0.8, reason: 'one' },
      { category: 'environmental', score: 0.4, confidence: 0.7, reason: 'two' },
    ],
    categoryScores: { environmental: 0.4, behavioral: 0.3 },
    experimental: { observations: { v1: { status: 'clear', detections: [] } } },
  };
}

test('parity ignores object and detection order plus insignificant float noise', () => {
  const left = row('sample');
  const right = row('sample', 0.400000000001);
  right.detections.reverse();
  right.categoryScores = { behavioral: 0.3, environmental: 0.4 };

  const result = compareServerResults([
    { name: 'node', results: [left] },
    { name: 'go', results: [right] },
  ]);
  assert.deepEqual(result.mismatches, []);
  assert.deepEqual(result.decisionMismatches, []);
  assert.deepEqual(verdict(left), verdict(right));
});

test('parity normalizes dynamic reason values and server-specific explanation suffixes', () => {
  const left = row('sample');
  const right = row('sample');
  left.detections[0].reason = 'Challenge submitted before the required delay for this source (1604ms of 10000ms)';
  right.detections[0].reason = 'Challenge submitted before the required delay for this source (1612ms of 6000ms)';
  left.detections[1].reason = 'Viewport equals window size';
  right.detections[1].reason = 'Viewport equals window size (no browser chrome)';
  assert.deepEqual(verdict(left), verdict(right));
});

test('parity reports verdict and missing-sample drift as decision failures', () => {
  const changed = row('changed', 0.5);
  changed.recommendation = 'challenge';
  const result = compareServerResults([
    { name: 'node', results: [row('changed'), row('missing')] },
    { name: 'python', results: [changed] },
  ]);
  assert.deepEqual(result.mismatches.map((item) => item.sample), ['changed', 'missing']);
  assert.deepEqual(result.decisionMismatches.map((item) => item.sample), ['changed', 'missing']);
});

test('score drift remains visible in detail without failing outcome parity', () => {
  const result = compareServerResults([
    { name: 'node', results: [row('sample', 0.4)] },
    { name: 'python', results: [row('sample', 0.5)] },
  ]);
  assert.equal(result.detailMismatches.length, 1);
  assert.deepEqual(result.decisionMismatches, []);
});

test('detail drift is visible without inventing a decision mismatch', () => {
  const left = row('sample');
  const right = row('sample');
  right.detections.push({ category: 'behavioral', score: 0.4, confidence: 0.5, reason: 'extra' });
  const result = compareServerResults([
    { name: 'node', results: [left] },
    { name: 'go', results: [right] },
  ]);
  assert.equal(result.detailMismatches.length, 1);
  assert.deepEqual(result.decisionMismatches, []);
});

test('parity requires independent server result sets', () => {
  assert.throws(() => compareServerResults([{ name: 'node', results: [] }]), /at least two/);
});
