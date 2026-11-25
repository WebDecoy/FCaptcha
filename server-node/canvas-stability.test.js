'use strict';

const assert = require('node:assert/strict');
const fixtures = require('../test/fixtures/canvas-stability.json');
const { detectCanvasStability, calculateCategoryScores, calculateFinalScore } = require('./engine');

for (const fixture of fixtures.cases) {
  const before = JSON.stringify(fixture);
  const detections = detectCanvasStability(fixture.signals);
  assert.deepEqual(detections, fixture.expected ? [fixture.expected] : [], fixture.name);
  assert.equal(JSON.stringify(fixture), before, `${fixture.name}: detector mutated fixture`);
}

const unstable = detectCanvasStability(fixtures.cases[0].signals);
const categoryScores = calculateCategoryScores(unstable);
const score = calculateFinalScore(categoryScores);
assert.ok(Math.abs(score - 0.0112) < 1e-9, `canvas instability alone scored ${score}`);
assert.equal(unstable[0].dispositive, undefined, 'privacy-ambiguous evidence must not be dispositive');

console.log(`  ok  ${fixtures.cases.length} shared canvas-stability fixtures`);
