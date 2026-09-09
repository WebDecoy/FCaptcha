'use strict';

// The behavioural corroboration floor. See engine.js for the measurement that
// chose its constants; these pin the behaviour and the invariants that keep it
// honest, and mirror server-go/corroboration_test.go.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  applyCorroborationFloor, calculateCategoryScores, detectCDP,
  CORROBORATION_AGREE_AT, CORROBORATION_MIN_AGREE, CORROBORATION_FLOOR,
  DISPOSITIVE_FLOOR, BEHAVIOURAL_CATEGORIES,
} = require('./engine');

// One detection per category at exactly the given strength, so each category's
// noisy-OR score is the number written here.
const views = (cats) => Object.entries(cats).map(([category, score]) => ({ category, score, confidence: 1 }));

test('two agreeing behavioural categories floor the score', () => {
  const dets = views({ vision_ai: 0.652, behavioral: 0.597, automation: 0.36 });
  assert.equal(applyCorroborationFloor(0.234, dets), CORROBORATION_FLOOR);
});

test('one category alone never floors, however strong', () => {
  for (const c of BEHAVIOURAL_CATEGORIES) {
    assert.equal(applyCorroborationFloor(0.2, views({ [c]: 1 })), 0.2, `${c} alone must not floor`);
  }
});

test('non-behavioural categories do not corroborate', () => {
  assert.equal(applyCorroborationFloor(0.3, views({ headless: 1, fingerprint: 1, datacenter: 1, bot: 1 })), 0.3);
});

test('the floor never lowers a score', () => {
  assert.equal(applyCorroborationFloor(0.95, views({ vision_ai: 0.9, behavioral: 0.9 })), 0.95);
});

test('agreement starts exactly at the threshold', () => {
  const under = CORROBORATION_AGREE_AT - 0.01;
  assert.equal(applyCorroborationFloor(0.2, views({ vision_ai: under, behavioral: under })), 0.2);
  const at = CORROBORATION_AGREE_AT;
  assert.equal(applyCorroborationFloor(0.2, views({ vision_ai: at, behavioral: at })), CORROBORATION_FLOOR);
});

test('the floor blocks, sits below the dispositive floor, and needs exactly two views', () => {
  assert.ok(CORROBORATION_FLOOR >= 0.5);
  assert.ok(CORROBORATION_FLOOR < DISPOSITIVE_FLOOR);
  assert.equal(CORROBORATION_MIN_AGREE, 2);
});

test('a non-corroborating detection cannot be the second view', () => {
  const consoleAttached = { category: 'cdp', score: 0.6, confidence: 1, nonCorroborating: true };
  const movement = { category: 'behavioral', score: CORROBORATION_AGREE_AT, confidence: 1 };
  assert.equal(applyCorroborationFloor(0.2, [consoleAttached, movement]), 0.2);
  // Same evidence from an independent view does floor: provenance, not strength.
  assert.equal(applyCorroborationFloor(0.2, [{ ...consoleAttached, nonCorroborating: false }, movement]), CORROBORATION_FLOOR);
});

test('a non-corroborating detection still scores its category', () => {
  const scores = calculateCategoryScores([{ category: 'cdp', score: 0.6, confidence: 0.5, nonCorroborating: true }]);
  assert.ok(Math.abs(scores.cdp - 0.3) < 1e-9, `cdp scored ${scores.cdp}`);
});

test('the console-attach probe carries the mark, and only it', () => {
  const dets = detectCDP({ behavioral: { touchEvents: 0 }, environmental: { cdpRuntime: { consoleAttached: true } } });
  const probe = dets.find((d) => /console consumer attached/.test(d.reason));
  assert.ok(probe, 'expected the console-attach detection to fire');
  assert.equal(probe.nonCorroborating, true);
  assert.equal(dets.filter((d) => d.nonCorroborating).length, 1);
});

// Live measurements from the webdecoy.com demo, 2026-09-09, v1.35.0. An
// extension-driven click in a real Chrome: every environmental category clean,
// vision_ai 0.40, behavioral 0.44, cdp 0.30 from the console probe alone,
// weighted sum 0.189, allowed. vision_ai lands at 0.3999999999999999, so the
// epsilon is load-bearing here.
test('the extension-driven click that passed at 0.5 is floored at 0.4', () => {
  const dets = [
    { category: 'vision_ai', score: 0.5, confidence: 0.5 },   // path unnaturally direct
    { category: 'vision_ai', score: 0.4, confidence: 0.5 },   // click precision
    { category: 'behavioral', score: 0.6, confidence: 0.7 },  // insufficient movement
    { category: 'behavioral', score: 0.2, confidence: 0.2 },  // no scroll or keyboard
    { category: 'cdp', score: 0.6, confidence: 0.5, nonCorroborating: true },
    { category: 'fingerprint', score: 0.4, confidence: 0.4 },
  ];
  assert.ok(applyCorroborationFloor(0.189, dets) >= 0.5);
});

test('a developer with DevTools open and a quick click is not floored', () => {
  const dets = [
    { category: 'behavioral', score: 0.5, confidence: 0.5 },  // first interaction too soon
    { category: 'behavioral', score: 0.4, confidence: 0.4 },  // no overshoot corrections
    { category: 'cdp', score: 0.6, confidence: 0.5, nonCorroborating: true },
    { category: 'fingerprint', score: 0.4, confidence: 0.4 },
  ];
  assert.equal(applyCorroborationFloor(0.115, dets), 0.115);
});
