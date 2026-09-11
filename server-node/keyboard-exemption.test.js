'use strict';

// The keyboard-only accessibility exemption and the key-hold check that keeps a
// keyboard-driven agent from claiming it. Mirrors server-go/keyboard_exemption_test.go.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  keyboardOnlyUser, detectVisionAI, detectBehavioral, applyCorroborationFloor, CORROBORATION_FLOOR,
} = require('./engine');

const kb = (keyEvents, extra = {}) => ({
  behavioral: { totalPoints: 0, trajectoryLength: 0, keyEvents, touchEvents: 0, ...extra },
  environmental: { automationFlags: {} },
});
const reasons = (dets) => dets.map((d) => d.reason).join(' | ');

test('the exemption stands without hold data', () => {
  const s = kb(8);
  assert.equal(keyboardOnlyUser(s, s.behavioral), true);
});

test('the exemption stands for fingers', () => {
  const s = kb(12, { keyHoldSamples: 6, keyHoldAvg: 85 });
  assert.equal(keyboardOnlyUser(s, s.behavioral), true);
});

test('the exemption is denied for mechanical holds', () => {
  const s = kb(12, { keyHoldSamples: 6, keyHoldAvg: 4 });
  assert.equal(keyboardOnlyUser(s, s.behavioral), false);
});

test('form-field dwell times are pooled into the judgement', () => {
  const mechanical = { ...kb(9), formAnalysis: { textareaKeyboard: { message: { dwellTimes: [2, 3, 1, 2] } } } };
  assert.equal(keyboardOnlyUser(mechanical, mechanical.behavioral), false);
  const human = { ...kb(9), formAnalysis: { textareaKeyboard: { message: { dwellTimes: [60, 75, 90] } } } };
  assert.equal(keyboardOnlyUser(human, human.behavioral), true);
});

test('too few holds cannot take the exemption away', () => {
  const s = kb(4, { keyHoldSamples: 2, keyHoldAvg: 3 });
  assert.equal(keyboardOnlyUser(s, s.behavioral), true);
});

test('the exemption requires key events and no pointer', () => {
  const one = kb(1);
  assert.equal(keyboardOnlyUser(one, one.behavioral), false);
  const moved = kb(8, { totalPoints: 3 });
  assert.equal(keyboardOnlyUser(moved, moved.behavioral), false);
});

test('a keyboard-driven agent is scored as pointerless and corroborates; a keyboard person is not', () => {
  const agent = kb(14, { keyHoldSamples: 14, keyHoldAvg: 2 });
  let dets = [...detectVisionAI(agent), ...detectBehavioral(agent)];
  assert.match(reasons(dets), /Zero mouse, touch, or keyboard events/);
  assert.match(reasons(dets), /No mouse movement detected before click/);
  assert.ok(applyCorroborationFloor(0.1, dets) >= CORROBORATION_FLOOR);

  const person = kb(14, { keyHoldSamples: 14, keyHoldAvg: 80 });
  dets = [...detectVisionAI(person), ...detectBehavioral(person)];
  assert.doesNotMatch(reasons(dets), /Zero mouse|No mouse movement/);
});
