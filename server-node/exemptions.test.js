'use strict';

// Tests for the library's false-positive guards (run: `node exemptions.test.js`).
//
// These guards came out of bench human panel findings. server-node used to
// carry two engines and the published library never received them, so
// `@webdecoy/fcaptcha` scored real users the other engines exempt: touch,
// keyboard-only and screen-reader visitors on the mouse-trajectory checks, and
// elderly/motor-impaired visitors on the slow-pointer checks. Both engines now
// share engine.js, so these run once and cover both.
//
// The values here sit deliberately on either side of the documented
// thresholds; they are constructed cases, not bench captures.

const assert = require('assert');
const { detectVisionAI, detectBehavioral } = require('./engine');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

const visionReasons = (behavioral) =>
  detectVisionAI({ behavioral }).map((d) => d.reason);
const behavioralReasons = (behavioral) =>
  detectBehavioral({ behavioral }).map((d) => d.reason);

const TREMOR = 'Mouse movement lacks natural micro-tremor';
const DIRECT = 'Mouse path to target is unnaturally direct';
const VELOCITY = 'Mouse velocity too consistent';
const EVENT_RATE = 'Mouse event rate abnormally low';

// A pointer path flat enough to trip both mouse-trajectory checks.
const flatPath = {
  totalPoints: 60,
  trajectoryLength: 400,
  microTremorScore: 0.05,
  approachPoints: 12,
  approachDirectness: 0.99,
  keyEvents: 0,
  touchEvents: 0,
};

test('a mouse user with a flat path still trips both trajectory checks', () => {
  // The control: without it, the exemptions below prove nothing.
  const reasons = visionReasons(flatPath);
  assert.ok(reasons.includes(TREMOR), `expected ${TREMOR}, got ${JSON.stringify(reasons)}`);
  assert.ok(reasons.includes(DIRECT), `expected ${DIRECT}, got ${JSON.stringify(reasons)}`);
});

test('a touch user is exempt from the mouse-trajectory checks', () => {
  const reasons = visionReasons({ ...flatPath, touchEvents: 5 });
  assert.ok(!reasons.includes(TREMOR), 'touch users have no mouse path to judge');
  assert.ok(!reasons.includes(DIRECT), 'touch users have no approach path to judge');
});

test('one touch event plus a non-mouse pointer establishes modality', () => {
  // A mobile user who simply taps produces exactly one touch event.
  const reasons = visionReasons({
    ...flatPath,
    touchEvents: 1,
    pointerHasNonMouseType: true,
  });
  assert.ok(!reasons.includes(TREMOR), 'a single tap still establishes touch modality');
  assert.ok(!reasons.includes(DIRECT), 'a single tap still establishes touch modality');
});

test('a keyboard-only user is exempt from the mouse-trajectory checks', () => {
  const reasons = visionReasons({
    ...flatPath,
    totalPoints: 0,
    keyEvents: 4,
  });
  assert.ok(!reasons.includes(TREMOR), 'keyboard-only users never move a mouse');
  assert.ok(!reasons.includes(DIRECT), 'keyboard-only users have no approach path');
});

test('micro-tremor is not judged without real mouse movement', () => {
  // 0.5 is the client's "no mouse data" sentinel; below 5 points there is no
  // texture to measure either way.
  const reasons = visionReasons({ ...flatPath, totalPoints: 2 });
  assert.ok(!reasons.includes(TREMOR), 'two points is not a path');
});

test('directness is not judged without an approach path', () => {
  const reasons = visionReasons({ ...flatPath, approachPoints: 0, approachDirectness: 1 });
  assert.ok(!reasons.includes(DIRECT), 'directness 1 with no points is the no-path sentinel');
});

// A slow but unmistakably human pointer: saturated tremor, corrective
// overshoots and plenty of direction changes.
const slowHuman = {
  totalPoints: 60,
  trajectoryLength: 400,
  microTremorScore: 0.8,
  overshootCorrections: 3,
  directionChanges: 24,
  velocityVariance: 0.01,
  mouseEventRate: 5,
};

test('a slow human with movement markers is exempt from the slow-pointer checks', () => {
  const reasons = behavioralReasons(slowHuman);
  assert.ok(!reasons.includes(VELOCITY), 'motor-slow visitors move consistently and slowly');
  assert.ok(!reasons.includes(EVENT_RATE), 'elderly and motor-slow visitors emit few events');
});

test('the same slow pointer without movement markers still trips them', () => {
  // Slowness alone cannot separate a human from an agent — the markers do.
  const reasons = behavioralReasons({
    ...slowHuman,
    microTremorScore: 0.05,
    overshootCorrections: 0,
    directionChanges: 1,
  });
  assert.ok(reasons.includes(VELOCITY), `expected ${VELOCITY}, got ${JSON.stringify(reasons)}`);
  assert.ok(reasons.includes(EVENT_RATE), `expected ${EVENT_RATE}, got ${JSON.stringify(reasons)}`);
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL ${name}\n       ${err.message}`);
  }
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed === 0 ? 0 : 1);
