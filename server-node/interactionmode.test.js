'use strict';

// Tests for the widget/invisible interaction mode (run: `node interactionmode.test.js`).
//
// approachPoints, approachDirectness, clickPrecision, explorationRatio and
// overshootCorrections are all produced by the client's analyzeClick(), which
// only runs when there is a widget to click. Invisible scoring never calls it,
// so those fields are absent and read back as 0 — indistinguishable from "the
// pointer teleported onto the target". Production logs had the approach check
// firing on 100% of /api/score calls before this.

const assert = require('assert');
const { setInteractionMode, detectVisionAI, detectBehavioral } = require('./engine');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// One payload, so the interaction mode is the only variable: click-derived
// fields at the values an absent analyzeClick() produces server-side, plus a
// couple of minutes on the page.
const clickDerivedSession = () => ({
  behavioral: {
    totalPoints: 60,
    trajectoryLength: 400,
    microTremorScore: 0.4,
    velocityVariance: 0.5,
    touchEvents: 0,
    keyEvents: 0,
    approachPoints: 0,
    explorationRatio: 0.0,
    overshootCorrections: 0,
    interactionDuration: 120000,
  },
});

const CLICK_DERIVED_REASONS = [
  'No exploratory mouse movement before click',
  'No overshoot corrections on long trajectory',
  'Unusually long interaction time',
];

const reasonsFor = (signals) =>
  [...detectVisionAI(signals), ...detectBehavioral(signals)].map((d) => d.reason);

test('widget mode still fires the click-derived checks', () => {
  const reasons = reasonsFor(setInteractionMode(clickDerivedSession(), true));
  for (const reason of CLICK_DERIVED_REASONS) {
    assert.ok(reasons.includes(reason), `expected ${reason}, got ${JSON.stringify(reasons)}`);
  }
});

test('invisible mode fires none of them', () => {
  const reasons = reasonsFor(setInteractionMode(clickDerivedSession(), false));
  for (const reason of CLICK_DERIVED_REASONS) {
    assert.ok(!reasons.includes(reason), `${reason} should not fire without a widget`);
  }
});

test('an unset mode defaults to widget, so existing callers are unaffected', () => {
  const reasons = reasonsFor(clickDerivedSession());
  for (const reason of CLICK_DERIVED_REASONS) {
    assert.ok(reasons.includes(reason), `expected ${reason} with no server context set`);
  }
});

test('a client cannot claim invisible mode in its own signals', () => {
  // The mode comes from the endpoint. A client that could claim "invisible"
  // could switch these checks off on the widget path.
  const spoofed = clickDerivedSession();
  spoofed.serverContext = { widgetInteraction: false };
  const reasons = reasonsFor(setInteractionMode(spoofed, true));
  for (const reason of CLICK_DERIVED_REASONS) {
    assert.ok(reasons.includes(reason), 'server-set mode must win over client-supplied context');
  }
});

test('directness needs a real approach path before it is judged', () => {
  // The client reports directness 1 (perfectly straight) when there is no
  // approach path at all, which fired on every keyboard-only, screen-reader
  // and touch user. server.js, Go and Python already required a path; the
  // library did not.
  const noPath = clickDerivedSession();
  noPath.behavioral.approachDirectness = 1;
  noPath.behavioral.approachPoints = 0;
  assert.ok(
    !reasonsFor(noPath).includes('Mouse path to target is unnaturally direct'),
    'directness must not be judged without an approach path'
  );

  const realPath = clickDerivedSession();
  realPath.behavioral.approachDirectness = 0.99;
  realPath.behavioral.approachPoints = 12;
  assert.ok(
    reasonsFor(realPath).includes('Mouse path to target is unnaturally direct'),
    'a genuinely straight path with points behind it should still fire'
  );
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
