'use strict';

// Tests for input forensics v2 (run: `node inputforensics.test.js`).
//
// The values here are the ones the bench corpus actually measured, not round
// numbers: human typing at 226.9ms/4549 variance/82ms hold, a scripted agent at
// 7.9ms/8/7.8ms, human scrolling at 109px max step, an agent jump at 704px.
// A test that passes on invented inputs proves nothing about real ones.

const assert = require('assert');
const {
  checkFontPlatformCoherence,
  checkPastePlatformCoherence,
  checkProgrammaticFill,
  checkScrollMorphology,
  checkTypingCadence,
} = require('./inputforensics');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

const NO_TYPING = {};
const field = (over = {}) => ({ message: { keyCount: 43, pasteCount: 0, ...over } });

// --- typing cadence ---------------------------------------------------------

test('human typing cadence is not flagged', () => {
  const dets = checkTypingCadence(
    field({ avgKeyInterval: 226.9, keyIntervalVariance: 4549, dwellTimes: [82, 75, 91, 68] }),
    NO_TYPING
  );
  assert.deepStrictEqual(dets, []);
});

test('scripted agent cadence is flagged', () => {
  const dets = checkTypingCadence(
    field({ avgKeyInterval: 7.9, keyIntervalVariance: 8, dwellTimes: [7.8, 8.1, 7.4, 8.0] }),
    NO_TYPING
  );
  assert.strictEqual(dets.length, 1);
  assert.match(dets[0].reason, /mechanical/);
});

// The failure mode this check has to avoid. A paste is one or two keydowns
// microseconds apart — arithmetically identical to very fast typing — and humans
// paste constantly.
test('a human paste is never flagged as machine typing', () => {
  const pasteShaped = { avgKeyInterval: 0.8, keyIntervalVariance: 0, dwellTimes: [2.6, 2.4] };

  // Too few keystrokes to be a typing sample at all.
  assert.deepStrictEqual(
    checkTypingCadence(field({ keyCount: 2, ...pasteShaped }), NO_TYPING),
    [],
    'n=2 is not a cadence measurement'
  );

  // Even at a plausible key count, a paste anywhere on the page stands it down.
  assert.deepStrictEqual(
    checkTypingCadence(field({ keyCount: 43, ...pasteShaped }), { pasteEvents: 1 }),
    [],
    'page-level paste must exempt'
  );
  assert.deepStrictEqual(
    checkTypingCadence(field({ keyCount: 43, pasteCount: 1, ...pasteShaped }), NO_TYPING),
    [],
    'field-level paste must exempt'
  );
});

test('fast-but-variable typing is not flagged', () => {
  // A quick typist: below the interval floor on average, but with a human spread
  // and human hold times. Both conditions must fail before we accuse anyone.
  const dets = checkTypingCadence(
    field({ avgKeyInterval: 35, keyIntervalVariance: 900, dwellTimes: [60, 45, 80] }),
    NO_TYPING
  );
  assert.deepStrictEqual(dets, []);
});

// --- paste shortcut vs platform --------------------------------------------

test('Control+V on a Mac claim, with a landed paste, is a contradiction', () => {
  const dets = checkPastePlatformCoherence(
    { pasteShortcutControl: 1, pasteShortcutMeta: 0, pasteEvents: 1 },
    'MacIntel'
  );
  assert.strictEqual(dets.length, 1);
  assert.match(dets[0].reason, /Control\+V while claiming MacIntel/);
});

test('Meta+V on a Windows claim, with a landed paste, is a contradiction', () => {
  const dets = checkPastePlatformCoherence(
    { pasteShortcutMeta: 1, pasteShortcutControl: 0, pasteInputs: 1 },
    'Win32'
  );
  assert.strictEqual(dets.length, 1);
  assert.match(dets[0].reason, /Meta\+V while claiming Win32/);
});

test('the platform-correct shortcut is never a contradiction', () => {
  assert.deepStrictEqual(
    checkPastePlatformCoherence({ pasteShortcutMeta: 1, pasteEvents: 1 }, 'MacIntel'),
    []
  );
  assert.deepStrictEqual(
    checkPastePlatformCoherence({ pasteShortcutControl: 1, pasteEvents: 1 }, 'Win32'),
    []
  );
});

// A Windows switcher on a new Mac really does reach for Ctrl+V. On macOS that
// does nothing, so no paste follows — and without a completed paste there is no
// contradiction to report, only a habit.
test('a wrong shortcut that produced no paste is a fat-finger, not a bot', () => {
  const dets = checkPastePlatformCoherence(
    { pasteShortcutControl: 1, pasteShortcutMeta: 0, pasteEvents: 0, pasteInputs: 0 },
    'MacIntel'
  );
  assert.deepStrictEqual(dets, []);
});

test('Linux claims are not judged either way', () => {
  // Linux pastes with Control+V like Windows, but "Linux" is also what every
  // cloud VM claims, so there is no contradiction to draw from either modifier.
  assert.deepStrictEqual(
    checkPastePlatformCoherence({ pasteShortcutControl: 1, pasteEvents: 1 }, 'Linux x86_64'),
    []
  );
});

// --- programmatic fill ------------------------------------------------------

test('a synthetic input event with no keys is flagged, weakly', () => {
  const dets = checkProgrammaticFill({ inputsWithoutInputType: 1, inputsWithoutKeys: 1 });
  assert.strictEqual(dets.length, 1);
  assert.ok(dets[0].confidence <= 0.5, 'must stay contributory — autofill looks like this too');
});

test('a paste is not a programmatic fill', () => {
  assert.deepStrictEqual(
    checkProgrammaticFill({ inputsWithoutInputType: 1, inputsWithoutKeys: 1, pasteEvents: 1 }),
    []
  );
});

// --- scroll morphology ------------------------------------------------------

test('human scrolling is not flagged', () => {
  assert.deepStrictEqual(
    checkScrollMorphology({ keyEvents: 0, scrollMorphology: { samples: 59, maxStep: 109 } }),
    []
  );
});

test('a single-event page jump is flagged', () => {
  const dets = checkScrollMorphology({
    keyEvents: 0,
    scrollMorphology: { samples: 3, maxStep: 704 },
  });
  assert.strictEqual(dets.length, 1);
  assert.match(dets[0].reason, /scrolled by API/);
});

// PageDown and End move roughly a viewport in one event. That is a hand.
test('a keyboard user paging down is not flagged', () => {
  assert.deepStrictEqual(
    checkScrollMorphology({ keyEvents: 4, scrollMorphology: { samples: 6, maxStep: 900 } }),
    []
  );
});

// --- font / platform coherence ---------------------------------------------

test('Windows faces under a Mac claim are a contradiction', () => {
  const dets = checkFontPlatformCoherence(
    { supported: true, count: 12, hasSegoeUI: true, hasCalibri: true, hasSFPro: false, hasMenlo: false },
    'MacIntel'
  );
  assert.strictEqual(dets.length, 1);
});

test('a coherent font set is not flagged', () => {
  assert.deepStrictEqual(
    checkFontPlatformCoherence(
      { supported: true, count: 12, hasSFPro: true, hasMenlo: true, hasSegoeUI: false },
      'MacIntel'
    ),
    []
  );
});

// The rule the PRD is emphatic about: score the contradiction, never the
// enumeration. A blocked or minimal font list is a privacy extension or a lean
// Linux box, not an agent.
test('a blocked or minimal font list is never flagged', () => {
  assert.deepStrictEqual(checkFontPlatformCoherence({ supported: false }, 'MacIntel'), []);
  assert.deepStrictEqual(
    checkFontPlatformCoherence({ supported: true, count: 0 }, 'MacIntel'),
    []
  );
  assert.deepStrictEqual(
    checkFontPlatformCoherence({ supported: true, count: 2, hasSegoeUI: true }, 'MacIntel'),
    [],
    'two faces is not an inventory'
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
