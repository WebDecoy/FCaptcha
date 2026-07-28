'use strict';

/**
 * Input forensics v2 — PRD workstream C.
 *
 * Four checks on *how* input arrived rather than how much of it there was:
 * typing cadence, typing modality, the paste-shortcut/platform contradiction,
 * and scroll morphology.
 *
 * ## Every threshold here was measured, not assumed
 *
 * The PRD quotes FP-Agent's observations (Manus 1.39ms inter-key, Browser Use
 * 5.31ms, Skyvern 9.52ms) and then warns, correctly, that they are *not*
 * constants: the paper found Browser Use programs an 18ms delay yet is observed
 * at 5.31ms, because the renderer batches events. The numbers are a function of
 * browser version and machine load. Hardcoding them would be copying someone
 * else's laboratory conditions.
 *
 * So the values below come from the bench corpus (bench/README.md), captured on
 * real hardware through a real browser:
 *
 *   signal                 human                     scripted agent
 *   ---------------------  ------------------------  --------------------
 *   inter-key interval     min 114.6ms, med 226.9ms  max 25.9ms, med 7.9ms
 *   interval variance      4549                      8
 *   key hold (dwell)       min 41.4ms, med 82.0ms    max 25.5ms, med 7.8ms
 *   scroll max step        109px                     704px
 *
 * The distributions do not overlap, so the thresholds sit in the empty space
 * between them with a wide margin on both sides rather than hugging either.
 * Re-derive them with `node bench/run-bench.js` on your own hardware if you
 * fork this; that is what §7.4 of the PRD is asking for.
 *
 * ## What is deliberately NOT here
 *
 * Keystroke overlap — the claim that humans press the next key before releasing
 * the current one and agents never do. An earlier PRD draft attributed it to
 * FP-Agent; the paper does not say it. It defines a keystroke as "a keydown
 * event followed by a keyup event" and its only overlap language is about
 * modifier keys in shortcuts. Rollover typing is real in the keystroke-dynamics
 * literature, so the hypothesis may well hold — but it has no source and no
 * measurement here, so it earns no weight.
 *
 * ## Weighting
 *
 * All of these are contributory, not decisive, per §7.4. The coalesced-events
 * signal FCaptcha already ships is under active attack from stealth tooling
 * that synthesises it; behavioural signals have a shelf life, and any one of
 * them carrying a verdict on its own is a liability. The one exception in
 * spirit is the platform contradiction, which scores higher because it is not a
 * threshold at all — it is the client disagreeing with itself.
 */

// --- measured thresholds ----------------------------------------------------

// 2.9x below the slowest human keystroke observed, 1.5x above the fastest agent one.
const MAX_MACHINE_INTERKEY_MS = 40;
// Human variance was 4549; the scripted agent's was 8.
const MAX_MACHINE_INTERVAL_VARIANCE = 200;
// Human holds bottomed out at 41ms; the agent never exceeded 25.5ms.
const MAX_MACHINE_DWELL_MS = 35;
// Enough keystrokes to be a typing sample at all. A paste registers as one or
// two keydowns, and at n=2 any cadence statistic is noise.
const MIN_KEYS_FOR_CADENCE = 10;
// Human scrolling never stepped more than 109px between events; scrollIntoView
// covered 704px in one.
const MAX_HUMAN_SCROLL_STEP_PX = 400;

const MAC_PLATFORMS = /^(mac|iphone|ipad|ipod)/i;
const WINDOWS_PLATFORMS = /^win/i;

const num = (v, dflt = 0) => (typeof v === 'number' && Number.isFinite(v) ? v : dflt);

/**
 * Typing cadence: a hand cannot hold a key for 8ms, forty times, with no spread.
 *
 * Gated hard, because the failure mode is punishing people who paste. Humans
 * paste constantly — password managers, copied addresses, one-time codes — and
 * a paste arrives as one or two keydowns microseconds apart, which is
 * arithmetically indistinguishable from very fast typing. The bench's
 * paste-by-human persona is exactly that shape: 2 keys, 0.8ms apart, variance 0.
 *
 * Hence three preconditions before the cadence is even looked at: enough keys to
 * be a sample, no paste anywhere on the page, and no paste into this field.
 */
function checkTypingCadence(fields, typing) {
  const detections = [];
  if (!fields) return detections;

  const pastedAnywhere = num(typing.pasteEvents) > 0 || num(typing.pasteInputs) > 0;
  if (pastedAnywhere) return detections;

  for (const [, stats] of Object.entries(fields)) {
    if (!stats || typeof stats !== 'object') continue;
    if (num(stats.pasteCount) > 0) continue;

    const keyCount = num(stats.keyCount);
    if (keyCount < MIN_KEYS_FOR_CADENCE) continue;

    const interval = num(stats.avgKeyInterval, Infinity);
    const variance = num(stats.keyIntervalVariance, Infinity);
    const dwells = Array.isArray(stats.dwellTimes) ? stats.dwellTimes : [];
    const avgDwell = dwells.length
      ? dwells.reduce((a, b) => a + b, 0) / dwells.length
      : Infinity;

    // Both the rhythm and the hold have to be inhuman. Either alone is a
    // machine that happens to be slow, or a fast typist on a bad keyboard.
    const machineRhythm = interval < MAX_MACHINE_INTERKEY_MS && variance < MAX_MACHINE_INTERVAL_VARIANCE;
    const machineHold = avgDwell < MAX_MACHINE_DWELL_MS;

    if (machineRhythm && machineHold) {
      detections.push({
        category: 'behavioral',
        score: 0.6,
        confidence: 0.6,
        reason: 'Typing cadence is mechanical (inter-key and hold both below human range)',
      });
      break; // one detection per request, however many fields were filled
    }
  }

  return detections;
}

/**
 * The paste shortcut disagrees with the platform the client claims.
 *
 * macOS pastes with Meta+V; Windows and Linux paste with Control+V. These are
 * not conventions a user can be halfway between — the other combination does
 * nothing at all on that OS. So a client reporting `MacIntel` whose visitor
 * pasted with Control+V has told us two incompatible things about itself.
 *
 * Requiring that the paste *landed* is what makes this safe. A Windows
 * switcher on a new Mac really does fat-finger Ctrl+V — and on macOS nothing
 * happens, so no paste event follows. Only a client whose real platform differs
 * from its claimed one gets both the wrong shortcut and a completed paste.
 *
 * No threshold, no calibration, no hardware dependence. Scored higher than the
 * cadence checks for exactly that reason.
 */
function checkPastePlatformCoherence(typing, platform) {
  if (!platform) return [];

  const pasted = num(typing.pasteEvents) > 0 || num(typing.pasteInputs) > 0;
  if (!pasted) return [];

  const ctrl = num(typing.pasteShortcutControl);
  const meta = num(typing.pasteShortcutMeta);

  const claimsMac = MAC_PLATFORMS.test(platform);
  const claimsWindows = WINDOWS_PLATFORMS.test(platform);

  if (claimsMac && ctrl > 0 && meta === 0) {
    return [{
      category: 'automation',
      score: 0.7,
      confidence: 0.8,
      reason: `Paste shortcut contradicts platform (Control+V while claiming ${platform})`,
    }];
  }
  if (claimsWindows && meta > 0 && ctrl === 0) {
    return [{
      category: 'automation',
      score: 0.7,
      confidence: 0.8,
      reason: `Paste shortcut contradicts platform (Meta+V while claiming ${platform})`,
    }];
  }
  return [];
}

/**
 * Text that appeared without being typed or pasted.
 *
 * A genuine `input` event carries an `inputType` describing what the browser
 * did; a synthetic one dispatched by script does not. Combined with no
 * keystrokes and no paste, that is a value assigned straight into the DOM.
 *
 * Deliberately low confidence: browser autofill and some password managers also
 * produce input events with no keystrokes behind them, and the whole point of
 * §7.1's warning is that a check which punishes password-manager users is worse
 * than no check. It contributes; it never decides.
 */
function checkProgrammaticFill(typing) {
  const noType = num(typing.inputsWithoutInputType);
  const noKeys = num(typing.inputsWithoutKeys);
  const pasted = num(typing.pasteEvents) > 0 || num(typing.pasteInputs) > 0;

  if (noType > 0 && noKeys > 0 && !pasted) {
    return [{
      category: 'automation',
      score: 0.5,
      confidence: 0.4,
      reason: 'Field populated without keystrokes or paste (synthetic input event)',
    }];
  }
  return [];
}

/**
 * Scroll morphology: the page moved further in one event than a hand can move it.
 *
 * A wheel notch or trackpad flick advances tens of pixels and emits an event
 * each time, so covering a long page takes dozens of them. `scrollIntoView()`
 * covers the same distance in one, because it is aiming at an element rather
 * than turning a wheel. Measured: human scrolling never exceeded 109px between
 * consecutive events; the agent's jump was 704px.
 *
 * This is an architecture tell as much as a bot tell — DOM-driven agents jump,
 * vision-driven ones emit short bursts, people produce long variable gestures.
 *
 * Gated on there being no keyboard activity, because PageDown, End and Space
 * are legitimate one-event jumps of roughly a viewport. A visitor using the
 * keyboard to scroll is doing something a hand does; a DOM agent has no keys.
 */
function checkScrollMorphology(behavioral) {
  const m = behavioral.scrollMorphology;
  if (!m || typeof m !== 'object') return [];

  if (num(behavioral.keyEvents) > 0) return [];
  if (num(m.samples) < 2) return [];

  if (num(m.maxStep) > MAX_HUMAN_SCROLL_STEP_PX) {
    return [{
      category: 'automation',
      score: 0.5,
      confidence: 0.5,
      reason: 'Page scrolled by API rather than by gesture (single-event jump)',
    }];
  }
  return [];
}

/**
 * Font list contradicts the claimed operating system.
 *
 * Scores the *contradiction*, never the enumeration. A short font list means a
 * privacy extension, a minimal Linux install or a locked-down corporate image —
 * all ordinary. A list full of Windows-only faces under a macOS claim is not
 * ordinary, it is two different machines' worth of evidence in one payload.
 *
 * Validated in both directions by the bench corpus, though the positive case
 * arrived by accident: the `incoherent-paste` persona spoofs `Win32` in order to
 * test the paste-shortcut check, and while doing so it presents this machine's
 * genuine macOS font set under a Windows claim. This check caught that
 * independently. It stays silent on all 14 human personas.
 *
 * Still weighted as contributory. One machine's font set is thin evidence for a
 * rule about every machine, and the specific shape the PRD describes — ChatGPT
 * Agent reporting a Calibri-only list under both Linux and MacIntel claims — has
 * not been captured here.
 */
function checkFontPlatformCoherence(fonts, platform) {
  if (!fonts || fonts.supported === false || !platform) return [];

  // An empty or near-empty list is a blocked enumeration, not a contradiction.
  if (num(fonts.count) < 3) return [];

  const claimsMac = MAC_PLATFORMS.test(platform);
  const claimsWindows = WINDOWS_PLATFORMS.test(platform);

  const macFonts = fonts.hasSFPro === true || fonts.hasMenlo === true;
  const winFonts = fonts.hasSegoeUI === true || fonts.hasCalibri === true;

  if (claimsMac && winFonts && !macFonts) {
    return [{
      category: 'automation',
      score: 0.5,
      confidence: 0.5,
      reason: `Font set contradicts platform (Windows faces while claiming ${platform})`,
    }];
  }
  if (claimsWindows && macFonts && !winFonts) {
    return [{
      category: 'automation',
      score: 0.5,
      confidence: 0.5,
      reason: `Font set contradicts platform (macOS faces while claiming ${platform})`,
    }];
  }
  return [];
}

/** Runs every workstream-C check. */
function detectInputForensics(signals) {
  const behavioral = signals.behavioral || {};
  const form = signals.formAnalysis || {};
  const env = signals.environmental || {};
  const typing = form.typing || {};
  const platform = (env.navigator && env.navigator.platform) || null;

  return [
    ...checkTypingCadence(form.textareaKeyboard, typing),
    ...checkPastePlatformCoherence(typing, platform),
    ...checkProgrammaticFill(typing),
    ...checkScrollMorphology(behavioral),
    ...checkFontPlatformCoherence(env.fontsInfo, platform),
  ];
}

module.exports = {
  MAX_HUMAN_SCROLL_STEP_PX,
  MAX_MACHINE_DWELL_MS,
  MAX_MACHINE_INTERKEY_MS,
  MAX_MACHINE_INTERVAL_VARIANCE,
  MIN_KEYS_FOR_CADENCE,
  checkFontPlatformCoherence,
  checkPastePlatformCoherence,
  checkProgrammaticFill,
  checkScrollMorphology,
  checkTypingCadence,
  detectInputForensics,
};
