'use strict';

/**
 * Shared detection and scoring core.
 *
 * server-node used to carry two independent engines: server.js (the Express
 * server) and index.js (the npm `main`, published as `@webdecoy/fcaptcha`).
 * They drifted badly. The library was missing seventeen detectors, had no
 * `cdp` or `declared_ai` weight category, and still aggregated with the
 * pre-v1.18.0 confidence-weighted mean — the model where corroborating
 * evidence *lowers* the verdict — with no dispositive floor. Anyone using the
 * package as a library got materially weaker detection than anyone running the
 * server, and nothing in the API said so.
 *
 * Everything here is pure: signals in, detections out. The stateful detectors
 * (fingerprint reuse, rate abuse) stay with whichever engine owns the store.
 */

// =============================================================================
// Detection Patterns
// =============================================================================

const AUTOMATION_UA_PATTERNS = [
  /headless/i, /phantomjs/i, /selenium/i, /webdriver/i,
  /puppeteer/i, /playwright/i, /cypress/i, /nightwatch/i,
  /zombie/i, /electron/i, /chromium.*headless/i
];

const WEIGHTS = {
  vision_ai: 0.15,
  headless: 0.15,
  automation: 0.08,
  cdp: 0.12,
  behavioral: 0.18,
  fingerprint: 0.08,
  rate_limit: 0.01,
  datacenter: 0.07,
  tor_vpn: 0.01,
  bot: 0.13,
  declared_ai: 0.02
};

// =============================================================================
// Detection Functions
// =============================================================================

/**
 * Movement that carries independent evidence of a human hand.
 *
 * A slow pointer is the thing two of these checks look for, and it is also
 * exactly what an elderly or motor-impaired visitor produces. The bench human
 * panel caught both firing on them: "Mouse event rate abnormally low" on the
 * elderly and motor-slow personas, "Mouse velocity too consistent" on
 * motor-slow.
 *
 * Slowness alone cannot separate those users from an agent, but it does not
 * have to. The same captures carry markers no low-effort automation produces:
 * saturated micro-tremor, dozens of direction changes, corrective overshoots.
 * On the bench corpus the split is total - every human persona clears this bar
 * (tremor 1.00, 22-49 direction changes, 1-4 corrections) and every agent
 * misses it (tremor 0.04-0.16, 0-1 direction changes, 0 corrections).
 *
 * So: do not read slowness as automation when the movement independently looks
 * like a hand. An agent can of course fake all three, but faking three
 * correlated properties of human motion is a materially harder job than
 * running slowly, which is the point.
 */
function hasHumanMovementMarkers(b) {
  const tremor = b.microTremorScore ?? 0.5;
  const corrections = b.overshootCorrections ?? 0;
  const changes = b.directionChanges ?? 0;
  return tremor >= 0.5 && (corrections >= 1 || changes >= 10);
}

/**
 * Whether this visitor is using a touch or pen device, and so should be exempt
 * from the mouse-trajectory detections.
 *
 * The old rule was `touchEvents >= 3`, which a mobile user who simply taps the
 * checkbox does not meet: the client records touchstart and touchmove, and a
 * clean tap on a page short enough not to need scrolling produces exactly one
 * event. The bench human panel captured precisely that — `touchEvents: 1` — and
 * the visitor collected three agent detections for it, including
 * "Zero mouse, touch, or keyboard events recorded" at confidence 0.9.
 *
 * One touch event is enough to establish modality. Corroborating it with the
 * pointer type keeps a bare forged count from claiming the exemption on its
 * own — though note this is a soft check either way, since every input here is
 * client-supplied and an agent willing to claim `touchEvents: 1` was equally
 * willing to claim 3.
 */
function isTouchModality(b) {
  const touchEvents = b.touchEvents ?? 0;
  const touchPoints = b.touchTotalPoints ?? 0;
  return touchEvents >= 3 || ((touchEvents >= 1 || touchPoints >= 1) && b.pointerHasNonMouseType === true);
}

function getNestedValue(obj, ...keys) {
  return keys.reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);
}

// serverContext holds request facts the server establishes itself, kept apart
// from the client-supplied signal tree it sits beside.
const SERVER_CONTEXT_KEY = 'serverContext';

/**
 * Record whether this request came from a rendered widget (a real click
 * target) or from invisible scoring.
 *
 * approachPoints, approachDirectness, clickPrecision, explorationRatio and
 * overshootCorrections are all produced by the client's analyzeClick(), which
 * only runs when there is a widget to click. Invisible scoring never calls it,
 * so those fields are absent and read back as 0 — indistinguishable from "the
 * pointer teleported onto the target". Production logs showed the approach
 * check firing on 100% of invisible calls for exactly that reason.
 *
 * Set from the endpoint, never from the signals: a client that could claim
 * "invisible" could switch these checks off on the widget path.
 */
function setInteractionMode(signals, widget) {
  if (!signals || typeof signals !== 'object') return signals;
  signals[SERVER_CONTEXT_KEY] = {
    ...(signals[SERVER_CONTEXT_KEY] || {}),
    widgetInteraction: !!widget
  };
  return signals;
}

/**
 * Whether click-derived behavioural fields carry meaning for this request.
 * Absent context means widget mode — the long-standing behaviour.
 */
function hasWidgetInteraction(signals) {
  const ctx = signals && signals[SERVER_CONTEXT_KEY];
  if (!ctx || typeof ctx.widgetInteraction !== 'boolean') return true;
  return ctx.widgetInteraction;
}

function detectVisionAI(signals) {
  const detections = [];
  const b = signals.behavioral || {};
  const t = signals.temporal || {};

  // Zero/minimal mouse movement - strong indicator of AI agent or programmatic click
  // Exempt: touch users (mobile) and keyboard-only users (accessibility)
  const totalPoints = b.totalPoints ?? 0;
  const trajectory = b.trajectoryLength ?? 0;
  const approachPts = b.approachPoints ?? 0;
  const touchEvents = b.touchEvents ?? 0;
  const keyEvents = b.keyEvents ?? 0;
  const isTouchUser = isTouchModality(b);
  const isKeyboardUser = keyEvents >= 2 && totalPoints === 0;
  // Click-derived fields only exist when a widget was there to click.
  const isWidget = hasWidgetInteraction(signals);

  if (totalPoints < 5 && trajectory < 10 && !isTouchUser && !isKeyboardUser) {
    detections.push({
      category: 'vision_ai', score: 0.9, confidence: 0.85,
      reason: 'No mouse movement detected before click (AI agent pattern)'
    });
  }

  // Invisible scoring has no target to approach, so a missing approach path
  // says nothing there (see setInteractionMode).
  if (isWidget && approachPts === 0 && !isTouchUser && !isKeyboardUser) {
    detections.push({
      category: 'vision_ai', score: 0.7, confidence: 0.8,
      reason: 'No approach trajectory to target'
    });
  }

  // PoW timing
  const pow = t.pow || {};
  if (pow.duration && pow.iterations) {
    const expectedMin = (pow.iterations / 500000) * 1000;
    const expectedMax = (pow.iterations / 50000) * 1000;

    if (pow.duration < expectedMin * 0.5) {
      detections.push({
        category: 'vision_ai', score: 0.8, confidence: 0.7,
        reason: 'PoW completed impossibly fast'
      });
    } else if (pow.duration > expectedMax * 3) {
      detections.push({
        category: 'vision_ai', score: 0.6, confidence: 0.5,
        reason: 'PoW timing suggests external processing'
      });
    }
  }

  // Micro-tremor
  // Micro-tremor.
  //
  // Two things were wrong here. Go defaulted a missing microTremorScore to 0
  // (maximally suspicious) while Node and Python defaulted to 0.5, so a client
  // that omitted the field was flagged by one server and not the others. And
  // like the approach-directness check above, this fires on a measurement that
  // does not exist for someone who never moved a mouse — the client itself
  // reports 0.5 as its "no mouse data" sentinel.
  //
  // Require real mouse movement before judging its texture, and apply the same
  // exemptions as the surrounding checks.
  const microTremor = b.microTremorScore ?? 0.5;
  const hasMouseMovement = totalPoints >= 5;
  if (hasMouseMovement && !isTouchUser && !isKeyboardUser && microTremor < 0.15) {
    detections.push({
      category: 'vision_ai', score: 0.7, confidence: 0.6,
      reason: 'Mouse movement lacks natural micro-tremor'
    });
  }

  // Approach directness.
  //
  // The client reports directness 1 (perfectly straight) when there is no
  // approach path to measure at all, so this check used to fire on every
  // keyboard-only, screen-reader and touch user — the populations the
  // surrounding checks go out of their way to exempt. Found by the bench
  // human panel: keyboard-only, screen-reader and touch all reported
  // approachPoints 0 with approachDirectness 1.
  //
  // Require an actual path before judging its shape, and apply the same
  // exemptions as its neighbours.
  const hasApproachPath = approachPts >= 5;
  if (hasApproachPath && !isTouchUser && !isKeyboardUser && (b.approachDirectness ?? 0) > 0.95) {
    detections.push({
      category: 'vision_ai', score: 0.5, confidence: 0.5,
      reason: 'Mouse path to target is unnaturally direct'
    });
  }

  // Click precision
  const precision = b.clickPrecision ?? 10;
  if (precision > 0 && precision < 2) {
    detections.push({
      category: 'vision_ai', score: 0.4, confidence: 0.5,
      reason: 'Click precision is unnaturally accurate'
    });
  }

  // Exploration. Click-derived, so widget-only.
  const exploration = b.explorationRatio ?? 0.3;
  if (isWidget && exploration < 0.05 && trajectory > 50) {
    detections.push({
      category: 'vision_ai', score: 0.4, confidence: 0.4,
      reason: 'No exploratory mouse movement before click'
    });
  }

  // Input-event forensics: teleport clicks and agent think-time cadence.
  const fcs = b.inputForensics;
  if (fcs) {
    const teleports = fcs.teleportClicks ?? 0;
    if (teleports >= 1 && !isTouchUser) {
      detections.push({
        category: 'vision_ai', score: 0.7, confidence: 0.7,
        reason: `Click injected with no pointer trajectory (${teleports} teleport clicks)`
      });
    }
    // Bursts of activity separated by multi-second perfect silence — the agent
    // act -> screenshot -> inference loop. Low confidence (slow humans idle too);
    // requires silence to dominate. Keyboard-only users are exempt.
    if (!isKeyboardUser &&
        (fcs.cadenceEvents ?? 0) >= 12 &&
        (fcs.cadenceSilentGaps ?? 0) >= 3 &&
        (fcs.cadenceGapCV ?? 0) > 2.5 &&
        (fcs.cadenceSilentRatio ?? 0) > 0.6) {
      detections.push({
        category: 'vision_ai', score: 0.6, confidence: 0.5,
        reason: 'Interaction cadence matches agent act/think loop (bursts + dead air)'
      });
    }
  }

  return detections;
}

function detectHeadless(signals, userAgent) {
  const detections = [];
  const env = signals.environmental || {};
  const headless = env.headlessIndicators || {};
  const automation = env.automationFlags || {};

  // WebDriver
  if (env.webdriver) {
    detections.push({
      category: 'headless', score: 0.95, confidence: 0.95,
      dispositive: true, // navigator.webdriver === true — see DISPOSITIVE_FLOOR
      reason: 'WebDriver detected'
    });
  }

  // Automation flags
  if (automation.plugins === 0) {
    detections.push({
      category: 'headless', score: 0.6, confidence: 0.6,
      reason: 'No browser plugins detected'
    });
  }

  if (automation.languages === false) {
    detections.push({
      category: 'headless', score: 0.5, confidence: 0.5,
      reason: 'No navigator.languages'
    });
  }

  // Headless indicators
  if (headless.hasOuterDimensions === false) {
    detections.push({
      category: 'headless', score: 0.7, confidence: 0.7,
      reason: 'Window lacks outer dimensions'
    });
  }

  if (headless.innerEqualsOuter === true) {
    detections.push({
      category: 'headless', score: 0.4, confidence: 0.5,
      reason: 'Viewport equals window size'
    });
  }

  if (headless.notificationPermission === 'denied') {
    detections.push({
      category: 'headless', score: 0.3, confidence: 0.4,
      reason: 'Notifications pre-denied'
    });
  }

  // User-Agent patterns
  for (const pattern of AUTOMATION_UA_PATTERNS) {
    if (pattern.test(userAgent)) {
      detections.push({
        category: 'headless', score: 0.9, confidence: 0.9,
        reason: 'Automation pattern in User-Agent'
      });
      break;
    }
  }

  // WebGL renderer
  const renderer = (getNestedValue(env, 'webglInfo', 'renderer') || '').toLowerCase();
  if (renderer.includes('swiftshader') || renderer.includes('llvmpipe')) {
    detections.push({
      category: 'headless', score: 0.8, confidence: 0.8,
      reason: 'Software WebGL renderer detected'
    });
  }

  // Playwright-specific detection
  const playwright = env.playwright || {};
  if (playwright.detected) {
    const playwrightSignals = playwright.signals || [];
    const scoreMap = {
      playwright_globals: 0.95,
      webdriver_deleted: 0.8,
      webdriver_configurable: 0.7,
      chrome_runtime_missing: 0.6,
    };
    // Signals a genuine browser also produces, and therefore not evidence of
    // anything. Ignored here as well as in the client, because clients already
    // deployed will keep sending them.
    //
    // Measured in Chrome 150 with navigator.webdriver === false:
    //   webdriver_configurable  descriptor present and configurable — WebIDL
    //                           defines the attribute that way, so every browser
    //                           reports what a patched one reports
    //   chrome_runtime_missing  window.chrome present, chrome.runtime absent, on
    //                           any page without a matching externally_connectable
    //                           extension, i.e. almost every page
    //
    // They fired together on ordinary Chrome, so they cannot corroborate each
    // other either.
    const INERT_SIGNALS = new Set(['webdriver_configurable', 'chrome_runtime_missing']);

    for (const sig of playwrightSignals) {
      if (INERT_SIGNALS.has(sig)) continue;
      const sigScore = scoreMap[sig] || 0.7;
      detections.push({
        category: 'headless', score: sigScore, confidence: 0.8,
        reason: `Playwright artifact detected: ${sig}`
      });
    }

  }

  return detections;
}

// Flags anti-detection patch traces collected by the client. FALSE-POSITIVE-
// SAFE: a genuine browser never produces these (internal contradictions /
// native-function tampering, not environment-shape heuristics that would
// misfire on real Linux/VPN users). Targets stealth agents (e.g. Manus AI)
// driving real-but-patched Chromium. Only the two FP-safe signals are scored;
// the client also collects privacy-extension-ambiguous artifacts (patched_*)
// for observability that are intentionally NOT scored. Keep in sync with Go/Py.
function detectStealthArtifacts(signals) {
  const detections = [];
  const env = signals.environmental || {};

  // Function.prototype.toString proxied — the signature move of stealth
  // frameworks (used to make their other native overrides look untouched).
  const artifactSignals = (env.stealthArtifacts && env.stealthArtifacts.signals) || [];
  if (artifactSignals.includes('tostring_proxied')) {
    detections.push({
      category: 'headless', score: 0.9, confidence: 0.85,
      reason: 'Function.prototype.toString is proxied (stealth automation patch)'
    });
  }

  // Notification.permission === 'denied' while the Permissions API reports
  // 'prompt': a state a real browser cannot reach (classic headless tell).
  if (env.permissionProbe && env.permissionProbe.contradiction === true) {
    detections.push({
      category: 'headless', score: 0.85, confidence: 0.85,
      reason: 'Notification permission contradicts Permissions API (headless/stealth tell)'
    });
  }

  return detections;
}

function detectAutomation(signals) {
  const detections = [];
  const env = signals.environmental || {};
  const b = signals.behavioral || {};

  // JS execution timing
  const jsTime = getNestedValue(env, 'jsExecutionTime', 'mathOps') || 0;
  if (jsTime > 0) {
    if (jsTime < 0.1) {
      detections.push({
        category: 'automation', score: 0.4, confidence: 0.3,
        reason: 'JS execution unusually fast'
      });
    } else if (jsTime > 50) {
      detections.push({
        category: 'automation', score: 0.3, confidence: 0.3,
        reason: 'JS execution unusually slow'
      });
    }
  }

  // RAF consistency
  const raf = env.rafConsistency || {};
  if (raf.frameTimeVariance !== undefined && raf.frameTimeVariance < 0.1) {
    detections.push({
      category: 'automation', score: 0.5, confidence: 0.4,
      reason: 'RequestAnimationFrame timing too consistent'
    });
  }

  // Event timing
  const eventVar = b.eventDeltaVariance ?? 10;
  const totalPoints = b.totalPoints ?? 0;
  if (eventVar < 2 && totalPoints > 10) {
    detections.push({
      category: 'automation', score: 0.6, confidence: 0.6,
      reason: 'Mouse event timing unnaturally consistent'
    });
  }

  return detections;
}

function detectCDP(signals) {
  const detections = [];
  const env = signals.environmental || {};
  const cdp = env.cdp || {};

  // Input-event forensics: catch CDP-injected input that reports isTrusted:true
  // and so evades the global-based checks below. Touch users are exempt.
  const b = signals.behavioral || {};
  const isTouchUser = (b.touchEvents ?? 0) >= 3;
  const fcs = b.inputForensics;
  if (fcs && !isTouchUser) {
    // Real mice coalesce several hardware samples per frame; a stream of
    // pointermoves that NEVER coalesced is synthetic injection.
    if ((fcs.coalescedSamples ?? 0) >= 20 && (fcs.coalescedMax ?? 0) <= 1) {
      detections.push({
        category: 'cdp', score: 0.8, confidence: 0.6,
        reason: 'Pointer moves never coalesced across many samples (synthetic/CDP input)'
      });
    }
    // movementX/Y incoherent with actual position deltas across most moves.
    if ((fcs.pointerMoveSamples ?? 0) >= 20 && (fcs.pointerMoveZeroRatio ?? 0) > 0.9) {
      detections.push({
        category: 'cdp', score: 0.6, confidence: 0.5,
        reason: 'Pointer movement deltas incoherent with position (synthetic input)'
      });
    }
  }

  // CDP Runtime/DevTools console consumer attached. Low confidence: a developer
  // with DevTools open also trips this, so it contributes rather than blocks.
  if (env.cdpRuntime && env.cdpRuntime.consoleAttached) {
    detections.push({
      category: 'cdp', score: 0.6, confidence: 0.5,
      reason: 'CDP/DevTools console consumer attached (automation protocol or open DevTools)'
    });
  }

  if (cdp.detected) {
    const signalList = cdp.signals || [];
    const signalCount = signalList.length;

    // High-confidence signals
    const highConfSignals = ['chromedriver_cdc', 'puppeteer_eval', 'cdp_script_injection'];
    const hasHighConf = signalList.some(s => highConfSignals.includes(s));

    if (hasHighConf) {
      detections.push({
        category: 'cdp',
        score: 0.9,
        confidence: 0.95,
        dispositive: true, // driver-injected globals — see DISPOSITIVE_FLOOR
        reason: `CDP automation detected: ${signalList.join(', ')}`
      });
    } else if (signalCount >= 2) {
      detections.push({
        category: 'cdp',
        score: 0.8,
        confidence: 0.85,
        reason: `Multiple CDP indicators: ${signalList.join(', ')}`
      });
    } else if (signalCount === 1) {
      detections.push({
        category: 'cdp',
        score: 0.6,
        confidence: 0.7,
        reason: `CDP indicator: ${signalList.join(', ')}`
      });
    }
  }

  return detections;
}

function detectBehavioral(signals) {
  const detections = [];
  const b = signals.behavioral || {};
  const t = signals.temporal || {};

  // Insufficient mouse data - critical check for zero-click bots
  // Exempt: touch users (mobile) and keyboard-only users (accessibility)
  const totalPoints = b.totalPoints ?? 0;
  const trajectory = b.trajectoryLength ?? 0;
  const touchEvts = b.touchEvents ?? 0;
  const keyEvts = b.keyEvents ?? 0;
  const isTouchUsr = isTouchModality(b);
  const isKbdUser = keyEvts >= 2 && totalPoints === 0;

  if (totalPoints === 0 && !isTouchUsr && !isKbdUser) {
    detections.push({
      category: 'behavioral', score: 0.8, confidence: 0.9,
      reason: 'Zero mouse, touch, or keyboard events recorded'
    });
  } else if (totalPoints < 10 && !isTouchUsr && !isKbdUser && trajectory < 30) {
    detections.push({
      category: 'behavioral', score: 0.6, confidence: 0.7,
      reason: 'Insufficient mouse movement before interaction'
    });
  }

  // Velocity variance
  const velVar = b.velocityVariance ?? 1;
  if (velVar < 0.02 && trajectory > 50 && !hasHumanMovementMarkers(b)) {
    detections.push({
      category: 'behavioral', score: 0.6, confidence: 0.6,
      reason: 'Mouse velocity too consistent'
    });
  }

  const isWidgetInt = hasWidgetInteraction(signals);

  // Overshoot. Click-derived, so widget-only.
  const overshoots = b.overshootCorrections ?? 0;
  if (isWidgetInt && overshoots === 0 && trajectory > 200) {
    detections.push({
      category: 'behavioral', score: 0.4, confidence: 0.4,
      reason: 'No overshoot corrections on long trajectory'
    });
  }

  // Interaction speed. Widget mode measures time spent solving; invisible mode
  // reuses the same field for time on page, where a minute is just a reader.
  const interactionTime = b.interactionDuration ?? 1000;
  if (interactionTime > 0 && interactionTime < 200) {
    detections.push({
      category: 'behavioral', score: 0.7, confidence: 0.7,
      reason: 'Interaction completed too quickly'
    });
  } else if (isWidgetInt && interactionTime > 60000) {
    detections.push({
      category: 'captcha_farm', score: 0.3, confidence: 0.3,
      reason: 'Unusually long interaction time'
    });
  }

  // First interaction
  const firstInt = t.pageLoadToFirstInteraction;
  if (firstInt !== null && firstInt > 0 && firstInt < 100) {
    detections.push({
      category: 'behavioral', score: 0.5, confidence: 0.5,
      reason: 'First interaction too soon after page load'
    });
  }

  // Mouse event rate
  const eventRate = b.mouseEventRate ?? 60;
  if (eventRate > 200) {
    detections.push({
      category: 'behavioral', score: 0.6, confidence: 0.5,
      reason: 'Mouse event rate abnormally high'
    });
  } else if (eventRate > 0 && eventRate < 10 && !hasHumanMovementMarkers(b)) {
    detections.push({
      category: 'behavioral', score: 0.4, confidence: 0.4,
      reason: 'Mouse event rate abnormally low'
    });
  }

  // Straight line ratio
  const straight = b.straightLineRatio ?? 0;
  if (straight > 0.8 && trajectory > 100) {
    detections.push({
      category: 'behavioral', score: 0.5, confidence: 0.5,
      reason: 'Mouse movements too straight'
    });
  }

  // Direction changes
  const dirChanges = b.directionChanges ?? 10;
  if (totalPoints > 50 && dirChanges < 3) {
    detections.push({
      category: 'behavioral', score: 0.4, confidence: 0.4,
      reason: 'Too few direction changes'
    });
  }

  return detections;
}

// =============================================================================
// Mobile-native detectors (touch authenticity, sensor entropy, touch kinematics)
// UA-gated on mobile. Non-mobile UAs: no-op. Designed to never penalize iOS
// Safari without permission (absence of motion events treated as neutral).
// =============================================================================

function _isMobileUA(userAgent) {
  const ua = (userAgent || '').toLowerCase();
  return /mobile|android|iphone|ipad|ipod/.test(ua);
}

function detectTouchAuthenticity(signals, userAgent) {
  const detections = [];
  if (!_isMobileUA(userAgent)) return detections;

  const b = signals.behavioral || {};
  const touchPoints = b.touchTotalPoints ?? b.touchEvents ?? 0;
  if (touchPoints < 3) return detections;

  const forceVariance = b.touchForceVariance ?? 0;
  const radiusVariance = b.touchRadiusVariance ?? 0;
  const forceAllOne = b.touchForceAllOne === true;
  const uniqueIds = b.touchUniqueIdentifiers ?? 0;
  const forceMax = b.touchForceMax ?? 0;
  const radiusMax = b.touchRadiusMax ?? 0;

  // Uniform non-zero force across all events → synthetic injection.
  // Older Android returning all-zero is legitimate — only penalize uniformity
  // when max > 0.
  if (forceVariance === 0 && forceMax > 0 && touchPoints >= 5) {
    detections.push({
      category: 'behavioral', score: 0.75, confidence: 0.85,
      reason: 'Touch force is identical across all events (synthetic touch)'
    });
  }

  // All force=1 exactly is a common synthetic default in automation frameworks.
  if (forceAllOne && touchPoints >= 5) {
    detections.push({
      category: 'behavioral', score: 0.8, confidence: 0.9,
      reason: 'All touches report force=1.0 exactly (synthetic pattern)'
    });
  }

  // Uniform contact radius across many events is unusual on real phones.
  if (radiusVariance === 0 && radiusMax > 0 && touchPoints >= 5) {
    detections.push({
      category: 'behavioral', score: 0.7, confidence: 0.8,
      reason: 'Touch contact radius identical across all events'
    });
  }

  // Mobile UA with real touches but zero unique identifiers — framework default.
  if (touchPoints >= 5 && uniqueIds === 0) {
    detections.push({
      category: 'behavioral', score: 0.6, confidence: 0.7,
      reason: 'Mobile touches lack identifier tracking (synthetic injection)'
    });
  }

  return detections;
}

function detectSensorEntropy(signals, userAgent) {
  const detections = [];
  if (!_isMobileUA(userAgent)) return detections;

  const env = signals.environmental || {};
  const sensor = env.sensor || {};
  const motionCount = sensor.motionEventCount ?? 0;
  const motionVariance = sensor.motionAccelVariance ?? 0;
  const orientationCount = sensor.orientationEventCount ?? 0;
  const orientationVariance = sensor.orientationVariance ?? 0;

  // Sensor events fired but completely flat → emulator / headless mobile.
  if (motionCount >= 10 && motionVariance < 0.01) {
    detections.push({
      category: 'headless', score: 0.7, confidence: 0.8,
      reason: `Motion sensor active but flat (variance=${motionVariance.toFixed(4)}) — likely emulator`
    });
  }

  if (orientationCount >= 10 && orientationVariance < 0.01) {
    detections.push({
      category: 'headless', score: 0.6, confidence: 0.7,
      reason: 'Orientation sensor active but completely flat — likely emulator'
    });
  }

  // motionCount == 0 is NEUTRAL (iOS w/o permission is the common case).

  return detections;
}

function detectTouchKinematics(signals) {
  const detections = [];
  const b = signals.behavioral || {};
  const touchPoints = b.touchTotalPoints ?? 0;
  if (touchPoints < 10) return detections;

  const straightLine = b.touchStraightLineRatio ?? 0;
  const tremor = b.touchMicroTremorScore ?? 0;
  const dirChanges = b.touchDirectionChanges ?? 0;

  if (straightLine > 0.85 && touchPoints >= 20) {
    detections.push({
      category: 'behavioral', score: 0.65, confidence: 0.75,
      reason: `Touch path too straight (ratio=${straightLine.toFixed(2)}) — automation pattern`
    });
  }

  if (tremor < 0.05 && touchPoints >= 30) {
    detections.push({
      category: 'behavioral', score: 0.55, confidence: 0.65,
      reason: 'Touch path has no micro-tremor (unnaturally smooth)'
    });
  }

  if (dirChanges === 0 && touchPoints >= 30) {
    detections.push({
      category: 'behavioral', score: 0.5, confidence: 0.6,
      reason: 'Touch path has zero direction changes over long trajectory'
    });
  }

  return detections;
}

// =============================================================================
// Scoring
// =============================================================================

/**
 * Combines the detections within each category into a category score.
 *
 * ## Why this is not a mean
 *
 * It used to be a confidence-weighted mean, which had a property nobody
 * intended: corroborating evidence *lowered* the verdict. A visitor whose
 * browser reported `navigator.webdriver === true` and nothing else scored 0.95
 * in the headless category. The same visitor, additionally caught with no
 * plugins, a software renderer, a viewport equal to its window and three more
 * automation tells, scored 0.686 — because each additional signal, being
 * individually weaker than the first, pulled the average down. Seven pieces of
 * corroboration made the case weaker than one.
 *
 * Noisy-OR fixes that. Each detection is treated as independent evidence of
 * strength `score × confidence`, and the category is the probability that at
 * least one of them is right:
 *
 *     category = 1 - ∏(1 - scoreᵢ × confidenceᵢ)
 *
 * Evidence now accumulates: adding a signal can only raise a category, never
 * lower it. And it is *more* forgiving of isolated weak evidence than the mean
 * was — one detection at score 0.4, confidence 0.5 contributes 0.20 rather than
 * setting the whole category to 0.40 — which is the right treatment for a
 * lone low-confidence hit on a real user.
 *
 * Measured on the bench corpus (bench/tools/compare-aggregation.js): human
 * median 0.182 → 0.097 and human max 0.260 → 0.171, while agent median rose
 * 0.517 → 0.570. Both populations moved in the direction they should.
 */
// weights is a parameter because ScoringEngine accepts `options.weights`. It
// only decides which categories get filled in at zero; the per-category
// aggregation below is weight-independent.
function calculateCategoryScores(detections, weights = WEIGHTS) {
  const categoryData = {};

  for (const d of detections) {
    if (!categoryData[d.category]) {
      categoryData[d.category] = [];
    }
    categoryData[d.category].push([d.score, d.confidence]);
  }

  const result = {};
  for (const [cat, scores] of Object.entries(categoryData)) {
    if (scores.length > 0) {
      let survives = 1;
      for (const [score, conf] of scores) {
        const strength = Math.max(0, Math.min(1, score * conf));
        survives *= 1 - strength;
      }
      result[cat] = Math.min(1.0, 1 - survives);
    }
  }

  // Fill missing
  for (const cat of Object.keys(weights)) {
    if (!(cat in result)) {
      result[cat] = 0.0;
    }
  }

  return result;
}

function calculateFinalScore(categoryScores, weights = WEIGHTS) {
  let total = 0;
  for (const [cat, weight] of Object.entries(weights)) {
    total += (categoryScores[cat] || 0) * weight;
  }
  return Math.min(1.0, total);
}

/**
 * Score below which a self-declared automated browser cannot fall.
 *
 * ## Why a floor exists at all
 *
 * The final score is a weighted sum across all eleven categories, so a category
 * can contribute at most its own weight no matter how certain it is. A local
 * automated browser trips at most the six categories reachable without a
 * datacenter IP, a reused fingerprint or a rate-limit hit — about 0.81 of the
 * weight — and in practice lands near 0.5. The bench measured exactly that: a
 * Playwright browser reporting `navigator.webdriver === true`, no plugins, a
 * software renderer and four more automation tells scored 0.549, i.e.
 * "challenge", not "block".
 *
 * That is the weighted sum working as designed. It expresses "what fraction of
 * the total suspicion budget did this visitor consume", and no single fact can
 * consume most of that budget. The trouble is that some facts are not
 * probabilistic evidence at all — they are the browser saying so.
 *
 * ## What qualifies
 *
 * Only detections marked `dispositive`, and the bar for that mark is that a
 * browser cannot produce the signal without being automated:
 *
 *   - `navigator.webdriver === true` — a W3C-specified flag whose sole purpose
 *     is to tell the page it is under automation.
 *   - ChromeDriver / Puppeteer injected globals (`chromedriver_cdc`,
 *     `puppeteer_eval`, `cdp_script_injection`), which exist in no ordinary
 *     browsing session.
 *
 * Deliberately excluded, though both look tempting: the "console consumer
 * attached" CDP check, because the bench human panel proves it fires on a
 * developer with DevTools open; and the Playwright `webdriver_configurable`
 * artifact, which relies on a property-descriptor detail no specification
 * guarantees.
 *
 * ## What this does not do
 *
 * It does not catch a stealth agent, which patches `navigator.webdriver` before
 * the page ever sees it. That is not a regression — such an agent scores the
 * same as it did before — and it is the reason the behavioural workstreams
 * still matter. The floor closes the case where an agent is not even trying to
 * hide, which was previously being waved through with a "challenge".
 */
const DISPOSITIVE_FLOOR = 0.9;

function applyDispositiveFloor(score, detections) {
  const selfDeclared = detections.some((d) => d.dispositive === true);
  return selfDeclared ? Math.max(score, DISPOSITIVE_FLOOR) : score;
}

/**
 * Behavioural corroboration floor.
 *
 * A source-patched browser scrubs every JS-observable automation flag at the binary
 * level, so it trips no headless, cdp, fingerprint, datacenter or bot category.
 * Those weights total 0.59, and the weighted sum silently keeps all of it — leaving
 * such a browser a ceiling of 0.41 against a 0.5 threshold. It cannot be blocked
 * however obviously robotic its movement is.
 *
 * Measured, not argued: the corpus sample of that adversary trips seven correct
 * behavioural detections and scores 0.234. Every one fires; the aggregation
 * discards the verdict. Same structural flaw that let a bare curl through before
 * v1.23.0, landing this time on the behavioural detection that is the point of the
 * product. It treats absence of environmental evidence as evidence of absence — but
 * on this adversary a clean environment is the attack working, not innocence.
 *
 * The rule: when two or more behavioural categories independently reach 0.5, floor
 * the score at 0.6.
 *
 * Constants swept over a 40-point grid against the labelled corpus
 * (bench/tools/sweep-corroboration.js), not reasoned about. No human in the
 * 126-sample panel reaches two agreeing behavioural categories at any threshold
 * tested, while 66 of 75 agents do at 0.5. Requiring three fails outright — all
 * sixteen such combinations leave the adversary allowed. The floor value does not
 * affect separation, so 0.6 is a policy choice: the block boundary, kept distinct
 * from the 0.9 reserved for a browser that declares its own automation.
 *
 * Caveat: the adversary is one synthetic, hand-authored sample. This shows the
 * arithmetic works on the shape the corpus describes, not that it works on a real
 * source-patched browser.
 */
const CORROBORATION_AGREE_AT = 0.5;
const CORROBORATION_MIN_AGREE = 2;
const CORROBORATION_FLOOR = 0.6;

// Categories a browser trips by how it moves rather than by what it is. A
// patched binary can hide what it is; it cannot hide that nothing is moving the
// pointer like a hand.
const BEHAVIOURAL_CATEGORIES = ['vision_ai', 'behavioral', 'automation', 'cdp'];

function applyCorroborationFloor(score, categoryScores) {
  const agreeing = BEHAVIOURAL_CATEGORIES
    .filter((c) => (categoryScores[c] || 0) >= CORROBORATION_AGREE_AT).length;
  return agreeing >= CORROBORATION_MIN_AGREE ? Math.max(score, CORROBORATION_FLOOR) : score;
}

module.exports = {
  // Constants
  AUTOMATION_UA_PATTERNS,
  WEIGHTS,
  DISPOSITIVE_FLOOR,
  CORROBORATION_AGREE_AT,
  CORROBORATION_MIN_AGREE,
  CORROBORATION_FLOOR,
  BEHAVIOURAL_CATEGORIES,

  // Helpers
  hasHumanMovementMarkers,
  isTouchModality,
  getNestedValue,

  // Interaction mode (set from the endpoint, never from client signals)
  setInteractionMode,
  hasWidgetInteraction,

  // Pure detectors
  detectVisionAI,
  detectHeadless,
  detectStealthArtifacts,
  detectAutomation,
  detectCDP,
  detectBehavioral,
  detectTouchAuthenticity,
  detectSensorEntropy,
  detectTouchKinematics,

  // Aggregation
  calculateCategoryScores,
  calculateFinalScore,
  applyDispositiveFloor,
  applyCorroborationFloor,
};
