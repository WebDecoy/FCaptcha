/**
 * FCaptcha Server - Node.js/Express Implementation
 *
 * Run: node server.js
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const detection = require('./detection');
const webbotauth = require('./webbotauth');
const { ProxyTrust } = require('./clientip');
const { BoundedMap, BoundedSet, SiteKeyGuard } = require('./limits');
const { SuspicionLedger, computeChallengeCost, BASE_MIN_AGE_MS } = require('./suspicion');
const { detectInputForensics } = require('./inputforensics');
const {
  ERROR_CODES,
  HostnameAllowlist,
  IdempotencyStore,
  requestHostname,
  sanitizeAction,
  sanitizeCdata,
  secretMatches,
  siteverify
} = require('./siteverify');

const app = express();
app.use(cors());
app.use(express.json());
// The siteverify contract accepts form-encoded bodies as well as JSON, and most
// PHP and Python integrations in the wild post form-encoded. Parsing both here
// costs nothing on the JSON path.
app.use(express.urlencoded({ extended: false }));

const SECRET_KEY = process.env.FCAPTCHA_SECRET || 'dev-secret-change-in-production';

// The credential a backend presents to validate a token. Defaults to the signing
// key, which is what the README has always documented, but can be separated:
// the signing key is a long-lived secret that must never leave the server, while
// this one is handed to every backend that verifies. Splitting them means a
// leaked verify credential does not let the holder mint tokens.
const VERIFY_SECRET = process.env.FCAPTCHA_VERIFY_SECRET || SECRET_KEY;

// Token verification used to accept anyone who could reach the endpoint: all
// three servers read `secret` out of the body and dropped it. Enforcing it is a
// breaking change for deployments that never sent one, so there is one release
// of escape hatch before the parameter becomes mandatory outright.
const LEGACY_UNAUTH_VERIFY = /^(1|true|yes|on)$/i.test(
  process.env.FCAPTCHA_LEGACY_UNAUTH_VERIFY || ''
);

// Optional: restrict which page origins may mint tokens. Off by default so
// zero-config self-hosting keeps working. See siteverify.js.
const ALLOWED_HOSTNAMES = HostnameAllowlist.fromEnv();

// Lets a caller retry a validation that timed out without burning the token.
const IDEMPOTENCY = new IdempotencyStore();

const PORT = process.env.PORT || 3000;
const TRUSTED_JA4_HEADERS = detection.getTrustedJA4HeaderNames();

// Which peers may speak for another client via X-Forwarded-For / X-Real-IP and
// the TLS-fingerprint headers. See clientip.js.
const PROXY_TRUST = ProxyTrust.fromEnv();

// siteKey is client-supplied and validated against no registry, yet it is the
// first component of every rate-limit, fingerprint and challenge partition key.
// SITE_KEYS bounds how many distinct values one IP may allocate state for. See
// limits.js — the cap is unconditional; FCAPTCHA_SITE_KEYS adds an allowlist.
const SITE_KEYS = SiteKeyGuard.fromEnv();

// Recent strong verdicts per source, used to price the next challenge that
// source asks for. Bounded and short-lived; see suspicion.js.
const suspicionLedger = new SuspicionLedger();

// Express's own `trust proxy` would re-derive req.ip from the same headers on
// its own terms; IP resolution goes through PROXY_TRUST.clientIP exclusively.
app.set('trust proxy', false);

// Verdict logging is off by default: a self-hosted FCaptcha emits no per-request
// logs unless the operator opts in via FCAPTCHA_LOG_VERDICTS (1/true/yes/on).
// When on, each /api/verify and /api/score logs one privacy-safe JSON line
// (score, recommendation, category scores, and per-hit category/score/confidence)
// for observability and tuning. It deliberately omits IP, user agent, raw
// signals, and the free-text detection `reason`, which can interpolate
// visitor-derived data (reverse-DNS hostname, UA/header fragments, field ids).
//
// FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW additionally includes that free-text reason.
// Separate and off by default because reasons can carry visitor-derived data —
// only enable in trusted debugging contexts with no privacy obligations.
const envFlag = (name) => ['1', 'true', 'yes', 'on']
  .includes(String(process.env[name] || '').trim().toLowerCase());
const VERDICT_LOGGING_ENABLED = envFlag('FCAPTCHA_LOG_VERDICTS');
const VERDICT_LOG_INCLUDE_RAW = envFlag('FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW');
if (VERDICT_LOGGING_ENABLED && VERDICT_LOG_INCLUDE_RAW) {
  console.warn('WARNING: FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW enabled — verdict logs include free-text detection reasons that may contain visitor-derived data (hostnames, UA/header fragments, field ids). Do not enable where you have privacy obligations.');
}

function logVerdict(endpoint, siteKey, result) {
  if (!VERDICT_LOGGING_ENABLED || !result) return;
  console.log(JSON.stringify({
    event: 'verdict',
    endpoint,
    siteKey,
    success: result.success,
    score: result.score,
    recommendation: result.recommendation,
    categoryScores: result.categoryScores,
    detections: (result.detections || []).map((d) => {
      const det = { category: d.category, score: d.score, confidence: d.confidence };
      if (VERDICT_LOG_INCLUDE_RAW) det.reason = d.reason;
      return det;
    })
  }));
}

// Serve the browser widget alongside the API so deployments expose a single
// origin to integrators (the implicit contract behind <serverUrl>/fcaptcha.js).
// Set FCAPTCHA_SERVE_CLIENT=false to opt out — useful when hosting the widget
// on a separate CDN / edge cache. Set FCAPTCHA_CLIENT_PATH=/abs/path/fcaptcha.js
// to override the default lookup when server-node is deployed standalone.
const CLIENT_PATH = process.env.FCAPTCHA_CLIENT_PATH
  || path.join(__dirname, '..', 'client', 'fcaptcha.js');

if (process.env.FCAPTCHA_SERVE_CLIENT !== 'false') {
  app.get('/fcaptcha.js', (req, res) => {
    res.sendFile(CLIENT_PATH);
  });
}

// =============================================================================
// In-Memory Storage (Use Redis in production)
// =============================================================================

// PoW Challenge Store
const powChallengeStore = {
  challenges: new BoundedMap(),
  usedSolutions: new BoundedSet(),

  // Generate a new challenge
  generate(siteKey, ip, difficulty = 4, minAgeMs = BASE_MIN_AGE_MS) {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const expiresAt = timestamp + (5 * 60 * 1000); // 5 minutes

    // Challenge data to be signed
    const challengeData = {
      id: challengeId,
      siteKey,
      timestamp,
      expiresAt,
      difficulty,
      // How long the client must hold this challenge before submitting a
      // solution. Inside the signed payload so it cannot be talked down.
      minAgeMs,
      nonce,
      prefix: `${challengeId}:${timestamp}:${difficulty}`
    };

    // Sign the challenge
    challengeData.sig = crypto.createHmac('sha256', SECRET_KEY)
      .update(JSON.stringify(challengeData))
      .digest('hex');

    // Store challenge
    this.challenges.set(challengeId, {
      ...challengeData,
      ip,
      createdAt: timestamp
    });

    // Cleanup old challenges periodically
    if (Math.random() < 0.1) this._cleanup();

    return challengeData;
  },

  // Verify a PoW solution (signalsHash is optional for backward compat)
  verify(challengeId, nonce, hash, siteKey, signalsHash = null) {
    const challenge = this.challenges.get(challengeId);

    if (!challenge) {
      return { valid: false, reason: 'challenge_not_found' };
    }

    if (Date.now() > challenge.expiresAt) {
      this.challenges.delete(challengeId);
      return { valid: false, reason: 'challenge_expired' };
    }

    if (challenge.siteKey !== siteKey) {
      return { valid: false, reason: 'site_key_mismatch' };
    }

    // Check if solution was already used (prevent replay)
    const solutionKey = `${challengeId}:${nonce}`;
    if (this.usedSolutions.has(solutionKey)) {
      return { valid: false, reason: 'solution_already_used' };
    }

    // Verify the hash (with optional signalsHash binding)
    const input = signalsHash
      ? `${challenge.prefix}:${signalsHash}:${nonce}`
      : `${challenge.prefix}:${nonce}`;
    const expectedHash = crypto.createHash('sha256').update(input).digest('hex');

    if (hash !== expectedHash) {
      return { valid: false, reason: 'invalid_hash' };
    }

    // Check difficulty (hash must start with N zeros)
    const target = '0'.repeat(challenge.difficulty);
    if (!hash.startsWith(target)) {
      return { valid: false, reason: 'insufficient_difficulty' };
    }

    // Mark solution as used
    this.usedSolutions.add(solutionKey);

    // Delete challenge (one-time use)
    this.challenges.delete(challengeId);

    // Calculate server-side elapsed time (un-spoofable)
    const serverElapsed = Date.now() - challenge.createdAt;

    return {
      valid: true,
      difficulty: challenge.difficulty,
      serverElapsed,
      nonce: challenge.nonce,
      // Fall back for challenges issued before adaptive cost existed.
      minAgeMs: challenge.minAgeMs || BASE_MIN_AGE_MS
    };
  },

  _cleanup() {
    const now = Date.now();
    this.challenges.prune((challenge) => now <= challenge.expiresAt);
    // usedSolutions is a BoundedSet: it evicts its own oldest entries as it
    // fills. The previous code cleared the whole replay guard once it passed a
    // threshold, which an attacker could force in order to replay a solution.
  }
};

const rateLimiter = {
  requests: new BoundedMap(),

  check(key, windowSeconds = 60, maxRequests = 10) {
    const now = Date.now();
    const cutoff = now - (windowSeconds * 1000);

    let timestamps = this.requests.get(key) || [];
    timestamps = timestamps.filter(t => t > cutoff);

    const count = timestamps.length;
    if (count >= maxRequests) {
      return [true, count];
    }

    timestamps.push(now);
    this.requests.set(key, timestamps);
    return [false, count + 1];
  }
};

const fingerprintStore = {
  fingerprints: new BoundedMap(),
  ipFingerprints: new BoundedMap(),

  record(fp, ip, siteKey) {
    const key = `${siteKey}:${fp}`;

    if (!this.fingerprints.has(key)) {
      this.fingerprints.set(key, { count: 0, ips: new Set() });
    }
    const data = this.fingerprints.get(key);
    data.count++;
    data.ips.add(ip);

    if (!this.ipFingerprints.has(ip)) {
      this.ipFingerprints.set(ip, new Set());
    }
    this.ipFingerprints.get(ip).add(fp);
  },

  getIpFpCount(ip) {
    return this.ipFingerprints.get(ip)?.size || 0;
  },

  getFpIpCount(fp, siteKey) {
    const key = `${siteKey}:${fp}`;
    return this.fingerprints.get(key)?.ips.size || 0;
  }
};

// Token Store - prevents token replay attacks
const tokenStore = {
  usedTokens: new BoundedSet(),

  // Mark a token as used (returns false if already used)
  markUsed(tokenSig) {
    if (this.usedTokens.has(tokenSig)) {
      return false; // Already used
    }
    this.usedTokens.add(tokenSig);

    // Cleanup old tokens periodically (tokens expire after 5 min anyway)
    if (Math.random() < 0.1) this._cleanup();
    return true;
  },

  isUsed(tokenSig) {
    return this.usedTokens.has(tokenSig);
  },

  _cleanup() {
    // In production with Redis, use TTL instead. In memory usedTokens is a
    // BoundedSet, so it evicts its oldest entries rather than clearing wholesale
    // — clearing would let an attacker who forced the threshold replay a token.
  }
};

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

function isTouchModality(b) {
  const touchEvents = b.touchEvents ?? 0;
  const touchPoints = b.touchTotalPoints ?? 0;
  return touchEvents >= 3 || ((touchEvents >= 1 || touchPoints >= 1) && b.pointerHasNonMouseType === true);
}

function getNestedValue(obj, ...keys) {
  return keys.reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);
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

  if (totalPoints < 5 && trajectory < 10 && !isTouchUser && !isKeyboardUser) {
    detections.push({
      category: 'vision_ai', score: 0.9, confidence: 0.85,
      reason: 'No mouse movement detected before click (AI agent pattern)'
    });
  }

  if (approachPts === 0 && !isTouchUser && !isKeyboardUser) {
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

  // Exploration
  const exploration = b.explorationRatio ?? 0.3;
  if (exploration < 0.05 && trajectory > 50) {
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

  // Overshoot
  const overshoots = b.overshootCorrections ?? 0;
  if (overshoots === 0 && trajectory > 200) {
    detections.push({
      category: 'behavioral', score: 0.4, confidence: 0.4,
      reason: 'No overshoot corrections on long trajectory'
    });
  }

  // Interaction speed
  const interactionTime = b.interactionDuration ?? 1000;
  if (interactionTime > 0 && interactionTime < 200) {
    detections.push({
      category: 'behavioral', score: 0.7, confidence: 0.7,
      reason: 'Interaction completed too quickly'
    });
  } else if (interactionTime > 60000) {
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

function detectFingerprint(signals, ip, siteKey) {
  const detections = [];
  const env = signals.environmental || {};
  const automation = env.automationFlags || {};

  // Generate fingerprint
  const components = [
    String(getNestedValue(env, 'canvasHash', 'hash') || ''),
    String(getNestedValue(env, 'webglInfo', 'renderer') || ''),
    String(automation.platform || ''),
    String(automation.hardwareConcurrency || '')
  ];
  const fp = crypto.createHash('sha256').update(components.join('|')).digest('hex').slice(0, 16);

  fingerprintStore.record(fp, ip, siteKey);

  // IP fingerprint count
  const ipFpCount = fingerprintStore.getIpFpCount(ip);
  if (ipFpCount > 5) {
    detections.push({
      category: 'fingerprint', score: 0.6, confidence: 0.6,
      reason: 'IP has used many different fingerprints'
    });
  }

  // Fingerprint IP count
  const fpIpCount = fingerprintStore.getFpIpCount(fp, siteKey);
  if (fpIpCount > 10) {
    detections.push({
      category: 'fingerprint', score: 0.5, confidence: 0.5,
      reason: 'Fingerprint seen from many IPs'
    });
  }

  // Canvas issues
  const canvas = env.canvasHash || {};
  if (canvas.error || canvas.supported === false) {
    detections.push({
      category: 'fingerprint', score: 0.4, confidence: 0.4,
      reason: 'Canvas fingerprinting blocked or failed'
    });
  }

  return detections;
}

function detectRateAbuse(ip, siteKey) {
  const detections = [];
  const key = `${siteKey}:${ip}`;

  const [exceeded, count] = rateLimiter.check(key, 60, 10);
  if (exceeded) {
    detections.push({
      category: 'rate_limit', score: 0.8, confidence: 0.9,
      reason: 'Rate limit exceeded'
    });
  } else if (count > 5) {
    detections.push({
      category: 'rate_limit', score: 0.3, confidence: 0.5,
      reason: 'High request rate'
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
function calculateCategoryScores(detections) {
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
  for (const cat of Object.keys(WEIGHTS)) {
    if (!(cat in result)) {
      result[cat] = 0.0;
    }
  }

  return result;
}

function calculateFinalScore(categoryScores) {
  let total = 0;
  for (const [cat, weight] of Object.entries(WEIGHTS)) {
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

// Bind the token to the page that minted it and to the action it was minted
// for. All three ride inside the signed payload, so a token issued for
// `action=login` on example.com cannot be replayed against a password-reset
// endpoint or presented from a site that lifted the key — the backend compares
// what siteverify reports against what it expected.
//
// Empty strings rather than omitted keys: the signing payload is a sorted-key
// JSON serialisation, so a token whose key set varies with what the browser
// happened to send would be a second payload shape to keep in sync across three
// languages. Fixed shape, empty when unknown.
function generateToken(ip, siteKey, score, binding = {}) {
  const ipHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 8);
  const data = {
    site_key: siteKey,
    timestamp: Math.floor(Date.now() / 1000),
    score: Math.round(score * 1000) / 1000,
    ip_hash: ipHash,
    hostname: binding.hostname || '',
    action: binding.action || '',
    cdata: binding.cdata || ''
  };

  const payload = JSON.stringify(data, Object.keys(data).sort());
  data.sig = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('hex');

  return Buffer.from(JSON.stringify(data)).toString('base64url');
}

function verifyToken(token, ip = null) {
  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64url').toString());

    // Check expiration
    if (Date.now() / 1000 - decoded.timestamp > 300) {
      return { valid: false, reason: 'expired' };
    }

    const sig = decoded.sig;
    delete decoded.sig;

    const payload = JSON.stringify(decoded, Object.keys(decoded).sort());
    const expectedSig = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
      return { valid: false, reason: 'invalid_signature' };
    }

    // Check for token replay (single-use tokens)
    if (tokenStore.isUsed(sig)) {
      return { valid: false, reason: 'token_already_used' };
    }

    // Verify IP matches (if provided)
    if (ip) {
      const expectedIpHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 8);
      if (decoded.ip_hash !== expectedIpHash) {
        return { valid: false, reason: 'ip_mismatch' };
      }
    }

    // Mark token as used (prevents replay)
    tokenStore.markUsed(sig);

    // hostname/action/cdata default to '' so a token minted before they existed
    // still verifies and reports the same shape. The signature covers whatever
    // keys the token actually carries, so old four-key tokens validate
    // unchanged — this is additive, not a format break.
    return {
      valid: true,
      site_key: decoded.site_key,
      timestamp: decoded.timestamp,
      score: decoded.score,
      ip_hash: decoded.ip_hash,
      hostname: decoded.hostname || '',
      action: decoded.action || '',
      cdata: decoded.cdata || ''
    };
  } catch (e) {
    return { valid: false, reason: e.message };
  }
}

// verifyWebBotAuth runs Web Bot Auth verification and never throws into the
// request path: any unexpected error degrades to no detection (fail open), so a
// verification bug can't turn a scoring request into a 500.
async function verifyWebBotAuth(req) {
  try {
    return await webbotauth.checkWebBotAuth(req);
  } catch (e) {
    console.error('[webbotauth] verification error:', e && e.message);
    return [];
  }
}

// preDetections are detections computed by the caller (the route handler) that
// require the raw request — currently Web Bot Auth signature verification, which
// needs the accurately-reconstructed signed request. They are seeded into the
// detection set so they participate in scoring like any other detection.
function runVerification(signals, ip, siteKey, userAgent, headers = {}, ja3Hash = null, powSolution = null, signalsJson = null, powTiming = null, preDetections = [], opts = {}) {
  const detections = Array.isArray(preDetections) ? [...preDetections] : [];

  // Verify signal commitment (signalsJson hash must match powSolution.signalsHash)
  const clientSignalsHash = powSolution?.signalsHash || null;
  if (signalsJson && clientSignalsHash) {
    const computedHash = crypto.createHash('sha256').update(signalsJson).digest('hex');
    if (computedHash !== clientSignalsHash) {
      detections.push({
        category: 'bot',
        score: 0.95,
        confidence: 0.95,
        reason: 'Signals tampered after PoW (signalsHash mismatch)'
      });
    }
    // Use signalsJson as the canonical signals source
    try {
      signals = JSON.parse(signalsJson);
    } catch (e) {
      // Fall back to parsed signals if signalsJson is invalid
    }
  }

  // Inject powTiming into signals.temporal.pow for detection functions
  if (powTiming) {
    if (!signals.temporal) signals.temporal = {};
    signals.temporal.pow = powTiming;
  }

  // Verify PoW if provided
  let powValid = false;
  // powSatisfied records whether the caller actually completed the challenge
  // this server issued. It gates token issuance below rather than only feeding
  // the score, because a proof of work is a precondition, not evidence: the
  // widget solves one on every path and aborts rather than submit without it,
  // so a request that arrives without a valid solution did not come from the
  // widget at all.
  //
  // Scoring it alone was not enough. The final score is a weighted sum, so the
  // bot category contributes at most its 0.13 weight — every PoW failure firing
  // at once reached 0.1298 against a 0.5 threshold, and a bare `curl` with no
  // solution and no signals was issued a valid token. The detections were all
  // correct; the aggregation discarded them.
  let powSatisfied = false;
  let powVerification = null;
  if (powSolution && powSolution.challengeId) {
    powVerification = powChallengeStore.verify(
      powSolution.challengeId,
      powSolution.nonce,
      powSolution.hash,
      siteKey,
      clientSignalsHash
    );
    powValid = powVerification.valid;

    if (!powValid) {
      detections.push({
        category: 'bot',
        score: 0.7,
        confidence: 0.8,
        reason: `PoW verification failed: ${powVerification.reason}`,
        // A solution that does not verify against a challenge this server
        // issued is not weak evidence of automation, it is proof the challenge
        // was not completed. See DISPOSITIVE_FLOOR.
        dispositive: true
      });
    } else {
      powSatisfied = true;
    }

    // Verify challenge nonce binding
    if (powValid && powVerification.nonce) {
      const clientNonce = signals.meta?.challengeNonce;
      if (!clientNonce || clientNonce !== powVerification.nonce) {
        // The solution verifies but the signals it commits to are not the ones
        // presented, so the work was done for a different payload. Revokes the
        // pass granted above.
        powSatisfied = false;
        detections.push({
          category: 'bot',
          score: 0.9,
          confidence: 0.9,
          reason: 'Challenge nonce mismatch (signals not bound to challenge)',
          dispositive: true
        });
      }
    }

    // Server-side timing, the one cost an attacker cannot buy their way out
    // of. Two thresholds, because they mean different things.
    if (powValid && powVerification.serverElapsed < BASE_MIN_AGE_MS) {
      // Under the universal baseline nothing legitimate can have happened.
      detections.push({
        category: 'bot',
        score: 0.8,
        confidence: 0.85,
        reason: `Challenge solved too fast (${powVerification.serverElapsed}ms server-side)`
      });
    } else if (powValid && powVerification.serverElapsed < (powVerification.minAgeMs || BASE_MIN_AGE_MS)) {
      // Between the baseline and this source's own elevated floor is weaker
      // evidence: a client predating adaptive cost, or one served from a stale
      // cache, does not know to wait. It contributes rather than deciding.
      detections.push({
        category: 'bot',
        score: 0.5,
        confidence: 0.5,
        reason: `Challenge submitted before the required delay for this source (${powVerification.serverElapsed}ms of ${powVerification.minAgeMs}ms)`
      });
    }
  } else {
    // No PoW solution provided - hard fail
    detections.push({
      category: 'bot',
      score: 0.9,
      confidence: 0.95,
      reason: 'No PoW solution provided',
      dispositive: true
    });
  }

  // Run behavioral detectors
  detections.push(
    ...detectVisionAI(signals),
    ...detectHeadless(signals, userAgent),
    ...detectStealthArtifacts(signals),
    ...detectAutomation(signals),
    ...detectCDP(signals),
    ...detectBehavioral(signals),
    // Input forensics v2 (PRD workstream C): typing cadence and modality, the
    // paste-shortcut/platform contradiction, scroll morphology, font coherence.
    ...detectInputForensics(signals),
    ...detectTouchAuthenticity(signals, userAgent),
    ...detectSensorEntropy(signals, userAgent),
    ...detectTouchKinematics(signals),
    ...detectFingerprint(signals, ip, siteKey),
    ...detectRateAbuse(ip, siteKey)
  );

  // Add IP reputation check (async but we'll use sync version for simplicity)
  if (detection.isDatacenterIP(ip)) {
    detections.push({
      category: 'datacenter',
      score: 0.6,
      confidence: 0.8,
      reason: 'Request from known datacenter IP range'
    });
  }

  // Add header analysis
  const headerDetections = detection.analyzeHeaders(headers, { peerTrusted: opts.peerTrusted === true });
  detections.push(...headerDetections);

  // Add browser consistency checks
  const consistencyDetections = detection.checkBrowserConsistency(userAgent, signals);
  detections.push(...consistencyDetections);

  // Flag declared/verified AI agents (self-identifying UA or Web Bot Auth signature)
  detections.push(...detection.checkDeclaredAIAgent(userAgent, headers));

  // Add JA3 fingerprint check (client-supplied — spoofable)
  if (ja3Hash) {
    const ja3Detections = detection.checkJA3Fingerprint(ja3Hash);
    detections.push(...ja3Detections);
  }

  // Add JA4 fingerprint check from trusted proxy headers (un-spoofable by client)
  if (TRUSTED_JA4_HEADERS.length > 0) {
    const ja4 = detection.readJA4FromHeaders(headers, TRUSTED_JA4_HEADERS);
    if (ja4) {
      detections.push(...detection.checkJA4Fingerprint(ja4));
    }
  }

  // Add form interaction analysis (credential stuffing & spam detection)
  const formAnalysis = signals.formAnalysis;
  if (formAnalysis) {
    // A visitor who moved a pointer or touched the screen has shown they are
    // there; that changes how a paste-only form fill should be read.
    const beh = signals.behavioral || {};
    const humanPresent = (beh.totalPoints ?? 0) >= 5 || (beh.touchEvents ?? 0) >= 1;
    const formDetections = detection.analyzeFormInteraction(formAnalysis, { humanPresent });
    detections.push(...formDetections);
  }

  // Add advanced fingerprint detection analysis
  const advancedDetections = detection.analyzeAdvancedSignals(signals, userAgent);
  detections.push(...advancedDetections);

  const categoryScores = calculateCategoryScores(detections);
  const finalScore = applyCorroborationFloor(
    applyDispositiveFloor(calculateFinalScore(categoryScores), detections),
    categoryScores
  );

  let recommendation;
  if (finalScore < 0.3) recommendation = 'allow';
  else if (finalScore < 0.6) recommendation = 'challenge';
  else recommendation = 'block';

  // The hostname comes from the request headers rather than the request body:
  // it is what the browser reported about the page, not what the page claimed
  // about itself.
  const hostname = requestHostname(headers);

  // An unlisted hostname withholds the token but does not touch the score. The
  // visitor is not the problem — a key registered to another site is — so the
  // detection layer has nothing to say about it and the refusal is reported as
  // its own reason rather than smuggled in as a bot verdict.
  const hostnameAllowed = ALLOWED_HOSTNAMES.permits(hostname);

  // Three independent conditions, deliberately not folded into the score.
  //
  // powSatisfied is the one that matters most: a score threshold answers "how
  // suspicious is this visitor", which is the wrong question to ask of someone
  // who never completed the challenge. Gating here means no future reweighting
  // can reopen the bypass, and it holds even if the dispositive floor is
  // lowered or removed.
  const success = finalScore < 0.5 && hostnameAllowed && powSatisfied;

  // Name the failed precondition whenever one fails, not only when the score
  // would otherwise have allowed. Gating it on the score made the PoW case
  // unreachable — a PoW failure is dispositive, so it floors the score at 0.9
  // and the branch never fired — which is exactly the case a caller most needs
  // explained.
  let withheldReason = '';
  if (!powSatisfied) withheldReason = 'pow_not_satisfied';
  else if (!hostnameAllowed) withheldReason = 'hostname_not_allowed';

  const token = success
    ? generateToken(ip, siteKey, finalScore, {
        hostname,
        action: sanitizeAction(opts.action),
        cdata: sanitizeCdata(opts.cdata)
      })
    : null;

  // Feed the ledger so the next challenge this source asks for is priced on
  // what it just did.
  suspicionLedger.record(siteKey, ip, finalScore);

  return {
    success,
    score: finalScore,
    token,
    timestamp: Math.floor(Date.now() / 1000),
    recommendation,
    categoryScores,
    detections,
    ...(withheldReason ? { reason: withheldReason } : {}),
    ...(hostnameAllowed ? {} : { hostname })
  };
}

// =============================================================================
// Routes
// =============================================================================

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// collectHeaders lowercases the request headers for the detectors, dropping the
// TLS-fingerprint headers when the peer is not a proxy we trust. TRUSTED_JA4_HEADERS
// is an allowlist of header *names*, which says nothing about who set them — without
// this gate a client could send cf-ja4 itself and present a clean fingerprint.
function collectHeaders(req) {
  const peerTrusted = PROXY_TRUST.peerTrusted(req);
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const name = key.toLowerCase();
    if (!peerTrusted && TRUSTED_JA4_HEADERS.includes(name)) continue;
    headers[name] = Array.isArray(value) ? value[0] : value;
  }
  return headers;
}

app.post('/api/verify', async (req, res) => {
  const { siteKey: rawSiteKey, signals, powSolution, signalsJson, powTiming, action, cdata } = req.body;
  const ip = PROXY_TRUST.clientIP(req);
  // Bound the state an unvalidated siteKey can allocate (limits.js).
  const siteKey = SITE_KEYS.normalize(rawSiteKey, ip);
  const userAgent = req.headers['user-agent'] || '';
  // Only honoured from a trusted proxy: a client that can state its own TLS
  // fingerprint would just claim a stock Chrome one.
  const ja3Hash = PROXY_TRUST.trustedHeader(req, 'x-ja3-hash') || null;

  // Collect headers for analysis
  const headers = collectHeaders(req);
  const peerTrusted = PROXY_TRUST.peerTrusted(req);

  // Web Bot Auth verification needs the raw request; its verdict is scored.
  const webBotAuth = await verifyWebBotAuth(req);

  const result = runVerification(signals, ip, siteKey, userAgent, headers, ja3Hash, powSolution, signalsJson, powTiming, webBotAuth, { peerTrusted, action, cdata });
  logVerdict('verify', siteKey, result);
  res.json(result);
});

app.post('/api/score', async (req, res) => {
  const { siteKey: rawSiteKey, signals, action, cdata, powSolution, signalsJson, powTiming } = req.body;
  const ip = PROXY_TRUST.clientIP(req);
  const siteKey = SITE_KEYS.normalize(rawSiteKey, ip);
  const userAgent = req.headers['user-agent'] || '';
  const ja3Hash = PROXY_TRUST.trustedHeader(req, 'x-ja3-hash') || null;

  // Use collectHeaders, not a bare copy of req.headers: this endpoint used to
  // build its own map, which skipped the trust gate on the TLS-fingerprint
  // header names and let an untrusted client present its own JA4.
  const headers = collectHeaders(req);
  const peerTrusted = PROXY_TRUST.peerTrusted(req);

  // Web Bot Auth verification needs the raw request; its verdict is scored.
  const webBotAuth = await verifyWebBotAuth(req);

  const result = runVerification(signals, ip, siteKey, userAgent, headers, ja3Hash, powSolution, signalsJson, powTiming, webBotAuth, { peerTrusted, action, cdata });
  logVerdict('score', siteKey, result);
  res.json({
    success: result.success,
    score: result.score,
    token: result.token,
    // Echo the sanitized form, not the raw input: this is what got signed into
    // the token, so a caller comparing the two sees the same value.
    action: sanitizeAction(action),
    cdata: sanitizeCdata(cdata),
    recommendation: result.recommendation,
    // Parity with /api/verify and with the Go server: a caller denied a token
    // needs to know which precondition failed.
    ...(result.reason ? { reason: result.reason } : {})
  });
});

app.post('/api/token/verify', (req, res) => {
  const { token, secret } = req.body;

  // The secret gate. This endpoint is the boundary between "a browser finished a
  // challenge" and "my backend believes it", so it is server-to-server and needs
  // a credential — without one, anyone who can reach the host can spend a token
  // they observed, and the single-use guard then denies the real user.
  if (!LEGACY_UNAUTH_VERIFY) {
    if (!secret) {
      return res.status(401).json({ valid: false, reason: 'missing_secret' });
    }
    if (!secretMatches(secret, VERIFY_SECRET)) {
      return res.status(401).json({ valid: false, reason: 'invalid_secret' });
    }
  }

  // Extract client IP for verification
  const ip = PROXY_TRUST.clientIP(req);

  res.json(verifyToken(token, ip));
});

// Turnstile / reCAPTCHA / hCaptcha drop-in compatibility.
//
// Same contract, three paths, because the path is hardcoded in the SDKs and
// plugins we want to be usable against FCaptcha: pointing an existing
// integration at this server should be a base-URL change and nothing else.
// See siteverify.js for the adapter itself.
function siteverifyHandler(req, res) {
  res.json(
    siteverify({
      body: req.body,
      // Bind to this server's token store, so replay state is shared with the
      // native endpoint rather than kept in a parallel universe.
      verifyToken,
      expectedSecret: VERIFY_SECRET,
      idempotencyStore: IDEMPOTENCY,
      requireSecret: !LEGACY_UNAUTH_VERIFY
    })
  );
}

app.post('/turnstile/v0/siteverify', siteverifyHandler);
app.post('/recaptcha/api/siteverify', siteverifyHandler);
app.post('/siteverify', siteverifyHandler);

// PoW Challenge endpoint - client fetches this on page load
app.get('/api/pow/challenge', (req, res) => {
  const ip = PROXY_TRUST.clientIP(req);
  const siteKey = SITE_KEYS.normalize(req.query.siteKey, ip);

  // Cost scaling. See suspicion.js for why the escalation lands almost
  // entirely on minAgeMs rather than on difficulty.
  const rateKey = `pow:${siteKey}:${ip}`;
  const [exceeded, count] = rateLimiter.check(rateKey, 60, 20);
  const cost = computeChallengeCost(
    suspicionLedger.count(siteKey, ip),
    detection.isDatacenterIP(ip),
    count,
    exceeded
  );

  const challenge = powChallengeStore.generate(siteKey, ip, cost.difficulty, cost.minAgeMs);

  res.json({
    challengeId: challenge.id,
    prefix: challenge.prefix,
    difficulty: challenge.difficulty,
    expiresAt: challenge.expiresAt,
    nonce: challenge.nonce,
    sig: challenge.sig,
    // Tells the client how long to hold a solved challenge before submitting.
    // Honouring it is how an ordinary visitor pays an elevated cost as a short
    // wait instead of as a worse score.
    minAgeMs: challenge.minAgeMs
  });
});

// Legacy challenge endpoint for backwards compatibility
app.get('/api/challenge', (req, res) => {
  const challengeId = crypto.createHash('sha256').update(String(Date.now())).digest('hex').slice(0, 32);
  res.json({
    challengeId,
    powDifficulty: 4,
    expires: Math.floor(Date.now() / 1000) + 300
  });
});

// =============================================================================
// Start
// =============================================================================

app.listen(PORT, () => {
  console.log(`FCaptcha server running on port ${PORT}`);
  console.log(`Trusted proxies: ${PROXY_TRUST.describe()}`);
  console.log(`Site keys: ${SITE_KEYS.describe()}`);
});
