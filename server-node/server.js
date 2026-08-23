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
const { ProxyTrust, networkIdentity } = require('./clientip');
const { BoundedMap, BoundedSet, SiteKeyGuard } = require('./limits');
const { signingSecretFromEnv } = require('./config');
const { SuspicionLedger, computeChallengeCost, BASE_MIN_AGE_MS } = require('./suspicion');
const { detectInputForensics } = require('./inputforensics');
const { RedisState } = require('./redis-state');
const {
  HostnameAllowlist,
  IdempotencyStore,
  requestHostname,
  sanitizeAction,
  sanitizeCdata,
  secretMatches,
  siteverifyAsync
} = require('./siteverify');

const app = express();
app.use(cors());
// Captured widget payloads are about 10-15 KiB. Four times that leaves ample
// room for future signals while bounding work done by the public JSON parsers.
const MAX_REQUEST_BODY_BYTES = 64 * 1024;
app.use(express.json({ limit: MAX_REQUEST_BODY_BYTES }));
// The siteverify contract accepts form-encoded bodies as well as JSON, and most
// PHP and Python integrations in the wild post form-encoded. Parsing both here
// costs nothing on the JSON path.
app.use(express.urlencoded({ extended: false, limit: MAX_REQUEST_BODY_BYTES }));

const SECRET_KEY = signingSecretFromEnv();
const REDIS_URL = process.env.REDIS_URL || '';
const SHARED_STATE = REDIS_URL ? new RedisState(REDIS_URL) : null;

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
const IDEMPOTENCY = SHARED_STATE
  ? {
      get: (key, token) => SHARED_STATE.getIdempotency(key, token),
      set: (key, token, response) => SHARED_STATE.setIdempotency(key, token, response)
    }
  : new IdempotencyStore();

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
  async generate(siteKey, ip, difficulty = 4, minAgeMs = BASE_MIN_AGE_MS) {
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

    const storedChallenge = {
      ...challengeData,
      ip,
      createdAt: timestamp
    };
    if (SHARED_STATE) {
      await SHARED_STATE.putChallenge(storedChallenge);
    } else {
      this.challenges.set(challengeId, storedChallenge);
    }

    // Cleanup old challenges periodically
    if (Math.random() < 0.1) this._cleanup();

    return challengeData;
  },

  // Verify a PoW solution (signalsHash is optional for backward compat)
  async verify(challengeId, nonce, hash, siteKey, ip, signalsHash = null) {
    let challenge;
    try {
      challenge = SHARED_STATE
        ? await SHARED_STATE.getChallenge(challengeId)
        : this.challenges.get(challengeId);
    } catch (_) {
      return { valid: false, reason: 'state_unavailable' };
    }

    if (!challenge) {
      return { valid: false, reason: 'challenge_not_found' };
    }

    if (Date.now() > challenge.expiresAt) {
      if (!SHARED_STATE) this.challenges.delete(challengeId);
      return { valid: false, reason: 'challenge_expired' };
    }

    if (challenge.siteKey !== siteKey) {
      return { valid: false, reason: 'site_key_mismatch' };
    }

    if (networkIdentity(challenge.ip) !== networkIdentity(ip)) {
      return { valid: false, reason: 'challenge_network_mismatch' };
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

    if (SHARED_STATE) {
      try {
        const claim = await SHARED_STATE.claimChallenge(challengeId, solutionKey);
        if (!claim.claimed) return { valid: false, reason: claim.reason };
      } catch (_) {
        return { valid: false, reason: 'state_unavailable' };
      }
    } else {
      // The local store is synchronous, so this test-and-set is atomic within
      // one event-loop turn.
      if (this.usedSolutions.has(solutionKey)) {
        return { valid: false, reason: 'solution_already_used' };
      }
      this.usedSolutions.add(solutionKey);
      this.challenges.delete(challengeId);
    }

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

// Detection patterns, the pure detectors and the scoring aggregation now
// live in engine.js, shared with the npm library entry point (index.js).
// The two used to be separate implementations and drifted; see engine.js.
const {
  getNestedValue,
  setInteractionMode,
  detectVisionAI,
  detectHeadless,
  detectStealthArtifacts,
  detectAutomation,
  detectCDP,
  detectBehavioral,
  detectTouchAuthenticity,
  detectSensorEntropy,
  detectTouchKinematics,
  calculateCategoryScores,
  calculateFinalScore,
  applyDispositiveFloor,
  applyCorroborationFloor,
} = require('./engine');

// Stateful detectors stay here: they read the module-level stores below.
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

async function verifyToken(token, ip = null) {
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

    // Verify IP matches (if provided)
    if (ip) {
      const expectedIpHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 8);
      if (decoded.ip_hash !== expectedIpHash) {
        return { valid: false, reason: 'ip_mismatch' };
      }
    }

    let claimed;
    try {
      claimed = SHARED_STATE
        ? await SHARED_STATE.claimToken(sig)
        : tokenStore.markUsed(sig);
    } catch (_) {
      return { valid: false, reason: 'state_unavailable' };
    }
    if (!claimed) return { valid: false, reason: 'token_already_used' };

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
  } catch (_) {
    return { valid: false, reason: 'invalid_token' };
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
async function runVerification(signals, ip, siteKey, userAgent, headers = {}, ja3Hash = null, powSolution = null, signalsJson = null, powTiming = null, preDetections = [], opts = {}) {
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

  // Stamp the interaction mode after signalsJson has been resolved above, so
  // it lands on the object the detectors actually read. Defaults to widget
  // mode for callers that do not set it (see setInteractionMode).
  setInteractionMode(signals, opts.widgetInteraction !== false);

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
    powVerification = await powChallengeStore.verify(
      powSolution.challengeId,
      powSolution.nonce,
      powSolution.hash,
      siteKey,
      ip,
      clientSignalsHash
    );
    powValid = powVerification.valid;

    if (!powValid) {
      detections.push({
        category: 'bot',
        score: 0.7,
        confidence: 0.8,
        reason: `PoW verification failed: ${powVerification.reason}`
        // Deliberately NOT dispositive. The gate already withholds the token,
        // which is the security requirement. Flooring the score as well says
        // "blatant bot", and a failed proof of work does not mean that: the
        // challenge expires after five minutes, challenges live only in memory
        // so every deploy invalidates the outstanding ones, and a double-click
        // replays a solution. All ordinary things that happen to real people.
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
          reason: 'Challenge nonce mismatch (signals not bound to challenge)'
          // Not dispositive — see above; a stale challenge produces this too.
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
      reason: 'No PoW solution provided'
      // Not dispositive — the gate refuses the token; inflating the score on
      // top only mislabels whoever hit a stale page.
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

  const result = await runVerification(signals, ip, siteKey, userAgent, headers, ja3Hash, powSolution, signalsJson, powTiming, webBotAuth, { peerTrusted, action, cdata, widgetInteraction: true });
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

  // Invisible scoring: no widget, so no click analysis in the signals.
  const result = await runVerification(signals, ip, siteKey, userAgent, headers, ja3Hash, powSolution, signalsJson, powTiming, webBotAuth, { peerTrusted, action, cdata, widgetInteraction: false });
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

app.post('/api/token/verify', async (req, res) => {
  const { token, secret, remoteip } = req.body;

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

  // This request comes from the integrating backend, not from the visitor who
  // received the token. Bind only when that trusted backend explicitly supplies
  // the visitor address; using the caller socket here compares unrelated hosts.
  res.json(await verifyToken(token, typeof remoteip === 'string' && remoteip ? remoteip : null));
});

// Turnstile / reCAPTCHA / hCaptcha drop-in compatibility.
//
// Same contract, three paths, because the path is hardcoded in the SDKs and
// plugins we want to be usable against FCaptcha: pointing an existing
// integration at this server should be a base-URL change and nothing else.
// See siteverify.js for the adapter itself.
async function siteverifyHandler(req, res) {
  res.json(
    await siteverifyAsync({
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
app.get('/api/pow/challenge', async (req, res) => {
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

  let challenge;
  try {
    challenge = await powChallengeStore.generate(siteKey, ip, cost.difficulty, cost.minAgeMs);
  } catch (_) {
    return res.status(503).json({ error: 'state_unavailable' });
  }

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

// Express identifies parser limit failures with status 413 / entity.too.large.
// Handle them explicitly so all three servers expose the same status instead
// of falling through to Express's HTML error response.
app.use((err, req, res, next) => {
  if (err && (err.status === 413 || err.type === 'entity.too.large')) {
    return res.status(413).json({ error: 'request_too_large' });
  }
  return next(err);
});

// =============================================================================
// Start
// =============================================================================

async function start() {
  if (SHARED_STATE) await SHARED_STATE.connect();
  app.listen(PORT, () => {
    console.log(`FCaptcha server running on port ${PORT}`);
    console.log(`Trusted proxies: ${PROXY_TRUST.describe()}`);
    console.log(`Site keys: ${SITE_KEYS.describe()}`);
    console.log(`Shared state: ${SHARED_STATE ? 'Redis (PoW)' : 'in-memory'}`);
  });
}

start().catch((err) => {
  console.error(`FCaptcha failed to start: ${err.message}`);
  process.exit(1);
});
