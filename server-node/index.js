/**
 * @webdecoy/fcaptcha - Open source CAPTCHA with PoW, bot detection, and Vision AI protection
 *
 * Main entry point for library usage.
 *
 * Usage:
 *   const fcaptcha = require('@webdecoy/fcaptcha');
 *   const engine = fcaptcha.createScoringEngine({ secret: 'your-secret' });
 *   const result = engine.verify(signals, ip, siteKey, userAgent, headers, powSolution);
 */

const crypto = require('crypto');
const detection = require('./detection');
const { ProxyTrust, networkIdentity } = require('./clientip');
const { SuspicionLedger, computeChallengeCost, BASE_MIN_AGE_MS } = require('./suspicion');
const { signingSecret } = require('./config');

// =============================================================================
// PoW Challenge Store (can be extended with Redis)
// =============================================================================

class PoWChallengeStore {
  constructor(options = {}) {
    this.secret = signingSecret(options.secret);
    this.challenges = new Map();
    this.usedSolutions = new Set();
    this.expirationMs = options.expirationMs || 5 * 60 * 1000; // 5 minutes
  }

  generate(siteKey, ip, difficulty = 4, minAgeMs = BASE_MIN_AGE_MS) {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const expiresAt = timestamp + this.expirationMs;

    const challengeData = {
      id: challengeId,
      siteKey,
      timestamp,
      expiresAt,
      difficulty,
      // How long the client must hold this challenge before submitting a
      // solution. Inside the signed payload so it cannot be talked down.
      minAgeMs,
      prefix: `${challengeId}:${timestamp}:${difficulty}`
    };

    // Sign the challenge
    const sig = crypto.createHmac('sha256', this.secret)
      .update(JSON.stringify(challengeData))
      .digest('hex');

    challengeData.sig = sig;

    // Store challenge
    this.challenges.set(challengeId, {
      ...challengeData,
      ip,
      createdAt: timestamp
    });

    // Periodic cleanup
    if (Math.random() < 0.1) this._cleanup();

    return challengeData;
  }

  verify(challengeId, nonce, hash, siteKey, ip) {
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

    if (networkIdentity(challenge.ip) !== networkIdentity(ip)) {
      return { valid: false, reason: 'challenge_network_mismatch' };
    }

    // Check for replay
    const solutionKey = `${challengeId}:${nonce}`;
    if (this.usedSolutions.has(solutionKey)) {
      return { valid: false, reason: 'solution_already_used' };
    }

    // Verify the hash
    const input = `${challenge.prefix}:${nonce}`;
    const expectedHash = crypto.createHash('sha256').update(input).digest('hex');

    if (hash !== expectedHash) {
      return { valid: false, reason: 'invalid_hash' };
    }

    // Check difficulty
    const target = '0'.repeat(challenge.difficulty);
    if (!hash.startsWith(target)) {
      return { valid: false, reason: 'insufficient_difficulty' };
    }

    // Mark as used
    this.usedSolutions.add(solutionKey);
    this.challenges.delete(challengeId);

    return {
      valid: true,
      difficulty: challenge.difficulty,
      serverElapsed: Date.now() - challenge.timestamp,
      // Fall back for challenges issued before adaptive cost existed.
      minAgeMs: challenge.minAgeMs || BASE_MIN_AGE_MS
    };
  }

  _cleanup() {
    const now = Date.now();
    for (const [id, challenge] of this.challenges) {
      if (now > challenge.expiresAt) {
        this.challenges.delete(id);
      }
    }
    if (this.usedSolutions.size > 10000) {
      this.usedSolutions.clear();
    }
  }
}

// =============================================================================
// Rate Limiter
// =============================================================================

class RateLimiter {
  constructor() {
    this.requests = new Map();
  }

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
}

// =============================================================================
// Fingerprint Store
// =============================================================================

class FingerprintStore {
  constructor() {
    this.fingerprints = new Map();
    this.ipFingerprints = new Map();
  }

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
  }

  getIpFpCount(ip) {
    return this.ipFingerprints.get(ip)?.size || 0;
  }

  getFpIpCount(fp, siteKey) {
    const key = `${siteKey}:${fp}`;
    return this.fingerprints.get(key)?.ips.size || 0;
  }
}

// =============================================================================
// Scoring Engine
// =============================================================================

// The detection and scoring core is shared with server.js. These used to be two
// separate implementations, and the library was the one that fell behind: it
// was missing seventeen detectors, had no `cdp` or `declared_ai` weight
// category, and still aggregated with the pre-v1.18.0 confidence-weighted mean
// (where corroborating evidence lowers the verdict) and no dispositive floor.
// Both engines now run the same code. See engine.js.
const {
  AUTOMATION_UA_PATTERNS,
  WEIGHTS,
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
const { detectInputForensics } = require('./inputforensics');

class ScoringEngine {
  constructor(options = {}) {
    this.secret = signingSecret(options.secret);
    this.powStore = options.powStore || new PoWChallengeStore({ secret: this.secret });
    this.rateLimiter = options.rateLimiter || new RateLimiter();
    this.fingerprintStore = options.fingerprintStore || new FingerprintStore();
    this.suspicion = options.suspicion || new SuspicionLedger();
    this.weights = options.weights || WEIGHTS;
  }

  // Generate a PoW challenge
  generateChallenge(siteKey, ip, options = {}) {
    // See suspicion.js for why the escalation lands almost entirely on
    // minAgeMs rather than on difficulty.
    let difficulty = options.difficulty || 4;
    let minAgeMs = BASE_MIN_AGE_MS;

    if (options.scaleByReputation !== false) {
      const rateKey = `pow:${siteKey}:${ip}`;
      const [exceeded, count] = this.rateLimiter.check(rateKey, 60, 20);
      const cost = computeChallengeCost(
        this.suspicion.count(siteKey, ip),
        detection.isDatacenterIP(ip),
        count,
        exceeded
      );
      difficulty = Math.max(difficulty, cost.difficulty);
      minAgeMs = cost.minAgeMs;
    }

    return this.powStore.generate(siteKey, ip, difficulty, minAgeMs);
  }

  // Verify signals and return score
  verify(signals, ip, siteKey, userAgent, headers = {}, powSolution = null) {
    const detections = [];
    let powSatisfied = false;

    // Run all detection modules
    // Run the shared detection core — the same detectors server.js runs.
    detections.push(
      ...detectVisionAI(signals),
      ...detectHeadless(signals, userAgent),
      ...detectStealthArtifacts(signals),
      ...detectAutomation(signals),
      ...detectCDP(signals),
      ...detectBehavioral(signals),
      // Input forensics v2: typing cadence and modality, the paste-shortcut /
      // platform contradiction, scroll morphology, font coherence.
      ...detectInputForensics(signals),
      ...detectTouchAuthenticity(signals, userAgent),
      ...detectSensorEntropy(signals, userAgent),
      ...detectTouchKinematics(signals),
      // Stateful detectors stay on the engine, which owns the stores.
      ...this._detectFingerprint(signals, ip, siteKey),
      ...this._detectRateAbuse(ip, siteKey)
    );

    // Verify PoW
    if (powSolution && powSolution.challengeId) {
      const powResult = this.powStore.verify(
        powSolution.challengeId,
        powSolution.nonce,
        powSolution.hash,
        siteKey,
        ip
      );

      if (!powResult.valid) {
        detections.push({
          category: 'bot',
          score: 0.7,
          confidence: 0.8,
          reason: `PoW verification failed: ${powResult.reason}`
        });
      } else if (powResult.serverElapsed < BASE_MIN_AGE_MS) {
        powSatisfied = true;
        // Under the universal baseline nothing legitimate can have happened —
        // no human completes an interaction that fast.
        detections.push({
          category: 'bot',
          score: 0.8,
          confidence: 0.85,
          reason: `Challenge solved too fast (${powResult.serverElapsed}ms server-side)`
        });
      } else if (powResult.serverElapsed < powResult.minAgeMs) {
        powSatisfied = true;
        // Between the baseline and this source's own elevated floor is weaker
        // evidence: a client predating adaptive cost, or one served from a
        // stale cache, does not know to wait. It contributes rather than
        // deciding.
        detections.push({
          category: 'bot',
          score: 0.5,
          confidence: 0.5,
          reason: `Challenge submitted before the required delay for this source (${powResult.serverElapsed}ms of ${powResult.minAgeMs}ms)`
        });
      } else {
        powSatisfied = true;
      }
    } else {
      detections.push({
        category: 'bot',
        score: 0.5,
        confidence: 0.6,
        reason: 'No PoW solution provided'
      });
    }

    // IP reputation
    if (detection.isDatacenterIP(ip)) {
      detections.push({
        category: 'datacenter',
        score: 0.6,
        confidence: 0.8,
        reason: 'Request from known datacenter IP range'
      });
    }

    // Header analysis
    detections.push(...detection.analyzeHeaders(headers));

    // Browser consistency
    detections.push(...detection.checkBrowserConsistency(userAgent, signals));

    // JA3 fingerprint
    if (headers['x-ja3-hash']) {
      detections.push(...detection.checkJA3Fingerprint(headers['x-ja3-hash']));
    }

    // Form interaction
    if (signals.formAnalysis) {
      detections.push(...detection.analyzeFormInteraction(signals.formAnalysis));
    }

    // Calculate scores
    // Same aggregation as server.js: noisy-OR within a category, weighted sum
    // across them, then the dispositive and corroboration floors.
    const categoryScores = calculateCategoryScores(detections, this.weights);
    const finalScore = applyCorroborationFloor(
      applyDispositiveFloor(calculateFinalScore(categoryScores, this.weights), detections),
      categoryScores
    );

    let recommendation;
    if (finalScore < 0.3) recommendation = 'allow';
    else if (finalScore < 0.6) recommendation = 'challenge';
    else recommendation = 'block';

    // PoW is a precondition, not weighted evidence. Expressing a missing or
    // invalid solution only as a bot-category score lets the category weight
    // dilute it below the allow threshold and used to mint a token for an empty
    // request. Keep this gate independent of scoring so weight changes cannot
    // reopen the bypass.
    const success = finalScore < 0.5 && powSatisfied;
    const token = success ? this._generateToken(ip, siteKey, finalScore) : null;

    // Feed the ledger so the next challenge this source asks for is priced on
    // what it just did.
    this.suspicion.record(siteKey, ip, finalScore);

    return {
      success,
      score: finalScore,
      token,
      timestamp: Math.floor(Date.now() / 1000),
      recommendation,
      categoryScores,
      detections,
      ...(!powSatisfied ? { reason: 'pow_not_satisfied' } : {})
    };
  }

  // Verify a previously issued token
  verifyToken(token) {
    try {
      const decoded = JSON.parse(Buffer.from(token, 'base64url').toString());

      if (Date.now() / 1000 - decoded.timestamp > 300) {
        return { valid: false, reason: 'expired' };
      }

      const sig = decoded.sig;
      delete decoded.sig;

      const payload = JSON.stringify(decoded, Object.keys(decoded).sort());
      const expectedSig = crypto.createHmac('sha256', this.secret).update(payload).digest('hex');

      if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
        return { valid: false, reason: 'invalid_signature' };
      }

      return {
        valid: true,
        site_key: decoded.site_key,
        timestamp: decoded.timestamp,
        score: decoded.score
      };
    } catch (e) {
      return { valid: false, reason: e.message };
    }
  }

  // Internal detection methods
  _getNestedValue(obj, ...keys) {
    return keys.reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);
  }

  _detectFingerprint(signals, ip, siteKey) {
    const detections = [];
    const env = signals.environmental || {};
    const automation = env.automationFlags || {};

    const components = [
      String(this._getNestedValue(env, 'canvasHash', 'hash') || ''),
      String(this._getNestedValue(env, 'webglInfo', 'renderer') || ''),
      String(automation.platform || ''),
      String(automation.hardwareConcurrency || '')
    ];
    const fp = crypto.createHash('sha256').update(components.join('|')).digest('hex').slice(0, 16);

    this.fingerprintStore.record(fp, ip, siteKey);

    const ipFpCount = this.fingerprintStore.getIpFpCount(ip);
    if (ipFpCount > 5) {
      detections.push({
        category: 'fingerprint', score: 0.6, confidence: 0.6,
        reason: 'IP has used many different fingerprints'
      });
    }

    const fpIpCount = this.fingerprintStore.getFpIpCount(fp, siteKey);
    if (fpIpCount > 10) {
      detections.push({
        category: 'fingerprint', score: 0.5, confidence: 0.5,
        reason: 'Fingerprint seen from many IPs'
      });
    }

    const canvas = env.canvasHash || {};
    if (canvas.error || canvas.supported === false) {
      detections.push({
        category: 'fingerprint', score: 0.4, confidence: 0.4,
        reason: 'Canvas fingerprinting blocked or failed'
      });
    }

    return detections;
  }

  _detectRateAbuse(ip, siteKey) {
    const detections = [];
    const key = `${siteKey}:${ip}`;

    const [exceeded, count] = this.rateLimiter.check(key, 60, 10);
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

  _generateToken(ip, siteKey, score) {
    const ipHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 8);
    const data = {
      site_key: siteKey,
      timestamp: Math.floor(Date.now() / 1000),
      score: Math.round(score * 1000) / 1000,
      ip_hash: ipHash
    };

    const payload = JSON.stringify(data, Object.keys(data).sort());
    const sig = crypto.createHmac('sha256', this.secret).update(payload).digest('hex');
    data.sig = sig;

    return Buffer.from(JSON.stringify(data)).toString('base64url');
  }
}

// =============================================================================
// Express Middleware Factory
// =============================================================================

function createMiddleware(options = {}) {
  const engine = new ScoringEngine(options);
  const proxyTrust = options.trustedProxies !== undefined
    ? new ProxyTrust(options.trustedProxies)
    : ProxyTrust.fromEnv();

  return {
    engine,
    proxyTrust,

    // Middleware to extract IP from request. Forwarding headers are honoured
    // only from a peer in the trusted-proxy set (TRUSTED_PROXIES, or the
    // private/loopback defaults) — otherwise any caller could claim a clean
    // residential IP and skip the datacenter, Tor/VPN and rate-limit checks.
    // Pass options.trustedProxies to override the env for this instance.
    getIP: (req) => proxyTrust.clientIP(req),

    // Challenge route handler
    challengeHandler: (req, res) => {
      const siteKey = req.query.siteKey || 'default';
      const ip = options.getIP ? options.getIP(req) : proxyTrust.clientIP(req);
      const challenge = engine.generateChallenge(siteKey, ip);

      res.json({
        challengeId: challenge.id,
        prefix: challenge.prefix,
        difficulty: challenge.difficulty,
        expiresAt: challenge.expiresAt,
        sig: challenge.sig
      });
    },

    // Verify route handler
    verifyHandler: (req, res) => {
      const { siteKey, signals, powSolution } = req.body;
      const ip = options.getIP ? options.getIP(req) : proxyTrust.clientIP(req);
      const userAgent = req.headers['user-agent'] || '';

      const headers = {};
      for (const [key, value] of Object.entries(req.headers)) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value[0] : value;
      }

      const result = engine.verify(signals, ip, siteKey, userAgent, headers, powSolution);
      res.json(result);
    },

    // Token verify route handler
    tokenVerifyHandler: (req, res) => {
      const { token } = req.body;
      res.json(engine.verifyToken(token));
    }
  };
}

// =============================================================================
// Exports
// =============================================================================

module.exports = {
  // Core classes
  ScoringEngine,
  PoWChallengeStore,
  RateLimiter,
  FingerprintStore,

  // Detection module (re-export)
  detection,

  // Factory functions
  createScoringEngine: (options) => new ScoringEngine(options),
  createMiddleware,

  // Call before verify() when scoring a session that had no widget to click,
  // so click-derived checks are not read off absent fields.
  setInteractionMode,

  // Constants
  WEIGHTS,
  AUTOMATION_UA_PATTERNS
};
