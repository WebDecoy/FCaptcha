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

// =============================================================================
// PoW Challenge Store (can be extended with Redis)
// =============================================================================

class PoWChallengeStore {
  constructor(options = {}) {
    this.secret = options.secret || 'dev-secret-change-in-production';
    this.challenges = new Map();
    this.usedSolutions = new Set();
    this.expirationMs = options.expirationMs || 5 * 60 * 1000; // 5 minutes
  }

  generate(siteKey, ip, difficulty = 4) {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const expiresAt = timestamp + this.expirationMs;

    const challengeData = {
      id: challengeId,
      siteKey,
      timestamp,
      expiresAt,
      difficulty,
      prefix: `${challengeId}:${timestamp}:${difficulty}`
    };

    // Sign the challenge
    const sig = crypto.createHmac('sha256', this.secret)
      .update(JSON.stringify(challengeData))
      .digest('hex')
      .slice(0, 16);

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

  verify(challengeId, nonce, hash, siteKey) {
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

    return { valid: true, difficulty: challenge.difficulty };
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

const WEIGHTS = {
  vision_ai: 0.15,
  headless: 0.15,
  automation: 0.10,
  behavioral: 0.20,
  fingerprint: 0.10,
  rate_limit: 0.05,
  datacenter: 0.10,
  tor_vpn: 0.05,
  bot: 0.10
};

const AUTOMATION_UA_PATTERNS = [
  /headless/i, /phantomjs/i, /selenium/i, /webdriver/i,
  /puppeteer/i, /playwright/i, /cypress/i, /nightwatch/i,
  /zombie/i, /electron/i, /chromium.*headless/i
];

class ScoringEngine {
  constructor(options = {}) {
    this.secret = options.secret || 'dev-secret-change-in-production';
    this.powStore = options.powStore || new PoWChallengeStore({ secret: this.secret });
    this.rateLimiter = options.rateLimiter || new RateLimiter();
    this.fingerprintStore = options.fingerprintStore || new FingerprintStore();
    this.weights = options.weights || WEIGHTS;
  }

  // Generate a PoW challenge
  generateChallenge(siteKey, ip, options = {}) {
    let difficulty = options.difficulty || 4;

    if (options.scaleByReputation !== false) {
      if (detection.isDatacenterIP(ip)) {
        difficulty = Math.max(difficulty, 5);
      }

      const rateKey = `pow:${siteKey}:${ip}`;
      const [exceeded, count] = this.rateLimiter.check(rateKey, 60, 20);
      if (count > 10) {
        difficulty = Math.min(6, difficulty + 1);
      }
      if (exceeded) {
        difficulty = 6;
      }
    }

    return this.powStore.generate(siteKey, ip, difficulty);
  }

  // Verify signals and return score
  verify(signals, ip, siteKey, userAgent, headers = {}, powSolution = null) {
    const detections = [];

    // Run all detection modules
    detections.push(...this._detectVisionAI(signals));
    detections.push(...this._detectHeadless(signals, userAgent));
    detections.push(...this._detectAutomation(signals));
    detections.push(...this._detectBehavioral(signals));
    detections.push(...this._detectFingerprint(signals, ip, siteKey));
    detections.push(...this._detectRateAbuse(ip, siteKey));

    // Verify PoW
    if (powSolution && powSolution.challengeId) {
      const powResult = this.powStore.verify(
        powSolution.challengeId,
        powSolution.nonce,
        powSolution.hash,
        siteKey
      );

      if (!powResult.valid) {
        detections.push({
          category: 'bot',
          score: 0.7,
          confidence: 0.8,
          reason: `PoW verification failed: ${powResult.reason}`
        });
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
    const categoryScores = this._calculateCategoryScores(detections);
    const finalScore = this._calculateFinalScore(categoryScores);

    let recommendation;
    if (finalScore < 0.3) recommendation = 'allow';
    else if (finalScore < 0.6) recommendation = 'challenge';
    else recommendation = 'block';

    const success = finalScore < 0.5;
    const token = success ? this._generateToken(ip, siteKey, finalScore) : null;

    return {
      success,
      score: finalScore,
      token,
      timestamp: Math.floor(Date.now() / 1000),
      recommendation,
      categoryScores,
      detections
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
      const expectedSig = crypto.createHmac('sha256', this.secret).update(payload).digest('hex').slice(0, 16);

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

  _detectVisionAI(signals) {
    const detections = [];
    const b = signals.behavioral || {};
    const t = signals.temporal || {};

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

    const microTremor = b.microTremorScore ?? 0.5;
    if (microTremor < 0.15) {
      detections.push({
        category: 'vision_ai', score: 0.7, confidence: 0.6,
        reason: 'Mouse movement lacks natural micro-tremor'
      });
    }

    if ((b.approachDirectness ?? 0) > 0.95) {
      detections.push({
        category: 'vision_ai', score: 0.5, confidence: 0.5,
        reason: 'Mouse path to target is unnaturally direct'
      });
    }

    const precision = b.clickPrecision ?? 10;
    if (precision > 0 && precision < 2) {
      detections.push({
        category: 'vision_ai', score: 0.4, confidence: 0.5,
        reason: 'Click precision is unnaturally accurate'
      });
    }

    const exploration = b.explorationRatio ?? 0.3;
    const trajectory = b.trajectoryLength ?? 0;
    if (exploration < 0.05 && trajectory > 50) {
      detections.push({
        category: 'vision_ai', score: 0.4, confidence: 0.4,
        reason: 'No exploratory mouse movement before click'
      });
    }

    return detections;
  }

  _detectHeadless(signals, userAgent) {
    const detections = [];
    const env = signals.environmental || {};
    const headless = env.headlessIndicators || {};
    const automation = env.automationFlags || {};

    if (env.webdriver) {
      detections.push({
        category: 'headless', score: 0.95, confidence: 0.95,
        reason: 'WebDriver detected'
      });
    }

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

    for (const pattern of AUTOMATION_UA_PATTERNS) {
      if (pattern.test(userAgent)) {
        detections.push({
          category: 'headless', score: 0.9, confidence: 0.9,
          reason: 'Automation pattern in User-Agent'
        });
        break;
      }
    }

    const renderer = (this._getNestedValue(env, 'webglInfo', 'renderer') || '').toLowerCase();
    if (renderer.includes('swiftshader') || renderer.includes('llvmpipe')) {
      detections.push({
        category: 'headless', score: 0.8, confidence: 0.8,
        reason: 'Software WebGL renderer detected'
      });
    }

    return detections;
  }

  _detectAutomation(signals) {
    const detections = [];
    const env = signals.environmental || {};
    const b = signals.behavioral || {};

    const jsTime = this._getNestedValue(env, 'jsExecutionTime', 'mathOps') || 0;
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

    const raf = env.rafConsistency || {};
    if (raf.frameTimeVariance !== undefined && raf.frameTimeVariance < 0.1) {
      detections.push({
        category: 'automation', score: 0.5, confidence: 0.4,
        reason: 'RequestAnimationFrame timing too consistent'
      });
    }

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

  _detectBehavioral(signals) {
    const detections = [];
    const b = signals.behavioral || {};
    const t = signals.temporal || {};

    const velVar = b.velocityVariance ?? 1;
    const trajectory = b.trajectoryLength ?? 0;
    if (velVar < 0.02 && trajectory > 50) {
      detections.push({
        category: 'behavioral', score: 0.6, confidence: 0.6,
        reason: 'Mouse velocity too consistent'
      });
    }

    const overshoots = b.overshootCorrections ?? 0;
    if (overshoots === 0 && trajectory > 200) {
      detections.push({
        category: 'behavioral', score: 0.4, confidence: 0.4,
        reason: 'No overshoot corrections on long trajectory'
      });
    }

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

    const firstInt = t.pageLoadToFirstInteraction;
    if (firstInt !== null && firstInt > 0 && firstInt < 100) {
      detections.push({
        category: 'behavioral', score: 0.5, confidence: 0.5,
        reason: 'First interaction too soon after page load'
      });
    }

    const eventRate = b.mouseEventRate ?? 60;
    if (eventRate > 200) {
      detections.push({
        category: 'behavioral', score: 0.6, confidence: 0.5,
        reason: 'Mouse event rate abnormally high'
      });
    } else if (eventRate > 0 && eventRate < 10) {
      detections.push({
        category: 'behavioral', score: 0.4, confidence: 0.4,
        reason: 'Mouse event rate abnormally low'
      });
    }

    const straight = b.straightLineRatio ?? 0;
    if (straight > 0.8 && trajectory > 100) {
      detections.push({
        category: 'behavioral', score: 0.5, confidence: 0.5,
        reason: 'Mouse movements too straight'
      });
    }

    const dirChanges = b.directionChanges ?? 10;
    const totalPoints = b.totalPoints ?? 0;
    if (totalPoints > 50 && dirChanges < 3) {
      detections.push({
        category: 'behavioral', score: 0.4, confidence: 0.4,
        reason: 'Too few direction changes'
      });
    }

    return detections;
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

  _calculateCategoryScores(detections) {
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
        const totalWeight = scores.reduce((sum, [, conf]) => sum + conf, 0);
        if (totalWeight > 0) {
          const weightedSum = scores.reduce((sum, [score, conf]) => sum + score * conf, 0);
          result[cat] = Math.min(1.0, weightedSum / totalWeight);
        }
      }
    }

    for (const cat of Object.keys(this.weights)) {
      if (!(cat in result)) {
        result[cat] = 0.0;
      }
    }

    return result;
  }

  _calculateFinalScore(categoryScores) {
    let total = 0;
    for (const [cat, weight] of Object.entries(this.weights)) {
      total += (categoryScores[cat] || 0) * weight;
    }
    return Math.min(1.0, total);
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
    const sig = crypto.createHmac('sha256', this.secret).update(payload).digest('hex').slice(0, 16);
    data.sig = sig;

    return Buffer.from(JSON.stringify(data)).toString('base64url');
  }
}

// =============================================================================
// Express Middleware Factory
// =============================================================================

function createMiddleware(options = {}) {
  const engine = new ScoringEngine(options);

  return {
    engine,

    // Middleware to extract IP from request
    getIP: (req) => {
      let ip = req.headers['x-real-ip'] || '';
      if (!ip) {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) {
          ip = forwarded.split(',')[0].trim();
        } else {
          ip = req.socket?.remoteAddress || '127.0.0.1';
        }
      }
      return ip;
    },

    // Challenge route handler
    challengeHandler: (req, res) => {
      const siteKey = req.query.siteKey || 'default';
      const ip = options.getIP ? options.getIP(req) : module.exports.createMiddleware({}).getIP(req);
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
      const ip = options.getIP ? options.getIP(req) : module.exports.createMiddleware({}).getIP(req);
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

  // Constants
  WEIGHTS,
  AUTOMATION_UA_PATTERNS
};
