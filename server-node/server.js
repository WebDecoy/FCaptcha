/**
 * FCaptcha Server - Node.js/Express Implementation
 *
 * Run: node server.js
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const detection = require('./detection');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.FCAPTCHA_SECRET || 'dev-secret-change-in-production';
const PORT = process.env.PORT || 3000;

// =============================================================================
// In-Memory Storage (Use Redis in production)
// =============================================================================

// PoW Challenge Store
const powChallengeStore = {
  challenges: new Map(),
  usedSolutions: new Set(),

  // Generate a new challenge
  generate(siteKey, ip, difficulty = 4) {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const expiresAt = timestamp + (5 * 60 * 1000); // 5 minutes

    // Challenge data to be signed
    const challengeData = {
      id: challengeId,
      siteKey,
      timestamp,
      expiresAt,
      difficulty,
      prefix: `${challengeId}:${timestamp}:${difficulty}`
    };

    // Sign the challenge
    const sig = crypto.createHmac('sha256', SECRET_KEY)
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

    // Cleanup old challenges periodically
    if (Math.random() < 0.1) this._cleanup();

    return challengeData;
  },

  // Verify a PoW solution
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

    // Check if solution was already used (prevent replay)
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

    // Check difficulty (hash must start with N zeros)
    const target = '0'.repeat(challenge.difficulty);
    if (!hash.startsWith(target)) {
      return { valid: false, reason: 'insufficient_difficulty' };
    }

    // Mark solution as used
    this.usedSolutions.add(solutionKey);

    // Delete challenge (one-time use)
    this.challenges.delete(challengeId);

    return { valid: true, difficulty: challenge.difficulty };
  },

  _cleanup() {
    const now = Date.now();
    for (const [id, challenge] of this.challenges) {
      if (now > challenge.expiresAt) {
        this.challenges.delete(id);
      }
    }
    // Cleanup old solutions (keep last hour)
    if (this.usedSolutions.size > 10000) {
      this.usedSolutions.clear();
    }
  }
};

const rateLimiter = {
  requests: new Map(),

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
  fingerprints: new Map(),
  ipFingerprints: new Map(),

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
  automation: 0.10,
  behavioral: 0.20,
  fingerprint: 0.10,
  rate_limit: 0.05,
  datacenter: 0.10,
  tor_vpn: 0.05,
  bot: 0.10
};

// =============================================================================
// Detection Functions
// =============================================================================

function getNestedValue(obj, ...keys) {
  return keys.reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);
}

function detectVisionAI(signals) {
  const detections = [];
  const b = signals.behavioral || {};
  const t = signals.temporal || {};

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
  const microTremor = b.microTremorScore ?? 0.5;
  if (microTremor < 0.15) {
    detections.push({
      category: 'vision_ai', score: 0.7, confidence: 0.6,
      reason: 'Mouse movement lacks natural micro-tremor'
    });
  }

  // Approach directness
  if ((b.approachDirectness ?? 0) > 0.95) {
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
  const trajectory = b.trajectoryLength ?? 0;
  if (exploration < 0.05 && trajectory > 50) {
    detections.push({
      category: 'vision_ai', score: 0.4, confidence: 0.4,
      reason: 'No exploratory mouse movement before click'
    });
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

function detectBehavioral(signals) {
  const detections = [];
  const b = signals.behavioral || {};
  const t = signals.temporal || {};

  // Velocity variance
  const velVar = b.velocityVariance ?? 1;
  const trajectory = b.trajectoryLength ?? 0;
  if (velVar < 0.02 && trajectory > 50) {
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
  } else if (eventRate > 0 && eventRate < 10) {
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
  const totalPoints = b.totalPoints ?? 0;
  if (totalPoints > 50 && dirChanges < 3) {
    detections.push({
      category: 'behavioral', score: 0.4, confidence: 0.4,
      reason: 'Too few direction changes'
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
      const totalWeight = scores.reduce((sum, [, conf]) => sum + conf, 0);
      if (totalWeight > 0) {
        const weightedSum = scores.reduce((sum, [score, conf]) => sum + score * conf, 0);
        result[cat] = Math.min(1.0, weightedSum / totalWeight);
      }
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

function generateToken(ip, siteKey, score) {
  const ipHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 8);
  const data = {
    site_key: siteKey,
    timestamp: Math.floor(Date.now() / 1000),
    score: Math.round(score * 1000) / 1000,
    ip_hash: ipHash
  };

  const payload = JSON.stringify(data, Object.keys(data).sort());
  const sig = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('hex').slice(0, 16);
  data.sig = sig;

  return Buffer.from(JSON.stringify(data)).toString('base64url');
}

function verifyToken(token) {
  try {
    const decoded = JSON.parse(Buffer.from(token, 'base64url').toString());

    // Check expiration
    if (Date.now() / 1000 - decoded.timestamp > 300) {
      return { valid: false, reason: 'expired' };
    }

    const sig = decoded.sig;
    delete decoded.sig;

    const payload = JSON.stringify(decoded, Object.keys(decoded).sort());
    const expectedSig = crypto.createHmac('sha256', SECRET_KEY).update(payload).digest('hex').slice(0, 16);

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

function runVerification(signals, ip, siteKey, userAgent, headers = {}, ja3Hash = null, powSolution = null) {
  const detections = [
    ...detectVisionAI(signals),
    ...detectHeadless(signals, userAgent),
    ...detectAutomation(signals),
    ...detectBehavioral(signals),
    ...detectFingerprint(signals, ip, siteKey),
    ...detectRateAbuse(ip, siteKey)
  ];

  // Verify PoW if provided
  let powValid = false;
  let powVerification = null;
  if (powSolution && powSolution.challengeId) {
    powVerification = powChallengeStore.verify(
      powSolution.challengeId,
      powSolution.nonce,
      powSolution.hash,
      siteKey
    );
    powValid = powVerification.valid;

    if (!powValid) {
      detections.push({
        category: 'bot',
        score: 0.7,
        confidence: 0.8,
        reason: `PoW verification failed: ${powVerification.reason}`
      });
    }
  } else {
    // No PoW solution provided - suspicious
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: 'No PoW solution provided'
    });
  }

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
  const headerDetections = detection.analyzeHeaders(headers);
  detections.push(...headerDetections);

  // Add browser consistency checks
  const consistencyDetections = detection.checkBrowserConsistency(userAgent, signals);
  detections.push(...consistencyDetections);

  // Add JA3 fingerprint check
  if (ja3Hash) {
    const ja3Detections = detection.checkJA3Fingerprint(ja3Hash);
    detections.push(...ja3Detections);
  }

  // Add form interaction analysis (credential stuffing & spam detection)
  const formAnalysis = signals.formAnalysis;
  if (formAnalysis) {
    const formDetections = detection.analyzeFormInteraction(formAnalysis);
    detections.push(...formDetections);
  }

  const categoryScores = calculateCategoryScores(detections);
  const finalScore = calculateFinalScore(categoryScores);

  let recommendation;
  if (finalScore < 0.3) recommendation = 'allow';
  else if (finalScore < 0.6) recommendation = 'challenge';
  else recommendation = 'block';

  const success = finalScore < 0.5;
  const token = success ? generateToken(ip, siteKey, finalScore) : null;

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

// =============================================================================
// Routes
// =============================================================================

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/verify', (req, res) => {
  const { siteKey, signals, powSolution } = req.body;
  let ip = req.headers['x-real-ip'] || '';
  if (!ip) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      ip = forwarded.split(',')[0].trim();
    } else {
      ip = req.socket.remoteAddress;
    }
  }
  const userAgent = req.headers['user-agent'] || '';
  const ja3Hash = req.headers['x-ja3-hash'] || null;

  // Collect headers for analysis
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    headers[key.toLowerCase()] = Array.isArray(value) ? value[0] : value;
  }

  const result = runVerification(signals, ip, siteKey, userAgent, headers, ja3Hash, powSolution);
  res.json(result);
});

app.post('/api/score', (req, res) => {
  const { siteKey, signals, action, powSolution } = req.body;
  let ip = req.headers['x-real-ip'] || '';
  if (!ip) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      ip = forwarded.split(',')[0].trim();
    } else {
      ip = req.socket.remoteAddress;
    }
  }
  const userAgent = req.headers['user-agent'] || '';
  const ja3Hash = req.headers['x-ja3-hash'] || null;

  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    headers[key.toLowerCase()] = Array.isArray(value) ? value[0] : value;
  }

  const result = runVerification(signals, ip, siteKey, userAgent, headers, ja3Hash, powSolution);
  res.json({
    success: result.success,
    score: result.score,
    token: result.token,
    action: action || '',
    recommendation: result.recommendation
  });
});

app.post('/api/token/verify', (req, res) => {
  const { token } = req.body;
  res.json(verifyToken(token));
});

// PoW Challenge endpoint - client fetches this on page load
app.get('/api/pow/challenge', (req, res) => {
  const siteKey = req.query.siteKey || 'default';

  let ip = req.headers['x-real-ip'] || '';
  if (!ip) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      ip = forwarded.split(',')[0].trim();
    } else {
      ip = req.socket.remoteAddress;
    }
  }

  // Difficulty scaling based on IP reputation
  let difficulty = 4; // Default: ~100-500ms on average hardware

  // Increase difficulty for suspicious IPs
  if (detection.isDatacenterIP(ip)) {
    difficulty = 5; // ~1-3 seconds
  }

  // Check rate - high request rate gets harder challenges
  const rateKey = `pow:${siteKey}:${ip}`;
  const [exceeded, count] = rateLimiter.check(rateKey, 60, 20);
  if (count > 10) {
    difficulty = Math.min(6, difficulty + 1); // Up to difficulty 6
  }
  if (exceeded) {
    difficulty = 6; // Maximum difficulty for rate-limited IPs
  }

  const challenge = powChallengeStore.generate(siteKey, ip, difficulty);

  res.json({
    challengeId: challenge.id,
    prefix: challenge.prefix,
    difficulty: challenge.difficulty,
    expiresAt: challenge.expiresAt,
    sig: challenge.sig
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
});
