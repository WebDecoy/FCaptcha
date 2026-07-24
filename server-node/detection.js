/**
 * FCaptcha Detection Module - Additional Detection Capabilities
 *
 * IP Reputation, Header Analysis, Browser Consistency, TLS Fingerprinting
 */

const dns = require('dns').promises;
const net = require('net');

// =============================================================================
// Datacenter IP Ranges
// =============================================================================

const DATACENTER_CIDRS = [
  // AWS
  '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '34.0.0.0/8', '35.0.0.0/8',
  '52.0.0.0/8', '54.0.0.0/8', '99.0.0.0/8',
  // Google Cloud
  '34.64.0.0/10', '35.184.0.0/13', '104.154.0.0/15', '104.196.0.0/14',
  // Azure
  '13.64.0.0/11', '20.0.0.0/8', '40.64.0.0/10', '52.224.0.0/11',
  // DigitalOcean
  '64.225.0.0/16', '68.183.0.0/16', '104.131.0.0/16', '134.209.0.0/16',
  '138.68.0.0/16', '139.59.0.0/16', '142.93.0.0/16', '157.245.0.0/16',
  // Linode
  '45.33.0.0/16', '45.56.0.0/16', '45.79.0.0/16', '139.162.0.0/16',
  // Vultr
  '45.32.0.0/16', '45.63.0.0/16', '45.76.0.0/16', '108.61.0.0/16',
  // Hetzner
  '5.9.0.0/16', '46.4.0.0/14', '78.46.0.0/15', '88.99.0.0/16',
  '95.216.0.0/14', '135.181.0.0/16',
  // OVH
  '51.38.0.0/16', '51.68.0.0/16', '51.75.0.0/16', '137.74.0.0/16',
  '139.99.0.0/16', '144.217.0.0/16', '149.56.0.0/16',
];

const VPN_PROXY_PATTERNS = [
  /vpn/i, /proxy/i, /tor-exit/i, /exit-?node/i,
  /anonymizer/i, /tunnel/i, /relay/i
];

function ipToLong(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function cidrContains(cidr, ip) {
  const [range, bits] = cidr.split('/');
  const mask = ~((1 << (32 - parseInt(bits))) - 1) >>> 0;
  const rangeStart = ipToLong(range) & mask;
  const ipLong = ipToLong(ip);
  return (ipLong & mask) === rangeStart;
}

function isDatacenterIP(ip) {
  if (!net.isIPv4(ip)) return false;
  return DATACENTER_CIDRS.some(cidr => cidrContains(cidr, ip));
}

async function checkIPReputation(ip) {
  const detections = [];

  // Datacenter check
  if (isDatacenterIP(ip)) {
    detections.push({
      category: 'datacenter',
      score: 0.6,
      confidence: 0.8,
      reason: 'Request from known datacenter IP range'
    });
  }

  // Reverse DNS check
  try {
    const hostnames = await dns.reverse(ip);
    for (const hostname of hostnames) {
      for (const pattern of VPN_PROXY_PATTERNS) {
        if (pattern.test(hostname)) {
          detections.push({
            category: 'tor_vpn',
            score: 0.5,
            confidence: 0.6,
            reason: `Reverse DNS suggests VPN/proxy: ${hostname}`
          });
          break;
        }
      }
    }
  } catch (e) {
    // DNS lookup failed, not suspicious
  }

  return detections;
}

// =============================================================================
// HTTP Header Analysis
// =============================================================================

const SUSPICIOUS_HEADERS = new Set([
  'x-requested-with', 'x-forwarded-for', 'x-real-ip', 'via',
  'forwarded', 'x-originating-ip', 'cf-connecting-ip',
  'true-client-ip', 'x-cluster-client-ip'
]);

const EXPECTED_BROWSER_HEADERS = new Set([
  'accept', 'accept-language', 'accept-encoding', 'user-agent'
]);

// Self-identifying AI agents and crawlers. These agents are honest about who they
// are, so matching is high-confidence but intentionally LOW-severity: operators
// decide via policy whether to allow polite agents rather than hard-blocking.
// Keep in sync with server-go and server-python.
const DECLARED_AI_AGENT_PATTERNS = [
  /\bClaudeBot\b/i,
  /\bClaude-User\b/i,
  /\bClaude-SearchBot\b/i,
  /\banthropic-ai\b/i,
  /\bGPTBot\b/i,
  /\bChatGPT-User\b/i,
  /\bOAI-SearchBot\b/i,
  /\bPerplexityBot\b/i,
  /\bPerplexity-User\b/i,
  /\bGoogle-Extended\b/i,
  /\bCCBot\b/i,
  /\bBytespider\b/i,
  /\bmeta-externalagent\b/i,
  /\bAmazonbot\b/i,
  /\bcohere-ai\b/i,
  /\bDiffbot\b/i,
  /\bYouBot\b/i
];

// checkDeclaredAIAgent flags self-identifying AI agents via the User-Agent as
// the declared_ai category, so callers can apply an allow/block policy instead
// of relying on a hard score.
//
// Web Bot Auth signed requests (RFC 9421 HTTP Message Signatures) used to be
// detected here by header presence alone. That moved to webbotauth.js, which
// cryptographically verifies the signature against the agent's published key
// directory — a presence check can't tell a real signer from three spoofed
// headers. Verification needs the raw request, so it runs in the route handler;
// the headers argument is retained for signature parity with the Go server.
function checkDeclaredAIAgent(userAgent, headers = {}) {
  const detections = [];
  const ua = userAgent || '';

  for (const re of DECLARED_AI_AGENT_PATTERNS) {
    const match = ua.match(re);
    if (match) {
      detections.push({
        category: 'declared_ai',
        score: 0.5,
        confidence: 0.99,
        reason: `Declared AI agent user-agent: ${match[0]}`,
        details: { matched: match[0] }
      });
      break;
    }
  }

  return detections;
}

function analyzeHeaders(headers) {
  const detections = [];
  const headersLower = {};
  for (const [key, value] of Object.entries(headers)) {
    headersLower[key.toLowerCase()] = value;
  }

  // Check for missing expected headers
  let missingCount = 0;
  for (const header of EXPECTED_BROWSER_HEADERS) {
    if (!(header in headersLower)) {
      missingCount++;
    }
  }
  if (missingCount > 1) {
    detections.push({
      category: 'bot',
      score: 0.4,
      confidence: 0.5,
      reason: `Missing ${missingCount} expected browser headers`
    });
  }

  // Check for suspicious headers
  for (const header of Object.keys(headersLower)) {
    if (SUSPICIOUS_HEADERS.has(header)) {
      detections.push({
        category: 'bot',
        score: 0.3,
        confidence: 0.4,
        reason: `Suspicious header present: ${header}`
      });
    }
  }

  // Check Accept-Language
  const acceptLang = headersLower['accept-language'] || '';
  if (acceptLang === '' || acceptLang === '*') {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'Invalid Accept-Language header'
    });
  }

  // Check Accept-Encoding
  const acceptEnc = headersLower['accept-encoding'] || '';
  if (acceptEnc && !acceptEnc.includes('gzip') && !acceptEnc.includes('deflate')) {
    detections.push({
      category: 'bot',
      score: 0.2,
      confidence: 0.3,
      reason: 'Unusual Accept-Encoding'
    });
  }

  return detections;
}

// =============================================================================
// Browser Consistency Checks
// =============================================================================

const BOT_UA_PATTERNS = [
  /bot/i, /spider/i, /crawler/i, /scraper/i, /curl/i, /wget/i,
  /python/i, /java\//i, /httpie/i, /postman/i, /insomnia/i,
  /axios/i, /node-fetch/i, /go-http/i, /okhttp/i
];

function parseUserAgent(ua) {
  const info = { browser: null, os: null, isMobile: false, isBot: false, botName: null };

  // Check for bots
  for (const pattern of BOT_UA_PATTERNS) {
    const match = ua.match(pattern);
    if (match) {
      info.isBot = true;
      info.botName = match[0];
      return info;
    }
  }

  // Detect browser
  if (ua.includes('Edg/')) info.browser = 'Edge';
  else if (ua.includes('Chrome/')) info.browser = 'Chrome';
  else if (ua.includes('Firefox/')) info.browser = 'Firefox';
  else if (ua.includes('Safari/') && !ua.includes('Chrome')) info.browser = 'Safari';

  // Detect OS
  if (ua.includes('Windows')) info.os = 'Windows';
  else if (ua.includes('Mac OS X') || ua.includes('Macintosh')) info.os = 'macOS';
  else if (ua.includes('Linux')) info.os = 'Linux';
  else if (ua.includes('Android')) { info.os = 'Android'; info.isMobile = true; }
  else if (ua.includes('iPhone') || ua.includes('iPad')) { info.os = 'iOS'; info.isMobile = true; }

  if (ua.includes('Mobile')) info.isMobile = true;

  return info;
}

function checkBrowserConsistency(ua, signals) {
  const detections = [];
  const uaInfo = parseUserAgent(ua);

  // If UA is a known bot
  if (uaInfo.isBot) {
    detections.push({
      category: 'bot',
      score: 0.9,
      confidence: 0.95,
      reason: `User-Agent indicates bot: ${uaInfo.botName}`
    });
    return detections;
  }

  const env = signals.environmental || {};
  const nav = env.navigator || {};
  const automation = env.automationFlags || {};
  const platform = nav.platform || automation.platform || '';

  // Check platform consistency
  if (uaInfo.os === 'Windows' && !platform.includes('Win')) {
    detections.push({
      category: 'bot',
      score: 0.6,
      confidence: 0.7,
      reason: `UA/platform mismatch: UA claims Windows, platform=${platform}`
    });
  }

  if (uaInfo.os === 'macOS' && !platform.includes('Mac')) {
    detections.push({
      category: 'bot',
      score: 0.6,
      confidence: 0.7,
      reason: `UA/platform mismatch: UA claims macOS, platform=${platform}`
    });
  }

  if (uaInfo.os === 'Linux' && !platform.includes('Linux')) {
    detections.push({
      category: 'bot',
      score: 0.6,
      confidence: 0.7,
      reason: `UA/platform mismatch: UA claims Linux, platform=${platform}`
    });
  }

  // Check mobile consistency
  const maxTouch = nav.maxTouchPoints || automation.maxTouchPoints || 0;
  if (uaInfo.isMobile && maxTouch === 0) {
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: 'UA claims mobile but no touch support'
    });
  }

  // Check Chrome-specific properties
  if (uaInfo.browser === 'Chrome' && !automation.chrome) {
    detections.push({
      category: 'bot',
      score: 0.7,
      confidence: 0.8,
      reason: 'UA claims Chrome but window.chrome missing'
    });
  }

  return detections;
}

// =============================================================================
// TLS Fingerprinting (JA3)
// =============================================================================

const KNOWN_BOT_JA3_HASHES = {
  '3b5074b1b5d032e5620f69f9f700ff0e': 'Python requests',
  'b32309a26951912be7dba376398abc3b': 'Python urllib',
  '9e10692f1b7f78228b2d4e424db3a98c': 'Go net/http',
  '473cd7cb9faa642487833865d516e578': 'curl',
  'c12f54a3f91dc7bafd92cb59fe009a35': 'Wget',
  '2d1eb5817ece335c24904f516ad5da2f': 'Java HttpClient',
  'fc54fe03db02a25e1be5bb5a7678b7a4': 'Node.js axios',
  '579ccef312d18482fc42e2b822ca2430': 'Node.js node-fetch',
  '5d7974c9fe7862e0f9a3eb35a6a5d9c8': 'Puppeteer default',
};

function checkJA3Fingerprint(ja3Hash) {
  if (!ja3Hash) return [];

  if (KNOWN_BOT_JA3_HASHES[ja3Hash]) {
    return [{
      category: 'bot',
      score: 0.8,
      confidence: 0.9,
      reason: `TLS fingerprint matches: ${KNOWN_BOT_JA3_HASHES[ja3Hash]}`
    }];
  }

  return [];
}

// =============================================================================
// TLS Fingerprinting (JA4) — read from trusted reverse-proxy headers
// =============================================================================
//
// Unlike the client-supplied X-JA3-Hash (which attackers can spoof), JA4
// fingerprints are computed from the TLS ClientHello by the reverse proxy
// and passed via a trusted header the server is configured to accept.
// Configure with: TRUSTED_JA4_HEADERS=cf-ja4,x-tls-ja4 (comma-separated).

const KNOWN_BOT_JA4_HASHES = {
  // Populate with observed automation fingerprints in production.
  // JA4 format: t##d####_####..._####
  // Placeholders — administrators should add real fingerprints as they
  // are collected from deployed environments.
  // Example once identified:
  //   't13d1516h2_8daaf6152771_02713d6af862': 'Go default stdlib TLS'
};

function getTrustedJA4HeaderNames() {
  const env = process.env.TRUSTED_JA4_HEADERS;
  if (!env) return [];
  return env.split(',').map(h => h.trim().toLowerCase()).filter(Boolean);
}

function readJA4FromHeaders(headers, trustedHeaderNames) {
  if (!trustedHeaderNames || trustedHeaderNames.length === 0) return null;
  for (const name of trustedHeaderNames) {
    const v = headers[name];
    if (v && typeof v === 'string' && v.trim()) return v.trim();
  }
  return null;
}

function checkJA4Fingerprint(ja4) {
  if (!ja4) return [];
  const match = KNOWN_BOT_JA4_HASHES[ja4];
  if (match) {
    return [{
      category: 'fingerprint',
      score: 0.8,
      confidence: 0.9,
      reason: `TLS JA4 fingerprint matches: ${match}`
    }];
  }
  return [];
}

// =============================================================================
// Statistical Utility Functions (Keystroke Cadence Analysis)
// =============================================================================

function mean(arr) {
  if (arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stddev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  const variance = arr.reduce((acc, v) => acc + (v - m) * (v - m), 0) / arr.length;
  return Math.sqrt(variance);
}

function erf(x) {
  // Abramowitz & Stegun approximation (max error ~1.5e-7)
  const sign = x >= 0 ? 1 : -1;
  x = Math.abs(x);
  const t = 1.0 / (1.0 + 0.3275911 * x);
  const y = 1.0 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x);
  return sign * y;
}

function normalCDF(x, mu, sigma) {
  if (sigma <= 0) return x >= mu ? 1.0 : 0.0;
  return 0.5 * (1.0 + erf((x - mu) / (sigma * Math.SQRT2)));
}

function ksTestStatistic(samples, cdfFn) {
  const n = samples.length;
  if (n === 0) return 0;
  const sorted = [...samples].sort((a, b) => a - b);
  let maxD = 0;
  for (let i = 0; i < n; i++) {
    const empirical = (i + 1) / n;
    const theoretical = cdfFn(sorted[i]);
    const d1 = Math.abs(empirical - theoretical);
    const d2 = Math.abs((i / n) - theoretical);
    maxD = Math.max(maxD, d1, d2);
  }
  return maxD;
}

function shannonEntropy(arr, bins) {
  if (arr.length === 0) return 0;
  const min = Math.min(...arr);
  const max = Math.max(...arr);
  if (max === min) return 0;
  const binWidth = (max - min) / bins;
  const counts = new Array(bins).fill(0);
  for (const v of arr) {
    let idx = Math.floor((v - min) / binWidth);
    if (idx >= bins) idx = bins - 1;
    counts[idx]++;
  }
  const n = arr.length;
  let entropy = 0;
  for (const c of counts) {
    if (c > 0) {
      const p = c / n;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

function lag1Autocorrelation(arr) {
  if (arr.length < 3) return 0;
  const n = arr.length - 1;
  const x = arr.slice(0, n);
  const y = arr.slice(1);
  const mx = mean(x);
  const my = mean(y);
  let num = 0, dx2 = 0, dy2 = 0;
  for (let i = 0; i < n; i++) {
    const dx = x[i] - mx;
    const dy = y[i] - my;
    num += dx * dy;
    dx2 += dx * dx;
    dy2 += dy * dy;
  }
  const denom = Math.sqrt(dx2 * dy2);
  if (denom === 0) return 0;
  return num / denom;
}

// =============================================================================
// Keystroke Cadence Analysis
// =============================================================================

function analyzeKeystrokeCadence(stats) {
  const keyCount = stats.keyCount || 0;
  const intervals = stats.intervals || [];
  const dwellTimes = stats.dwellTimes || [];
  const rollovers = stats.rollovers || 0;

  // Gate on minimum data
  if (keyCount < 20 || intervals.length < 15) return null;

  const metrics = {};
  let totalWeight = 0;
  let weightedSum = 0;
  let activeMetricCount = 0;

  // 1. Dwell Variance (weight 0.15)
  if (dwellTimes.length >= 10) {
    const dSd = stddev(dwellTimes);
    let score;
    if (dSd < 3) score = 0;
    else if (dSd < 10) score = 0.35 * (dSd - 3) / 7;
    else if (dSd < 20) score = 0.35 + 0.65 * (dSd - 10) / 10;
    else score = 1.0;
    metrics.dwellVariance = score;
    totalWeight += 0.15;
    weightedSum += score * 0.15;
    activeMetricCount++;
  }

  // 2. Log-Normal Fit (weight 0.20)
  if (intervals.length >= 15) {
    const logIntervals = intervals.filter(v => v > 0).map(v => Math.log(v));
    if (logIntervals.length >= 10) {
      const mu = mean(logIntervals);
      const sigma = stddev(logIntervals);
      const D = ksTestStatistic(logIntervals, (x) => normalCDF(x, mu, sigma));
      // Critical value at α=0.10: 1.22 / sqrt(n)
      const critical = 1.22 / Math.sqrt(logIntervals.length);
      let score;
      if (D <= critical * 0.8) score = 1.0;
      else if (D <= critical) score = 0.7;
      else if (D <= critical * 1.5) score = 0.3;
      else score = 0;
      metrics.logNormalFit = score;
      totalWeight += 0.20;
      weightedSum += score * 0.20;
      activeMetricCount++;
    }
  }

  // 3. Uniformity Detection (weight 0.15)
  if (intervals.length >= 15) {
    const minI = Math.min(...intervals);
    const maxI = Math.max(...intervals);
    if (maxI > minI) {
      const D = ksTestStatistic(intervals, (x) => (x - minI) / (maxI - minI));
      // Low D = looks uniform = bot-like
      let score;
      if (D < 0.05) score = 0;
      else if (D < 0.1) score = 0.3;
      else if (D < 0.15) score = 0.6;
      else score = 1.0;
      metrics.uniformity = score;
      totalWeight += 0.15;
      weightedSum += score * 0.15;
      activeMetricCount++;
    }
  }

  // 4. Lag-1 Autocorrelation (weight 0.15)
  if (intervals.length >= 15) {
    const r = Math.abs(lag1Autocorrelation(intervals));
    let score;
    if (r < 0.02) score = 0.1;
    else if (r < 0.1) score = 0.1 + 0.4 * (r - 0.02) / 0.08;
    else if (r < 0.2) score = 0.5 + 0.4 * (r - 0.1) / 0.1;
    else if (r <= 0.4) score = 0.9;
    else if (r <= 0.6) score = 0.9 - 0.4 * (r - 0.4) / 0.2;
    else score = 0.5;
    metrics.autocorrelation = score;
    totalWeight += 0.15;
    weightedSum += score * 0.15;
    activeMetricCount++;
  }

  // 5. Burst Regularity (weight 0.10)
  const burstGaps = [];
  for (let i = 0; i < intervals.length; i++) {
    if (intervals[i] > 300) burstGaps.push(intervals[i]);
  }
  if (burstGaps.length >= 3) {
    const burstMean = mean(burstGaps);
    const burstSd = stddev(burstGaps);
    const cv = burstMean > 0 ? burstSd / burstMean : 0;
    let score;
    if (cv < 0.1) score = 0.1;
    else if (cv < 0.3) score = 0.1 + 0.9 * (cv - 0.1) / 0.2;
    else score = 1.0;
    metrics.burstRegularity = score;
    totalWeight += 0.10;
    weightedSum += score * 0.10;
    activeMetricCount++;
  }

  // 6. Shannon Entropy (weight 0.15)
  if (intervals.length >= 15) {
    const H = shannonEntropy(intervals, 10);
    // Bell curve scoring: peak around H≈2.5
    let score;
    if (H < 0.5) score = 0.1;
    else if (H < 1.5) score = 0.1 + 0.5 * (H - 0.5);
    else if (H < 2.0) score = 0.6 + 0.4 * (H - 1.5) / 0.5;
    else if (H <= 3.0) score = 1.0;
    else if (H <= 3.3) score = 0.7;
    else score = 0.4;
    metrics.entropy = score;
    totalWeight += 0.15;
    weightedSum += score * 0.15;
    activeMetricCount++;
  }

  // 7. Rollover Rate (weight 0.10)
  if (keyCount >= 30) {
    const rate = rollovers / keyCount;
    let score;
    if (rate === 0) score = 0.5;
    else if (rate < 0.05) score = 0.5 + 0.3 * (rate / 0.05);
    else if (rate < 0.15) score = 0.8 + 0.2 * ((rate - 0.05) / 0.1);
    else score = 1.0;
    metrics.rolloverRate = score;
    totalWeight += 0.10;
    weightedSum += score * 0.10;
    activeMetricCount++;
  }

  if (totalWeight === 0) return null;

  const humanScore = weightedSum / totalWeight;
  const botScore = 1.0 - humanScore;

  // Only emit detection when botScore > 0.55
  if (botScore <= 0.55) return null;

  return {
    category: 'bot',
    score: botScore * 0.7,
    confidence: Math.min(0.7, activeMetricCount / 7),
    reason: 'Keystroke cadence analysis indicates non-human typing pattern',
    details: { metrics, cadenceHumanScore: humanScore }
  };
}

// =============================================================================
// Form Interaction Analysis (Credential Stuffing & Spam Detection)
// =============================================================================

function analyzeFormInteraction(formAnalysis) {
  if (!formAnalysis) return [];

  const detections = [];
  const submit = formAnalysis.submit || {};

  // Check for programmatic form submission (credential stuffing)
  if (submit.method === 'programmatic' || submit.method === 'programmatic_click') {
    detections.push({
      category: 'bot',
      score: 0.8,
      confidence: 0.85,
      reason: `Form submitted programmatically (${submit.method})`
    });
  }

  // Check timing - too fast from page load to submit
  if (submit.timeSincePageLoad !== null && submit.timeSincePageLoad < 800) {
    detections.push({
      category: 'bot',
      score: 0.7,
      confidence: 0.75,
      reason: `Form submitted too quickly after page load (${Math.round(submit.timeSincePageLoad)}ms)`
    });
  }

  // Check timing - too fast from page load to first interaction
  const pageToFirst = formAnalysis.pageLoadToFirstInteraction;
  if (pageToFirst !== null && pageToFirst < 300) {
    detections.push({
      category: 'bot',
      score: 0.6,
      confidence: 0.65,
      reason: `First interaction too fast after page load (${Math.round(pageToFirst)}ms)`
    });
  }

  // Check for no trigger event before submit
  if (submit.eventsBeforeSubmit === 0 && submit.method !== 'none') {
    detections.push({
      category: 'bot',
      score: 0.9,
      confidence: 0.9,
      reason: 'Form submitted with no user interaction events'
    });
  }

  // Check for very low event count before submit
  if (submit.eventsBeforeSubmit > 0 && submit.eventsBeforeSubmit < 3 && submit.method !== 'none') {
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: `Very few events before submit (${submit.eventsBeforeSubmit})`
    });
  }

  // Textarea keyboard analysis (spam detection)
  const textareaData = formAnalysis.textareaKeyboard;
  if (textareaData) {
    for (const [fieldId, stats] of Object.entries(textareaData)) {
      // Programmatic fill: meaningful content appeared with zero keystrokes and
      // zero pastes (e.g. Playwright fill() / element.value=). The length gate
      // keeps this off browser autofill of short fields.
      if ((stats.contentLength || 0) > 8 && (stats.keyCount || 0) === 0 && (stats.pasteCount || 0) === 0) {
        detections.push({
          category: 'automation',
          score: 0.8,
          confidence: 0.75,
          reason: `Textarea "${fieldId}" filled programmatically (${stats.contentLength} chars, no keystrokes or paste)`
        });
      }

      // Check for paste-heavy input (spam bots often paste content)
      if (stats.pasteCount > 0 && stats.keyCount < 5) {
        detections.push({
          category: 'bot',
          score: 0.6,
          confidence: 0.6,
          reason: `Textarea "${fieldId}" filled mostly by paste (${stats.pasteCount} pastes, ${stats.keyCount} keystrokes)`
        });
      }

      // Check for unnaturally consistent typing (bots have perfect timing)
      if (stats.keyCount > 10 && stats.keyIntervalVariance < 100) {
        detections.push({
          category: 'bot',
          score: 0.5,
          confidence: 0.55,
          reason: `Textarea "${fieldId}" has unnaturally consistent typing rhythm`
        });
      }

      // Check for impossibly fast typing (< 50ms between keys = 1200+ WPM)
      if (stats.keyCount > 10 && stats.avgKeyInterval > 0 && stats.avgKeyInterval < 50) {
        detections.push({
          category: 'bot',
          score: 0.7,
          confidence: 0.7,
          reason: `Textarea "${fieldId}" typing speed impossibly fast (${Math.round(stats.avgKeyInterval)}ms/key)`
        });
      }

      // Check keydown/keyup ratio (should be ~1.0 for real typing)
      if (stats.keyCount > 10 && (stats.keydownUpRatio < 0.8 || stats.keydownUpRatio > 1.2)) {
        detections.push({
          category: 'bot',
          score: 0.4,
          confidence: 0.5,
          reason: `Textarea "${fieldId}" has abnormal keydown/keyup ratio (${stats.keydownUpRatio.toFixed(2)})`
        });
      }

      // Check for content without keyboard events (DOM manipulation - browser extensions, bots)
      if (stats.noKeyboardEvents && stats.contentLength > 0) {
        detections.push({
          category: 'bot',
          score: 0.75,
          confidence: 0.8,
          reason: `Textarea "${fieldId}" has ${stats.contentLength} chars but no keyboard events (DOM manipulation)`
        });
      }

      // Keystroke cadence analysis
      const cadenceResult = analyzeKeystrokeCadence(stats);
      if (cadenceResult) {
        detections.push(cadenceResult);
      }
    }
  }

  return detections;
}

// =============================================================================
// Advanced Fingerprint Detection Functions
// =============================================================================

/**
 * Analyze WebRTC signals for headless browser and VM detection
 */
function analyzeWebRTC(webrtcInfo) {
  if (!webrtcInfo || !webrtcInfo.supported) return [];

  const detections = [];

  // Check media devices - headless browsers typically have 0 devices
  const mediaDevices = webrtcInfo.mediaDevices || {};
  if (mediaDevices.supported && mediaDevices.totalDevices === 0) {
    detections.push({
      category: 'headless',
      score: 0.7,
      confidence: 0.75,
      reason: 'No media devices detected (typical of headless browsers)'
    });
  }

  // Suspicious: has video inputs but no audio (unusual)
  if (mediaDevices.supported && mediaDevices.videoInputs > 0 && mediaDevices.audioInputs === 0) {
    detections.push({
      category: 'bot',
      score: 0.4,
      confidence: 0.5,
      reason: 'Has video devices but no audio devices (unusual configuration)'
    });
  }

  // Check local IP detection - VMs and some headless setups may not expose local IPs
  if (webrtcInfo.hasLocalIP === false && !webrtcInfo.localIPError) {
    detections.push({
      category: 'headless',
      score: 0.4,
      confidence: 0.5,
      reason: 'No local IP addresses detected via WebRTC'
    });
  }

  return detections;
}

/**
 * Analyze Speech API signals - voices are OS/browser specific and hard to spoof
 */
function analyzeSpeechAPI(speechInfo) {
  if (!speechInfo || !speechInfo.supported) return [];

  const detections = [];

  // No voices at all - suspicious
  if (speechInfo.totalVoices === 0) {
    detections.push({
      category: 'headless',
      score: 0.6,
      confidence: 0.7,
      reason: 'No speech synthesis voices available'
    });
  }

  // Very few voices (less than 5) - could be headless or minimal VM
  if (speechInfo.totalVoices > 0 && speechInfo.totalVoices < 5) {
    detections.push({
      category: 'headless',
      score: 0.3,
      confidence: 0.4,
      reason: `Very few speech voices available (${speechInfo.totalVoices})`
    });
  }

  // No local voices - all remote/network voices suggests unusual setup
  if (speechInfo.localVoices === 0 && speechInfo.totalVoices > 0) {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'No local speech synthesis voices'
    });
  }

  return detections;
}

/**
 * Analyze Worker consistency - spoofed values often don't match between contexts
 */
function analyzeWorkerConsistency(workerConsistency) {
  if (!workerConsistency || !workerConsistency.supported) return [];

  const detections = [];

  // Mismatches indicate fingerprint spoofing
  if (!workerConsistency.consistent && workerConsistency.mismatchCount > 0) {
    const score = Math.min(0.9, 0.3 + (workerConsistency.mismatchCount * 0.15));
    detections.push({
      category: 'bot',
      score: score,
      confidence: 0.85,
      reason: `Worker/main thread mismatch detected: ${workerConsistency.mismatches.join(', ')}`
    });
  }

  return detections;
}

/**
 * Analyze CSS Media Queries for environment consistency
 */
function analyzeCSSMediaQueries(cssMedia, signals) {
  if (!cssMedia || !cssMedia.supported) return [];

  const detections = [];
  const nav = (signals.environmental || {}).navigator || {};

  // Check pointer consistency with touch capability
  const maxTouch = nav.maxTouchPoints || 0;
  if (cssMedia.pointer === 'coarse' && maxTouch === 0) {
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: 'CSS reports coarse pointer but no touch support'
    });
  }

  // Check hover capability - headless browsers may have unusual values
  if (cssMedia.hover === false && cssMedia.pointer === 'fine') {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'Fine pointer reported but no hover capability'
    });
  }

  // Forced colors mode with reduced motion - accessibility features
  // Note: These are NOT suspicious on their own, just for fingerprinting
  // Don't penalize accessibility users

  return detections;
}

/**
 * Analyze font detection results for consistency
 */
function analyzeFonts(fontsInfo, userAgent) {
  if (!fontsInfo || !fontsInfo.supported) return [];

  const detections = [];

  // Very few fonts detected could indicate headless browser
  if (fontsInfo.count < 3) {
    detections.push({
      category: 'headless',
      score: 0.5,
      confidence: 0.5,
      reason: `Very few fonts detected (${fontsInfo.count})`
    });
  }

  // Check OS-specific fonts against UA
  const ua = (userAgent || '').toLowerCase();

  // Windows UA but no Segoe UI
  if (ua.includes('windows') && fontsInfo.hasSegoeUI === false && fontsInfo.count > 5) {
    detections.push({
      category: 'bot',
      score: 0.5,
      confidence: 0.6,
      reason: 'Windows UA but Segoe UI font not detected'
    });
  }

  // Mac UA but no SF Pro (modern macOS)
  if ((ua.includes('mac os x') || ua.includes('macintosh')) && fontsInfo.hasSFPro === false &&
      ua.includes('10_15') === false && ua.includes('10_14') === false && fontsInfo.count > 5) {
    // SF Pro is on macOS 10.15+ (Catalina and later)
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'Modern macOS UA but SF Pro font not detected'
    });
  }

  // Linux UA but no DejaVu Sans (very common on Linux)
  if (ua.includes('linux') && !ua.includes('android') &&
      fontsInfo.hasDejaVuSans === false && fontsInfo.count > 5) {
    detections.push({
      category: 'bot',
      score: 0.4,
      confidence: 0.5,
      reason: 'Linux UA but DejaVu Sans font not detected'
    });
  }

  return detections;
}

/**
 * Analyze permissions/API availability for headless detection
 */
function analyzePermissions(permissionsInfo) {
  if (!permissionsInfo || !permissionsInfo.supported) return [];

  const detections = [];

  // Count available APIs
  const apiKeys = [
    'hasPermissionsAPI', 'hasClipboard', 'hasShare', 'hasCredentials',
    'hasBluetooth', 'hasUsb', 'hasSerial', 'hasHid', 'hasXR',
    'hasGeolocation', 'hasMIDI'
  ];

  const availableApis = apiKeys.filter(key => permissionsInfo[key] === true).length;

  // Very few APIs available could indicate minimal/headless browser
  if (availableApis < 3) {
    detections.push({
      category: 'headless',
      score: 0.4,
      confidence: 0.5,
      reason: `Very few navigator APIs available (${availableApis})`
    });
  }

  return detections;
}

/**
 * Analyze DOMRect/geometry fingerprint for rendering anomalies
 */
function analyzeDOMRect(domRectInfo) {
  if (!domRectInfo || !domRectInfo.supported) return [];

  const detections = [];

  // Check for zero or very small dimensions (rendering issues)
  if (domRectInfo.rectAWidth === 0 || domRectInfo.rectBWidth === 0) {
    detections.push({
      category: 'headless',
      score: 0.6,
      confidence: 0.7,
      reason: 'DOMRect rendering returned zero-width elements'
    });
  }

  // Check for exact integer values (unusual in real browsers)
  if (domRectInfo.rectAWidth === Math.floor(domRectInfo.rectAWidth) &&
      domRectInfo.rectBWidth === Math.floor(domRectInfo.rectBWidth) &&
      domRectInfo.rangeWidth === Math.floor(domRectInfo.rangeWidth)) {
    detections.push({
      category: 'bot',
      score: 0.3,
      confidence: 0.4,
      reason: 'DOMRect measurements are all exact integers (unusual)'
    });
  }

  return detections;
}

/**
 * Master function to analyze all advanced fingerprint signals
 */
function analyzeAdvancedSignals(signals, userAgent) {
  const detections = [];
  const env = signals.environmental || {};

  // WebRTC analysis
  if (env.webrtcInfo) {
    detections.push(...analyzeWebRTC(env.webrtcInfo));
  }

  // Speech API analysis
  if (env.speechInfo) {
    detections.push(...analyzeSpeechAPI(env.speechInfo));
  }

  // Worker consistency analysis
  if (env.workerConsistency) {
    detections.push(...analyzeWorkerConsistency(env.workerConsistency));
  }

  // CSS Media Queries analysis
  if (env.cssMediaQueries) {
    detections.push(...analyzeCSSMediaQueries(env.cssMediaQueries, signals));
  }

  // Font analysis
  if (env.fontsInfo) {
    detections.push(...analyzeFonts(env.fontsInfo, userAgent));
  }

  // Permissions analysis
  if (env.permissionsInfo) {
    detections.push(...analyzePermissions(env.permissionsInfo));
  }

  // DOMRect analysis
  if (env.domRectFingerprint) {
    detections.push(...analyzeDOMRect(env.domRectFingerprint));
  }

  return detections;
}

module.exports = {
  isDatacenterIP,
  checkIPReputation,
  analyzeHeaders,
  parseUserAgent,
  checkBrowserConsistency,
  checkDeclaredAIAgent,
  checkJA3Fingerprint,
  checkJA4Fingerprint,
  getTrustedJA4HeaderNames,
  readJA4FromHeaders,
  KNOWN_BOT_JA4_HASHES,
  analyzeFormInteraction,
  // Advanced fingerprint detection functions
  analyzeWebRTC,
  analyzeSpeechAPI,
  analyzeWorkerConsistency,
  analyzeCSSMediaQueries,
  analyzeFonts,
  analyzePermissions,
  analyzeDOMRect,
  analyzeAdvancedSignals
};
