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
    }
  }

  return detections;
}

module.exports = {
  isDatacenterIP,
  checkIPReputation,
  analyzeHeaders,
  parseUserAgent,
  checkBrowserConsistency,
  checkJA3Fingerprint,
  analyzeFormInteraction
};
