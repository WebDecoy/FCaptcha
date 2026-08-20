#!/usr/bin/env node
/**
 * FCaptcha Detection Test Suite
 *
 * Tests all detection capabilities against a running server.
 *
 * Usage: node test-detection.js [server-url]
 * Default: http://localhost:3000
 */

const SERVER_URL = process.argv[2] || 'http://localhost:3000';

// Token verification is a server-to-server call and requires the secret. The
// default matches the servers' own fallback, so `node test/test-detection.js`
// against a dev server keeps working with no setup; point it at a configured
// deployment by exporting the same value the server has.
const VERIFY_SECRET =
  process.env.FCAPTCHA_VERIFY_SECRET ||
  process.env.FCAPTCHA_SECRET ||
  'dev-secret-change-in-production';

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
};

function log(msg, color = '') {
  console.log(`${color}${msg}${colors.reset}`);
}

// Test results tracking
let passed = 0;
let failed = 0;
const results = [];

async function makeRequest(endpoint, options = {}) {
  const url = `${SERVER_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  try {
    const response = await fetch(url, {
      method: options.method || 'POST',
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    return await response.json();
  } catch (error) {
    return { error: error.message };
  }
}

// A verification that completes the real challenge handshake: fetch a challenge,
// stamp its nonce into signals.meta, commit the signals into the PoW input,
// solve, and wait out the server's timing floor.
//
// Needed because a proof of work is now a precondition for a token rather than
// one more scored signal. A payload posted without one is dispositively a
// non-browser, so it floors at 0.9 no matter how human the rest of it looks —
// which is correct, and which makes "a legitimate visitor scores low" impossible
// to assert without modelling a legitimate visitor properly.
//
// Detection-only assertions deliberately keep using makeRequest: they ask
// whether a payload trips a given detector, and that answer does not depend on
// the handshake. Only the tests that assert on the final score need this.
//
// Reuses the bench harness's solver rather than carrying a second copy of the
// scheme; it depends on nothing outside Node's crypto module.
const { buildVerifyBody } = require('../bench/lib/pow.js');

async function makeVerifiedRequest(options = {}) {
  const requested = options.body || {};
  const siteKey = requested.siteKey || 'test-site-key';
  const { body } = await buildVerifyBody(
    SERVER_URL,
    siteKey,
    requested.signals || {},
    options.headers || {}
  );
  return makeRequest('/api/verify', { ...options, body: { ...requested, ...body } });
}

function assertDetection(result, category, shouldDetect, testName) {
  const detections = result.detections || [];
  const hasCategory = detections.some(d => d.category === category);
  const success = shouldDetect ? hasCategory : !hasCategory;

  if (success) {
    passed++;
    results.push({ name: testName, status: 'PASS', score: result.score });
    log(`  ✓ ${testName}`, colors.green);
  } else {
    failed++;
    results.push({ name: testName, status: 'FAIL', score: result.score, detections });
    log(`  ✗ ${testName}`, colors.red);
    log(`    Expected ${category} detection: ${shouldDetect}, got: ${hasCategory}`, colors.dim);
    if (detections.length > 0) {
      log(`    Detections: ${detections.map(d => d.category).join(', ')}`, colors.dim);
    }
  }
  return success;
}

function assertScore(result, minScore, maxScore, testName) {
  const score = result.score;
  const success = score >= minScore && score <= maxScore;

  if (success) {
    passed++;
    results.push({ name: testName, status: 'PASS', score });
    log(`  ✓ ${testName} (score: ${score.toFixed(3)})`, colors.green);
  } else {
    failed++;
    results.push({ name: testName, status: 'FAIL', score });
    log(`  ✗ ${testName}`, colors.red);
    log(`    Expected score ${minScore}-${maxScore}, got: ${score.toFixed(3)}`, colors.dim);
  }
  return success;
}

// =============================================================================
// Test Cases
// =============================================================================

async function testHealthEndpoint() {
  log('\n[Health Check]', colors.cyan);

  try {
    const response = await fetch(`${SERVER_URL}/health`);
    const data = await response.json();
    if (data.status === 'ok') {
      passed++;
      log(`  ✓ Server is running`, colors.green);
      return true;
    }
  } catch (e) {
    failed++;
    log(`  ✗ Server not reachable at ${SERVER_URL}`, colors.red);
    log(`    Error: ${e.message}`, colors.dim);
    return false;
  }
}

async function testBotUserAgents() {
  log('\n[Bot User-Agent Detection]', colors.cyan);

  const botUAs = [
    { ua: 'curl/7.64.1', name: 'curl' },
    { ua: 'python-requests/2.28.0', name: 'Python requests' },
    { ua: 'Go-http-client/1.1', name: 'Go http client' },
    { ua: 'axios/1.4.0', name: 'axios' },
    { ua: 'node-fetch/3.0.0', name: 'node-fetch' },
    { ua: 'Java/11.0.2', name: 'Java' },
    { ua: 'Wget/1.21', name: 'Wget' },
    { ua: 'PostmanRuntime/7.32.0', name: 'Postman' },
    { ua: 'Googlebot/2.1', name: 'Googlebot' },
    { ua: 'Mozilla/5.0 (compatible; bingbot/2.0)', name: 'Bingbot' },
  ];

  for (const { ua, name } of botUAs) {
    const result = await makeRequest('/api/verify', {
      headers: { 'User-Agent': ua },
      body: { siteKey: 'test', signals: {} }
    });
    assertDetection(result, 'bot', true, `Detects ${name}`);
  }
}

async function testHeadlessBrowserDetection() {
  log('\n[Headless Browser Detection]', colors.cyan);

  // Test WebDriver flag
  const webdriverResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          webdriver: true,
        }
      }
    }
  });
  assertDetection(webdriverResult, 'headless', true, 'Detects WebDriver flag');

  // Test headless Chrome UA
  const headlessResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0',
    },
    body: { siteKey: 'test', signals: {} }
  });
  assertDetection(headlessResult, 'headless', true, 'Detects HeadlessChrome UA');

  // Test no plugins
  const noPluginsResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          automationFlags: {
            plugins: 0,
            languages: false,
          }
        }
      }
    }
  });
  assertDetection(noPluginsResult, 'headless', true, 'Detects no browser plugins');
}

async function testStealthArtifactDetection() {
  log('\n[Stealth Patch Artifact Detection]', colors.cyan);

  const chromeHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
  };
  // Benign env shared by the positive cases so the ONLY headless signal is the
  // stealth artifact under test (avoids plugins=0 etc. firing headless too).
  const benignEnv = {
    automationFlags: { plugins: 3, languages: true, chrome: true },
    webglInfo: { renderer: 'ANGLE (NVIDIA, GeForce RTX 3060 Direct3D11)' },
  };

  // Function.prototype.toString proxied -> stealth automation patch
  const toStringResult = await makeRequest('/api/verify', {
    headers: chromeHeaders,
    body: { siteKey: 'test', signals: { environmental: {
      ...benignEnv,
      stealthArtifacts: { signals: ['tostring_proxied'] },
    } } }
  });
  assertDetection(toStringResult, 'headless', true, 'Detects proxied Function.prototype.toString');

  // Notification.permission "denied" vs Permissions API "prompt" -> impossible state
  const permResult = await makeRequest('/api/verify', {
    headers: chromeHeaders,
    body: { siteKey: 'test', signals: { environmental: {
      ...benignEnv,
      permissionProbe: { supported: true, notificationPermission: 'denied', queryState: 'prompt', contradiction: true },
    } } }
  });
  assertDetection(permResult, 'headless', true, 'Detects Notification/Permissions API contradiction');

  // FP-safety: privacy-extension-style native patches (patched_*) and a
  // consistent human session must NOT raise the score — these artifacts are
  // collected for observability but intentionally never scored.
  const privacyExtResult = await makeVerifiedRequest({
    headers: chromeHeaders,
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          ...benignEnv,
          stealthArtifacts: { signals: ['patched_canvas_todataurl', 'patched_webgl_getparameter'] },
          permissionProbe: { supported: true, notificationPermission: 'default', queryState: 'prompt', contradiction: false },
        },
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.4, approachPoints: 20, approachDirectness: 0.6,
          overshootCorrections: 2, directionChanges: 8, interactionDuration: 3500,
          mouseEventRate: 45,
        },
      }
    }
  });
  assertScore(privacyExtResult, 0, 0.3, 'Privacy-extension native patches do not raise score (FP-safe)');
}

async function testDatacenterIPDetection() {
  log('\n[Datacenter IP Detection]', colors.cyan);

  const datacenterIPs = [
    { ip: '52.1.2.3', provider: 'AWS' },
    { ip: '34.102.1.1', provider: 'Google Cloud' },
    { ip: '20.1.2.3', provider: 'Azure' },
    { ip: '134.209.1.1', provider: 'DigitalOcean' },
    { ip: '45.33.1.1', provider: 'Linode' },
    { ip: '45.32.1.1', provider: 'Vultr' },
    { ip: '95.216.1.1', provider: 'Hetzner' },
    { ip: '51.38.1.1', provider: 'OVH' },
  ];

  for (const { ip, provider } of datacenterIPs) {
    const result = await makeRequest('/api/verify', {
      headers: {
        'X-Real-IP': ip,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      body: { siteKey: 'test', signals: {} }
    });
    assertDetection(result, 'datacenter', true, `Detects ${provider} IP (${ip})`);
  }

  // Test residential IP (should NOT detect)
  const residentialResult = await makeRequest('/api/verify', {
    headers: {
      'X-Real-IP': '73.15.22.100', // Comcast residential
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: { siteKey: 'test', signals: {} }
  });
  assertDetection(residentialResult, 'datacenter', false, 'Does NOT flag residential IP');
}

async function testHeaderAnalysis() {
  log('\n[HTTP Header Analysis]', colors.cyan);

  // Missing headers
  const missingHeadersResult = await makeRequest('/api/verify', {
    headers: {
      // Minimal headers - missing Accept, Accept-Language, Accept-Encoding
    },
    body: { siteKey: 'test', signals: {} }
  });
  assertDetection(missingHeadersResult, 'bot', true, 'Detects missing browser headers');

  // Invalid Accept-Language
  const badLangResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': '*',
    },
    body: { siteKey: 'test', signals: {} }
  });
  assertDetection(badLangResult, 'bot', true, 'Detects invalid Accept-Language');

  // Good headers (should have low score)
  const goodHeadersResult = await makeVerifiedRequest({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: { siteKey: 'test', signals: {
      behavioral: {
        totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
        microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
        interactionDuration: 1500, approachPoints: 12,
      }
    } }
  });
  assertScore(goodHeadersResult, 0, 0.3, 'Normal headers get low score');
}

async function testBrowserConsistency() {
  log('\n[Browser Consistency Checks]', colors.cyan);

  // Chrome UA but no window.chrome
  const noChromeResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          automationFlags: {
            chrome: false,
            platform: 'Win32',
          }
        }
      }
    }
  });
  assertDetection(noChromeResult, 'bot', true, 'Detects Chrome UA without window.chrome');

  // Windows UA but Mac platform
  const platformMismatchResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          automationFlags: {
            platform: 'MacIntel',
            chrome: true,
          }
        }
      }
    }
  });
  assertDetection(platformMismatchResult, 'bot', true, 'Detects UA/platform mismatch');

  // Mobile UA but no touch
  const noTouchResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          navigator: {
            maxTouchPoints: 0,
          }
        }
      }
    }
  });
  assertDetection(noTouchResult, 'bot', true, 'Detects mobile UA without touch support');

  // Consistent browser (should pass)
  const consistentResult = await makeVerifiedRequest({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
          interactionDuration: 1500, approachPoints: 12,
        },
        environmental: {
          automationFlags: {
            chrome: true,
            platform: 'MacIntel',
            plugins: 5,
          },
          navigator: {
            platform: 'MacIntel',
            maxTouchPoints: 0,
          }
        }
      }
    }
  });
  assertScore(consistentResult, 0, 0.3, 'Consistent browser gets low score');
}

async function testBehavioralSignals() {
  log('\n[Behavioral Signal Analysis]', colors.cyan);

  // Bot-like behavior: too fast, no variance
  const botBehaviorResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          interactionDuration: 50, // Too fast
          velocityVariance: 0.001, // Too consistent
          trajectoryLength: 200,
          totalPoints: 100,
          microTremorScore: 0.05, // No natural tremor
          straightLineRatio: 0.95, // Too straight
          directionChanges: 1,
        }
      }
    }
  });
  assertScore(botBehaviorResult, 0.3, 1.0, 'Bot-like behavior gets high score');

  // Human-like behavior
  const humanBehaviorResult = await makeVerifiedRequest({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          interactionDuration: 1500,
          velocityVariance: 0.8,
          trajectoryLength: 350,
          totalPoints: 80,
          microTremorScore: 0.6,
          straightLineRatio: 0.3,
          directionChanges: 15,
          overshootCorrections: 3,
          mouseEventRate: 60,
          eventDeltaVariance: 25,
        },
        environmental: {
          automationFlags: {
            chrome: true,
            platform: 'MacIntel',
            plugins: 5,
          }
        }
      }
    }
  });
  assertScore(humanBehaviorResult, 0, 0.3, 'Human-like behavior gets low score');
}

async function testVisionAIDetection() {
  log('\n[Vision AI Detection]', colors.cyan);

  // Suspicious PoW timing (too slow - external API latency)
  const slowPoWResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        temporal: {
          pow: {
            duration: 15000, // 15 seconds - way too slow
            iterations: 100000,
          }
        }
      }
    }
  });
  assertDetection(slowPoWResult, 'vision_ai', true, 'Detects slow PoW (external API latency)');

  // Suspiciously fast PoW
  const fastPoWResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        temporal: {
          pow: {
            duration: 10, // 10ms for 100k iterations - impossibly fast
            iterations: 100000,
          }
        }
      }
    }
  });
  assertDetection(fastPoWResult, 'vision_ai', true, 'Detects impossibly fast PoW');

  // No micro-tremor (vision AI uses perfect coordinates)
  const noTremorResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          microTremorScore: 0.05,
          trajectoryLength: 200,
        }
      }
    }
  });
  assertDetection(noTremorResult, 'vision_ai', true, 'Detects lack of micro-tremor');
}

async function testFormAnalysis() {
  log('\n[Form Interaction Analysis]', colors.cyan);

  // Test programmatic form submission
  const programmaticResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        formAnalysis: {
          pageLoadToFirstInteraction: 500,
          submit: {
            method: 'programmatic',
            timeSincePageLoad: 100,
            eventsBeforeSubmit: 0,
            hadTriggerEvent: false
          }
        }
      }
    }
  });
  assertDetection(programmaticResult, 'bot', true, 'Detects programmatic form.submit()');

  // Test too-fast submission
  const fastSubmitResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        formAnalysis: {
          pageLoadToFirstInteraction: 50,
          submit: {
            method: 'keyboard',
            timeSincePageLoad: 200,
            eventsBeforeSubmit: 3,
            hadTriggerEvent: true
          }
        }
      }
    }
  });
  assertDetection(fastSubmitResult, 'bot', true, 'Detects too-fast form submission');

  // Test no events before submit
  const noEventsResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        formAnalysis: {
          pageLoadToFirstInteraction: null,
          submit: {
            method: 'programmatic_click',
            timeSincePageLoad: 50,
            eventsBeforeSubmit: 0,
            hadTriggerEvent: false
          }
        }
      }
    }
  });
  assertDetection(noEventsResult, 'bot', true, 'Detects zero events before submit');

  // Test textarea spam patterns
  const spamTextareaResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        formAnalysis: {
          pageLoadToFirstInteraction: 1000,
          submit: {
            method: 'mouse',
            timeSincePageLoad: 2000,
            eventsBeforeSubmit: 15,
            hadTriggerEvent: true
          },
          textareaKeyboard: {
            message: {
              keyCount: 2,
              pasteCount: 3,
              avgKeyInterval: 100,
              keyIntervalVariance: 500,
              keydownUpRatio: 1.0
            }
          }
        }
      }
    }
  });
  assertDetection(spamTextareaResult, 'bot', true, 'Detects paste-heavy textarea input');

  // Test unnaturally fast typing
  const fastTypingResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        formAnalysis: {
          pageLoadToFirstInteraction: 1000,
          submit: {
            method: 'keyboard',
            timeSincePageLoad: 2000,
            eventsBeforeSubmit: 50,
            hadTriggerEvent: true
          },
          textareaKeyboard: {
            comment: {
              keyCount: 50,
              pasteCount: 0,
              avgKeyInterval: 20, // 20ms = impossibly fast
              keyIntervalVariance: 50,
              keydownUpRatio: 1.0
            }
          }
        }
      }
    }
  });
  assertDetection(fastTypingResult, 'bot', true, 'Detects impossibly fast textarea typing');

  // Test legitimate form submission
  const legitimateResult = await makeVerifiedRequest({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
          interactionDuration: 1500, approachPoints: 12,
        },
        formAnalysis: {
          pageLoadToFirstInteraction: 1500,
          pageLoadToNow: 5000,
          totalInteractionEvents: 25,
          submit: {
            method: 'keyboard',
            timeSincePageLoad: 4500,
            timeSinceFirstInteraction: 3000,
            eventsBeforeSubmit: 25,
            hadTriggerEvent: true
          },
          textareaKeyboard: {
            message: {
              keyCount: 30,
              pasteCount: 0,
              avgKeyInterval: 150, // ~400 chars/min - normal typing
              keyIntervalVariance: 2500,
              keydownUpRatio: 1.0
            }
          }
        },
        environmental: {
          automationFlags: {
            chrome: true,
            platform: 'MacIntel',
            plugins: 5,
          }
        }
      }
    }
  });
  assertScore(legitimateResult, 0, 0.3, 'Legitimate form submission gets low score');
}

async function testKeystrokeCadence() {
  log('\n[Keystroke Cadence Analysis]', colors.cyan);

  // Generate realistic log-normal intervals for human typing
  function generateHumanIntervals(n) {
    const intervals = [];
    // Simulate log-normal distribution with mu≈4.8 (~120ms median), sigma≈0.4
    const mu = 4.8, sigma = 0.4;
    // Use seeded pseudo-random for reproducibility
    let seed = 42;
    function rand() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }
    for (let i = 0; i < n; i++) {
      // Box-Muller transform
      const u1 = rand() || 0.001;
      const u2 = rand() || 0.001;
      const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      const val = Math.exp(mu + sigma * z);
      intervals.push(Math.max(40, Math.min(500, val)));
    }
    return intervals;
  }

  // a) Human cadence - should NOT increase score
  const humanIntervals = generateHumanIntervals(35);
  const humanDwellTimes = [];
  { let s = 42; function r() { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; }
    for (let i = 0; i < 30; i++) humanDwellTimes.push(25 + r() * 50); }

  const humanCadenceResult = await makeVerifiedRequest({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
          interactionDuration: 1500, approachPoints: 12,
        },
        formAnalysis: {
          pageLoadToFirstInteraction: 1500,
          submit: {
            method: 'keyboard',
            timeSincePageLoad: 5000,
            eventsBeforeSubmit: 40,
            hadTriggerEvent: true
          },
          textareaKeyboard: {
            message: {
              keyCount: 40, avgKeyInterval: 130, keyIntervalVariance: 3500,
              keydownUpRatio: 1.0, pasteCount: 0,
              intervals: humanIntervals,
              dwellTimes: humanDwellTimes,
              rollovers: 8
            }
          }
        },
        environmental: {
          automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 }
        }
      }
    }
  });
  assertScore(humanCadenceResult, 0, 0.3, 'Human cadence does NOT increase score');

  // b) Constant-timing bot - should increase score
  const constantIntervals = Array(35).fill(100);
  const constantDwellTimes = Array(30).fill(50);
  const constantBotResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
          interactionDuration: 1500, approachPoints: 12,
        },
        formAnalysis: {
          pageLoadToFirstInteraction: 1500,
          submit: {
            method: 'keyboard',
            timeSincePageLoad: 5000,
            eventsBeforeSubmit: 40,
            hadTriggerEvent: true
          },
          textareaKeyboard: {
            message: {
              keyCount: 40, avgKeyInterval: 100, keyIntervalVariance: 5,
              keydownUpRatio: 1.0, pasteCount: 0,
              intervals: constantIntervals,
              dwellTimes: constantDwellTimes,
              rollovers: 0
            }
          }
        },
        environmental: {
          automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 }
        }
      }
    }
  });
  // Verify cadence detection is present (primary check)
  const hasConstantCadence = (constantBotResult.detections || []).some(
    d => d.reason && d.reason.includes('Keystroke cadence')
  );
  if (hasConstantCadence) {
    passed++;
    log(`  ✓ Constant-timing bot triggers cadence detection (score: ${constantBotResult.score.toFixed(3)})`, colors.green);
  } else {
    failed++;
    log(`  ✗ Constant-timing bot did NOT trigger cadence detection`, colors.red);
  }

  // c) Alternating-jitter bot - should increase score
  // Bot adds mechanical timing variation: alternating 80/120ms
  const jitterIntervals = [];
  for (let i = 0; i < 35; i++) jitterIntervals.push(i % 2 === 0 ? 80 : 120);
  // Constant dwell times (no variance = bot)
  const jitterDwellTimes = Array(30).fill(50);

  const jitterBotResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
          interactionDuration: 1500, approachPoints: 12,
        },
        formAnalysis: {
          pageLoadToFirstInteraction: 1500,
          submit: {
            method: 'keyboard',
            timeSincePageLoad: 5000,
            eventsBeforeSubmit: 40,
            hadTriggerEvent: true
          },
          textareaKeyboard: {
            message: {
              keyCount: 40, avgKeyInterval: 100, keyIntervalVariance: 150,
              keydownUpRatio: 1.0, pasteCount: 0,
              intervals: jitterIntervals,
              dwellTimes: jitterDwellTimes,
              rollovers: 0
            }
          }
        },
        environmental: {
          automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 }
        }
      }
    }
  });
  const hasJitterCadence = (jitterBotResult.detections || []).some(
    d => d.reason && d.reason.includes('Keystroke cadence')
  );
  if (hasJitterCadence) {
    passed++;
    log(`  ✓ Random-jitter bot triggers cadence detection`, colors.green);
  } else {
    failed++;
    log(`  ✗ Random-jitter bot did NOT trigger cadence detection`, colors.red);
  }

  // d) Minimal data - should NOT trigger cadence
  const minimalResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
          interactionDuration: 1500, approachPoints: 12,
        },
        formAnalysis: {
          pageLoadToFirstInteraction: 1500,
          submit: {
            method: 'keyboard',
            timeSincePageLoad: 5000,
            eventsBeforeSubmit: 10,
            hadTriggerEvent: true
          },
          textareaKeyboard: {
            message: {
              keyCount: 8, avgKeyInterval: 100, keyIntervalVariance: 5,
              keydownUpRatio: 1.0, pasteCount: 0,
              intervals: [100, 100, 100, 100, 100],
              dwellTimes: [50, 50, 50, 50, 50],
              rollovers: 0
            }
          }
        },
        environmental: {
          automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 }
        }
      }
    }
  });
  const hasMinimalCadence = (minimalResult.detections || []).some(
    d => d.reason && d.reason.includes('Keystroke cadence')
  );
  if (!hasMinimalCadence) {
    passed++;
    log(`  ✓ Minimal data does NOT trigger cadence detection`, colors.green);
  } else {
    failed++;
    log(`  ✗ Minimal data incorrectly triggered cadence detection`, colors.red);
  }
}

async function testHeadRequests() {
  log('\n[HEAD requests]', colors.cyan);

  // Caching proxies revalidate with HEAD and uptime monitors commonly probe with
  // it, so a 405 on a working server reads as an outage. Go and Python both
  // answered 405 until v1.26.0 — chi's r.Get and Starlette's @app.get each
  // register the named method only, while Express routes HEAD to its GET
  // handler, so Node alone was correct and nothing compared them.
  for (const path of ['/health', '/fcaptcha.js']) {
    let status = 0;
    let contentType = '';
    try {
      const res = await fetch(`${SERVER_URL}${path}`, { method: 'HEAD' });
      status = res.status;
      contentType = res.headers.get('content-type') || '';
    } catch (e) {
      status = -1;
    }

    if (status === 200) {
      passed++;
      log(`  ✓ HEAD ${path} is answered`, colors.green);
    } else {
      failed++;
      log(`  ✗ HEAD ${path} returned ${status}`, colors.red);
    }

    // The widget carries non-ASCII translations, which are decoded using the
    // document's encoding unless the response says otherwise.
    if (path === '/fcaptcha.js') {
      if (/charset=utf-8/i.test(contentType)) {
        passed++;
        log(`  ✓ ${path} declares UTF-8`, colors.green);
      } else {
        failed++;
        log(`  ✗ ${path} content-type lacks charset=utf-8: "${contentType}"`, colors.red);
      }
    }
  }
}

async function testTokenVerification() {
  log('\n[Token Verification]', colors.cyan);

  // First get a valid token. Must complete the real handshake: a token is only
  // issued to a caller that solved the challenge.
  const verifyResult = await makeVerifiedRequest({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350,
          interactionDuration: 1500, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15,
          mouseEventRate: 60, approachPoints: 12,
        },
        environmental: {
          automationFlags: {
            chrome: true,
            platform: 'MacIntel',
            plugins: 5,
          }
        }
      }
    }
  });

  if (verifyResult.token) {
    // Verify the token
    const tokenResult = await makeRequest('/api/token/verify', {
      body: { token: verifyResult.token, secret: VERIFY_SECRET }
    });

    if (tokenResult.valid) {
      passed++;
      log(`  ✓ Token verification works (score: ${tokenResult.score})`, colors.green);
    } else {
      failed++;
      log(`  ✗ Token verification failed: ${tokenResult.reason}`, colors.red);
    }
  } else {
    log(`  - Skipped: No token generated (score too high: ${verifyResult.score})`, colors.yellow);
  }

  // Test invalid token
  const invalidResult = await makeRequest('/api/token/verify', {
    body: { token: 'invalid-token-here', secret: VERIFY_SECRET }
  });

  if (!invalidResult.valid) {
    passed++;
    log(`  ✓ Invalid token rejected`, colors.green);
  } else {
    failed++;
    log(`  ✗ Invalid token was accepted`, colors.red);
  }

  // A correct token with the wrong secret must be refused: this endpoint used to
  // accept any caller, so the gate is worth asserting rather than assuming.
  if (verifyResult.token) {
    const unauthorized = await makeRequest('/api/token/verify', {
      body: { token: verifyResult.token, secret: 'not-the-secret' }
    });

    if (!unauthorized.valid && unauthorized.reason === 'invalid_secret') {
      passed++;
      log(`  ✓ Token verification refuses a wrong secret`, colors.green);
    } else {
      failed++;
      log(`  ✗ Wrong secret was accepted: ${JSON.stringify(unauthorized)}`, colors.red);
    }
  }
}

async function testInvisibleMode() {
  log('\n[Invisible Mode Scoring]', colors.cyan);

  const result = await makeRequest('/api/score', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      action: 'login',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350,
          interactionDuration: 2000, velocityVariance: 0.5,
          directionChanges: 15, mouseEventRate: 60, approachPoints: 12,
        }
      }
    }
  });

  if (result.action === 'login' && typeof result.score === 'number') {
    passed++;
    log(`  ✓ Invisible scoring works (action: ${result.action}, score: ${result.score.toFixed(3)})`, colors.green);
  } else {
    failed++;
    log(`  ✗ Invisible scoring failed`, colors.red);
  }
}

async function testAdvancedDetections() {
  log('\n[Advanced Fingerprint Detection]', colors.cyan);

  // Test WebRTC detection - no media devices (headless indicator)
  const noMediaDevicesResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          webrtcInfo: {
            supported: true,
            mediaDevices: {
              supported: true,
              audioInputs: 0,
              audioOutputs: 0,
              videoInputs: 0,
              totalDevices: 0
            },
            hasLocalIP: false
          }
        }
      }
    }
  });
  assertDetection(noMediaDevicesResult, 'headless', true, 'Detects no media devices via WebRTC');

  // Test Speech API - no voices (headless indicator)
  const noVoicesResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          speechInfo: {
            supported: true,
            totalVoices: 0,
            localVoices: 0,
            languages: 0
          }
        }
      }
    }
  });
  assertDetection(noVoicesResult, 'headless', true, 'Detects no speech synthesis voices');

  // Test Worker consistency - mismatch detection
  const workerMismatchResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          workerConsistency: {
            supported: true,
            consistent: false,
            mismatches: ['userAgent', 'platform', 'timezone'],
            mismatchCount: 3
          }
        }
      }
    }
  });
  assertDetection(workerMismatchResult, 'bot', true, 'Detects worker/main thread mismatch');

  // Test Font detection - Windows UA without Segoe UI
  const noSegoeUIResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          fontsInfo: {
            supported: true,
            count: 10,
            hasArial: true,
            hasTimesNewRoman: true,
            hasSegoeUI: false,  // Should have this on Windows!
            hasSFPro: false,
            hasDejaVuSans: false
          }
        }
      }
    }
  });
  assertDetection(noSegoeUIResult, 'bot', true, 'Detects Windows UA without Segoe UI font');

  // Test very few fonts (headless indicator)
  const fewFontsResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          fontsInfo: {
            supported: true,
            count: 2,
            hasArial: true,
            hasTimesNewRoman: false,
            hasSegoeUI: false,
            hasSFPro: false,
            hasDejaVuSans: false
          }
        }
      }
    }
  });
  assertDetection(fewFontsResult, 'headless', true, 'Detects very few system fonts');

  // Test CSS Media Query inconsistency - coarse pointer but no touch
  const pointerMismatchResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          cssMediaQueries: {
            supported: true,
            pointer: 'coarse',  // Indicates touch device
            hover: false,
            anyPointer: 'coarse',
            anyHover: false
          },
          navigator: {
            maxTouchPoints: 0  // But no touch support!
          }
        }
      }
    }
  });
  assertDetection(pointerMismatchResult, 'bot', true, 'Detects CSS pointer/touch mismatch');

  // Test DOMRect with zero dimensions
  const zeroDOMRectResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          domRectFingerprint: {
            supported: true,
            hash: 'abc123',
            rectAWidth: 0,
            rectBWidth: 0,
            rangeWidth: 0
          }
        }
      }
    }
  });
  assertDetection(zeroDOMRectResult, 'headless', true, 'Detects zero-dimension DOMRect');

  // Test legitimate advanced signals (should pass)
  const legitimateAdvancedResult = await makeVerifiedRequest({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          automationFlags: {
            chrome: true,
            platform: 'MacIntel',
            plugins: 5,
          },
          webrtcInfo: {
            supported: true,
            mediaDevices: {
              supported: true,
              audioInputs: 2,
              audioOutputs: 2,
              videoInputs: 1,
              totalDevices: 5
            },
            hasLocalIP: true,
            localIPs: ['192.168.1.100']
          },
          speechInfo: {
            supported: true,
            totalVoices: 67,
            localVoices: 45,
            languages: 24,
            hasAppleVoices: true
          },
          workerConsistency: {
            supported: true,
            consistent: true,
            mismatches: [],
            mismatchCount: 0
          },
          fontsInfo: {
            supported: true,
            count: 18,
            hasArial: true,
            hasTimesNewRoman: true,
            hasSegoeUI: false,
            hasSFPro: true,  // Mac font
            hasDejaVuSans: false
          },
          cssMediaQueries: {
            supported: true,
            pointer: 'fine',
            hover: true,
            anyPointer: 'fine',
            anyHover: true,
            prefersColorScheme: 'dark',
            dynamicRange: 'high'
          },
          domRectFingerprint: {
            supported: true,
            hash: 'abc123def',
            rectAWidth: 167.234375,
            rectBWidth: 89.5625,
            rangeWidth: 167.234375
          },
          permissionsInfo: {
            supported: true,
            hasPermissionsAPI: true,
            hasClipboard: true,
            hasShare: true,
            hasCredentials: true,
            hasGeolocation: true,
            hasBluetooth: true
          }
        },
        behavioral: {
          totalPoints: 80, trajectoryLength: 350,
          interactionDuration: 1500, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15,
          mouseEventRate: 60, approachPoints: 12,
        }
      }
    }
  });
  assertScore(legitimateAdvancedResult, 0, 0.3, 'Legitimate advanced signals get low score');
}

async function testPlaywrightDetection() {
  log('\n[Playwright Detection]', colors.cyan);

  // Test playwright_globals signal
  const playwrightGlobalsResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          playwright: {
            detected: true,
            signals: ['playwright_globals']
          }
        }
      }
    }
  });
  assertDetection(playwrightGlobalsResult, 'headless', true, 'Detects Playwright globals');

  // Test webdriver_deleted signal
  const webdriverDeletedResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        environmental: {
          playwright: {
            detected: true,
            signals: ['webdriver_deleted', 'chrome_runtime_missing']
          }
        }
      }
    }
  });
  assertDetection(webdriverDeletedResult, 'headless', true, 'Detects deleted webdriver property');

  // Test no playwright signals (should not detect)
  const noPlaywrightResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
          interactionDuration: 1500, approachPoints: 12,
        },
        environmental: {
          playwright: {
            detected: false,
            signals: []
          },
          automationFlags: {
            chrome: true,
            platform: 'MacIntel',
            plugins: 5,
          }
        }
      }
    }
  });
  // Verify no playwright-related headless detections
  const playwrightDetections = (noPlaywrightResult.detections || []).filter(
    d => d.reason && d.reason.includes('Playwright')
  );
  if (playwrightDetections.length === 0) {
    passed++;
    log(`  ✓ No Playwright detection for clean browser`, colors.green);
  } else {
    failed++;
    log(`  ✗ False Playwright detection on clean browser`, colors.red);
  }
}

async function testMissingPoWHardFail() {
  log('\n[Missing PoW Hard Fail]', colors.cyan);

  // No PoW solution should result in a high score (blocked)
  const noPoWResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 80, trajectoryLength: 350, velocityVariance: 0.8,
          microTremorScore: 0.6, directionChanges: 15, mouseEventRate: 60,
          interactionDuration: 1500, approachPoints: 12,
        },
        environmental: {
          automationFlags: {
            chrome: true,
            platform: 'MacIntel',
            plugins: 5,
          }
        }
      }
      // Note: no powSolution
    }
  });

  // With bot weight 0.15 and score 0.9, the bot contribution alone is 0.135
  // This should push overall score above 0.1 at minimum
  const hasMissingPoW = (noPoWResult.detections || []).some(
    d => d.reason && d.reason.includes('No PoW solution')
  );
  if (hasMissingPoW) {
    passed++;
    log(`  ✓ Missing PoW detected with hard-fail score (overall: ${noPoWResult.score.toFixed(3)})`, colors.green);
  } else {
    failed++;
    log(`  ✗ Missing PoW not detected`, colors.red);
  }

  // Score should be higher than before (0.135 from bot alone)
  assertScore(noPoWResult, 0.1, 1.0, 'Missing PoW raises score significantly');

  // The bypass found on 2026-08-19: this exact request — no PoW, no browser —
  // was issued a valid token, because the bot category contributes at most its
  // 0.13 weight to a 0.5 threshold no matter how conclusive the evidence. A
  // proof of work is now a precondition, checked outside the score.
  if (!noPoWResult.token && noPoWResult.success === false) {
    passed++;
    log(`  ✓ Missing PoW is refused a token outright`, colors.green);
  } else {
    failed++;
    log(`  ✗ Missing PoW was issued a token (score ${noPoWResult.score})`, colors.red);
  }

  if (noPoWResult.reason === 'pow_not_satisfied') {
    passed++;
    log(`  ✓ Refusal names the failed precondition`, colors.green);
  } else {
    failed++;
    log(`  ✗ Expected reason 'pow_not_satisfied', got '${noPoWResult.reason}'`, colors.red);
  }

  // A solution referencing a challenge the server never issued must fare no
  // better than sending none at all.
  const forgedPoW = await makeRequest('/api/verify', {
    headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0' },
    body: {
      siteKey: 'test-site-key',
      signals: { behavioral: { totalPoints: 80, trajectoryLength: 350, approachPoints: 12 } },
      powSolution: { challengeId: 'forged', nonce: 1, hash: '0000deadbeef', signalsHash: 'x' },
    },
  });

  if (!forgedPoW.token && forgedPoW.success === false) {
    passed++;
    log(`  ✓ Forged PoW is refused a token outright`, colors.green);
  } else {
    failed++;
    log(`  ✗ Forged PoW was issued a token (score ${forgedPoW.score})`, colors.red);
  }
}

async function testTightenedExemptions() {
  log('\n[Tightened Accessibility Exemptions]', colors.cyan);

  // touchEvents: 1 should NO LONGER exempt from mouse-movement checks
  const singleTouchResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0,
          trajectoryLength: 0,
          approachPoints: 0,
          touchEvents: 1,
          keyEvents: 0,
        }
      }
    }
  });
  // With touchEvents=1 (below threshold of 3), mouse-movement detections should fire
  assertDetection(singleTouchResult, 'vision_ai', true, 'touchEvents=1 no longer exempts from detection');
  assertDetection(singleTouchResult, 'behavioral', true, 'touchEvents=1 no longer exempts behavioral');

  // touchEvents: 3 should still exempt (legitimate touch user)
  const legitimateTouchResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0,
          trajectoryLength: 0,
          approachPoints: 0,
          touchEvents: 3,
          keyEvents: 0,
          interactionDuration: 1500,
        }
      }
    }
  });
  // With touchEvents=3, mouse-movement detections should NOT fire
  assertDetection(legitimateTouchResult, 'vision_ai', false, 'touchEvents=3 still exempts vision_ai');
  assertDetection(legitimateTouchResult, 'behavioral', false, 'touchEvents=3 still exempts behavioral');

  // keyEvents: 1 should NO LONGER exempt
  const singleKeyResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0,
          trajectoryLength: 0,
          approachPoints: 0,
          touchEvents: 0,
          keyEvents: 1,
        }
      }
    }
  });
  assertDetection(singleKeyResult, 'vision_ai', true, 'keyEvents=1 no longer exempts from detection');

  // keyEvents: 2 with no mouse should still exempt (Tab + Enter)
  const legitimateKbdResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0,
          trajectoryLength: 0,
          approachPoints: 0,
          touchEvents: 0,
          keyEvents: 2,
          interactionDuration: 1500,
        }
      }
    }
  });
  assertDetection(legitimateKbdResult, 'vision_ai', false, 'keyEvents=2 with no mouse still exempts');
}

async function testAccessibilityFalsePositives() {
  log('\n[Accessibility False Positives]', colors.cyan);

  // These cases came out of the bench human panel (bench/), which captures real
  // browser traces for keyboard-only, screen-reader and touch users. Every
  // assertion below failed before the fixes it guards.

  // A mobile user who taps the checkbox without scrolling first produces
  // exactly one touch event. Requiring three meant they were scored as an AI
  // agent — "Zero mouse, touch, or keyboard events recorded" at confidence 0.9.
  const tapOnlyResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0,
          touchEvents: 1, touchTotalPoints: 1, pointerHasNonMouseType: true,
          pointerTypes: ['touch'], keyEvents: 0, interactionDuration: 1500,
        }
      }
    }
  });
  assertDetection(tapOnlyResult, 'vision_ai', false, 'A single corroborated tap exempts (mobile user who does not scroll)');
  assertDetection(tapOnlyResult, 'behavioral', false, 'A single corroborated tap exempts behavioral checks');

  // The corroboration matters: a bare touchEvents count with no matching
  // pointer data must not buy the exemption, or the previous hardening is undone.
  const bareCountResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0,
          touchEvents: 1, keyEvents: 0,
        }
      }
    }
  });
  assertDetection(bareCountResult, 'vision_ai', true, 'An uncorroborated touchEvents=1 still does not exempt');

  // The client reports approachDirectness 1 (perfectly straight) when there is
  // no approach path at all, so "unnaturally direct mouse path" used to fire on
  // every keyboard, screen-reader and touch user — the exact populations the
  // neighbouring checks exempt.
  const keyboardResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0,
          approachDirectness: 1, microTremorScore: 0.5,
          touchEvents: 0, keyEvents: 8, interactionDuration: 4000,
        }
      }
    }
  });
  assertDetection(keyboardResult, 'vision_ai', false, 'Keyboard-only user is not flagged for a mouse path they never made');

  // Same shape, screen-reader pacing: many tabs, long dwells, no pointer.
  const screenReaderResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0,
          approachDirectness: 1, microTremorScore: 0.5,
          touchEvents: 0, keyEvents: 12, interactionDuration: 12000,
        }
      }
    }
  });
  assertDetection(screenReaderResult, 'vision_ai', false, 'Screen-reader traversal is not flagged for a mouse path');

  // A real mouse user travelling in a dead-straight line still gets caught:
  // the fix gates on a path existing, it does not disable the check.
  const straightLineResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 40, trajectoryLength: 300, approachPoints: 20,
          approachDirectness: 0.99, microTremorScore: 0.5,
          touchEvents: 0, keyEvents: 0,
        }
      }
    }
  });
  assertDetection(straightLineResult, 'vision_ai', true, 'A real straight-line mouse path is still flagged');
}

async function testForwardingHeaderTrust() {
  log('\n[Forwarding Header Trust]', colors.cyan);

  // Behind a reverse proxy, CDN or load balancer every visitor carries these
  // headers. Scoring them unconditionally gave every visitor to every proxied
  // deployment a permanent bot detection — measured by the bench at 100% of the
  // human panel AND 100% of the agent corpus, so it separated nothing.
  //
  // These requests reach the server from loopback, which is in the default
  // trusted-proxy set, so the headers count as infrastructure rather than as an
  // anomaly.
  const behindProxy = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'X-Forwarded-For': '203.0.113.45',
      'CF-Connecting-IP': '203.0.113.45',
      'True-Client-IP': '203.0.113.45',
    },
    body: { siteKey: 'test', signals: { behavioral: { totalPoints: 40, trajectoryLength: 300 } } }
  });

  const headerHits = (behindProxy.detections || [])
    .filter(d => /Suspicious header present/.test(d.reason || ''));
  if (headerHits.length === 0) {
    passed++;
    results.push({ name: 'Forwarding headers from a trusted proxy are not suspicious', status: 'PASS' });
    log('  ✓ Forwarding headers from a trusted proxy are not suspicious', colors.green);
  } else {
    failed++;
    results.push({ name: 'Forwarding headers from a trusted proxy are not suspicious', status: 'FAIL' });
    log('  ✗ Forwarding headers from a trusted proxy are not suspicious', colors.red);
    log(`    Fired: ${headerHits.map(d => d.reason).join(', ')}`, colors.dim);
  }
}

async function testGenuineBrowserArtifacts() {
  log('\n[Genuine-Browser Artifact Signals]', colors.cyan);

  // Measured in a real Chrome 150 with navigator.webdriver === false: the
  // webdriver descriptor is present and configurable, and chrome.runtime is
  // absent on any page without a matching externally_connectable extension.
  // Both were being reported as Playwright artifacts and scored, so an ordinary
  // Chrome visitor carried a headless-category score of 0.771.
  const realChrome = await makeVerifiedRequest({
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
      'Accept-Language': 'en-US,en;q=0.9', 'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: { totalPoints: 40, trajectoryLength: 320, microTremorScore: 0.7, approachPoints: 18, directionChanges: 15, overshootCorrections: 2, velocityVariance: 0.08 },
        environmental: {
          playwright: { detected: true, signals: ['webdriver_configurable', 'chrome_runtime_missing'] },
          webdriver: false,
          automationFlags: { chrome: true, plugins: 5, platform: 'MacIntel' },
          navigator: { platform: 'MacIntel' }
        }
      }
    }
  });
  assertDetection(realChrome, 'headless', false, "A genuine Chrome's signals raise no headless detection");
  assertScore(realChrome, 0, 0.3, 'A genuine Chrome is allowed');

  // The signals that DO mean something must still work. Deleting the webdriver
  // property is deliberate tampering — no shipped browser omits it.
  const tampered = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/150.0.0.0 Safari/537.36',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: { totalPoints: 40, trajectoryLength: 320, microTremorScore: 0.7, approachPoints: 18 },
        environmental: {
          playwright: { detected: true, signals: ['webdriver_deleted', 'playwright_globals'] },
          automationFlags: { chrome: true, plugins: 5, platform: 'MacIntel' }
        }
      }
    }
  });
  assertDetection(tampered, 'headless', true, 'Deleted webdriver and Playwright globals are still detected');
}

async function testTouchSubmitIsNotProgrammatic() {
  log('\n[Touch Form Submission]', colors.cyan);

  // A tap produces a compatibility mousedown that can lag or be suppressed, and
  // the classifier previously consulted only keydown and mousedown within 100ms.
  // A genuine mobile submit was therefore liable to be read as programmatic.
  const mobileSignals = (method) => ({
    siteKey: 'test',
    signals: {
      behavioral: {
        totalPoints: 0, trajectoryLength: 0, approachPoints: 0,
        touchEvents: 1, touchTotalPoints: 1, pointerHasNonMouseType: true,
        keyEvents: 0, interactionDuration: 4000
      },
      environmental: {
        automationFlags: { platform: 'iPhone', chrome: false, plugins: 0 },
        navigator: { platform: 'iPhone', maxTouchPoints: 5 }
      },
      formAnalysis: {
        pageLoadToFirstInteraction: 2200,
        submit: { method, timeSincePageLoad: 9000, eventsBeforeSubmit: 12, hadTriggerEvent: method !== 'programmatic_click' }
      }
    }
  });
  const mobileHeaders = {
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
    'Accept-Language': 'en-US,en;q=0.9',
  };

  const tapped = await makeRequest('/api/verify', { headers: mobileHeaders, body: mobileSignals('touch') });
  const tappedFlagged = (tapped.detections || []).some(d => /submitted programmatically/i.test(d.reason));
  if (!tappedFlagged) {
    passed++;
    results.push({ name: 'A tap-submitted form is not flagged as programmatic', status: 'PASS' });
    log('  ✓ A tap-submitted form is not flagged as programmatic', colors.green);
  } else {
    failed++;
    results.push({ name: 'A tap-submitted form is not flagged as programmatic', status: 'FAIL' });
    log('  ✗ A tap-submitted form is not flagged as programmatic', colors.red);
  }

  // The check still has to work: a real programmatic submit is still caught.
  const scripted = await makeRequest('/api/verify', { headers: mobileHeaders, body: mobileSignals('programmatic_click') });
  const scriptedFlagged = (scripted.detections || []).some(d => /submitted programmatically/i.test(d.reason));
  if (scriptedFlagged) {
    passed++;
    results.push({ name: 'A programmatic submit is still flagged', status: 'PASS' });
    log('  ✓ A programmatic submit is still flagged', colors.green);
  } else {
    failed++;
    results.push({ name: 'A programmatic submit is still flagged', status: 'FAIL' });
    log('  ✗ A programmatic submit is still flagged', colors.red);
  }
}

async function testMobileSensorDetection() {
  log('\n[Mobile Sensor & Touch Authenticity]', colors.cyan);

  const mobileUA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148';
  const desktopUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';

  // ---- Mobile UA with flat/synthetic touch force → behavioral detection fires ----
  const syntheticTouchResult = await makeRequest('/api/verify', {
    headers: { 'User-Agent': mobileUA, 'Accept-Language': 'en-US,en;q=0.9' },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0, keyEvents: 0,
          touchEvents: 10,
          touchTotalPoints: 10,
          touchForceMin: 1, touchForceMax: 1, touchForceVariance: 0,
          touchForceAllOne: true,
          touchRadiusMin: 0, touchRadiusMax: 0, touchRadiusVariance: 0,
          touchUniqueIdentifiers: 1,
          interactionDuration: 1500,
        }
      }
    }
  });
  assertDetection(syntheticTouchResult, 'behavioral', true,
    'Mobile UA with force=1 across all touches triggers behavioral detection');

  // ---- Mobile UA with healthy touch entropy → should NOT trigger new detectors ----
  const realTouchResult = await makeRequest('/api/verify', {
    headers: { 'User-Agent': mobileUA, 'Accept-Language': 'en-US,en;q=0.9' },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0, keyEvents: 0,
          touchEvents: 12,
          touchTotalPoints: 12,
          touchForceMin: 0.2, touchForceMax: 0.95, touchForceVariance: 0.08,
          touchForceAllOne: false, touchForceAllZero: false,
          touchRadiusMin: 14, touchRadiusMax: 28, touchRadiusVariance: 12,
          touchUniqueIdentifiers: 3,
          touchMultiTouchSeen: true,
          touchStraightLineRatio: 0.3,
          touchMicroTremorScore: 0.4,
          touchDirectionChanges: 8,
          interactionDuration: 2100,
        }
      }
    }
  });
  // Base touch score may still be non-zero due to other signals, but the three
  // new behavioral sub-detectors (force-variance, all-ones, radius uniformity,
  // identifiers) must not fire on this fixture.
  const realTouchBehavioralReasons = (realTouchResult.detections || [])
    .filter(d => d.category === 'behavioral')
    .map(d => d.reason || '');
  const didSyntheticFire = realTouchBehavioralReasons.some(r =>
    /synthetic|identical|lack identifier|unnaturally smooth|force=1\.0/i.test(r));
  if (!didSyntheticFire) {
    passed++;
    log('  ✓ Mobile UA with healthy touch entropy does not trigger synthetic-touch detectors', colors.green);
  } else {
    failed++;
    log('  ✗ Mobile UA with healthy touch entropy triggered a synthetic-touch detector', colors.red);
    log(`    Reasons: ${realTouchBehavioralReasons.join(' | ')}`, colors.dim);
  }

  // ---- Mobile UA with flat motion sensor → headless detection fires ----
  const flatSensorResult = await makeRequest('/api/verify', {
    headers: { 'User-Agent': mobileUA, 'Accept-Language': 'en-US,en;q=0.9' },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0, keyEvents: 0,
          touchEvents: 5, touchTotalPoints: 5,
          touchForceMin: 0.3, touchForceMax: 0.8, touchForceVariance: 0.05,
          touchRadiusMin: 12, touchRadiusMax: 22, touchRadiusVariance: 8,
          touchUniqueIdentifiers: 2,
          interactionDuration: 1500,
        },
        environmental: {
          sensor: {
            motionEventCount: 30,
            motionAccelVariance: 0.0001,
            orientationEventCount: 0,
            orientationVariance: 0,
          }
        }
      }
    }
  });
  const flatSensorReasons = (flatSensorResult.detections || [])
    .filter(d => d.category === 'headless')
    .map(d => d.reason || '');
  const motionFlatFired = flatSensorReasons.some(r => /sensor active but flat/i.test(r));
  if (motionFlatFired) {
    passed++;
    log('  ✓ Flat motion sensor on mobile UA triggers headless detection', colors.green);
  } else {
    failed++;
    log('  ✗ Flat motion sensor on mobile UA did not trigger headless detection', colors.red);
    log(`    Detections: ${(flatSensorResult.detections || []).map(d => d.category).join(', ')}`, colors.dim);
  }

  // ---- Mobile UA with NO sensor events → neutral (iOS w/o permission) ----
  const noSensorResult = await makeRequest('/api/verify', {
    headers: { 'User-Agent': mobileUA, 'Accept-Language': 'en-US,en;q=0.9' },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0, keyEvents: 0,
          touchEvents: 5, touchTotalPoints: 5,
          touchForceMin: 0.3, touchForceMax: 0.8, touchForceVariance: 0.05,
          touchRadiusMin: 12, touchRadiusMax: 22, touchRadiusVariance: 8,
          touchUniqueIdentifiers: 2,
          interactionDuration: 1500,
        },
        environmental: {
          sensor: {
            motionEventCount: 0, motionAccelVariance: 0,
            orientationEventCount: 0, orientationVariance: 0,
          }
        }
      }
    }
  });
  const noSensorReasons = (noSensorResult.detections || [])
    .filter(d => d.category === 'headless')
    .map(d => d.reason || '');
  const noSensorFalsePositive = noSensorReasons.some(r => /sensor active but flat/i.test(r));
  if (!noSensorFalsePositive) {
    passed++;
    log('  ✓ Absent sensor events on mobile UA treated as neutral (no penalty)', colors.green);
  } else {
    failed++;
    log('  ✗ Absent sensor events on mobile UA incorrectly triggered sensor detector', colors.red);
  }

  // ---- Desktop UA with flat sensor → mobile detectors must skip ----
  const desktopFlatSensorResult = await makeRequest('/api/verify', {
    headers: { 'User-Agent': desktopUA, 'Accept-Language': 'en-US,en;q=0.9' },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 50, trajectoryLength: 300, approachPoints: 15,
          touchEvents: 0, keyEvents: 0,
          velocityVariance: 0.5, microTremorScore: 0.3, straightLineRatio: 0.4,
          interactionDuration: 2000,
        },
        environmental: {
          sensor: {
            motionEventCount: 30, motionAccelVariance: 0.0001,
            orientationEventCount: 20, orientationVariance: 0.0001,
          }
        }
      }
    }
  });
  const desktopHeadlessReasons = (desktopFlatSensorResult.detections || [])
    .filter(d => d.category === 'headless')
    .map(d => d.reason || '');
  const desktopSensorFired = desktopHeadlessReasons.some(r => /sensor active but flat/i.test(r));
  if (!desktopSensorFired) {
    passed++;
    log('  ✓ Desktop UA: sensor detector skipped (UA gate works)', colors.green);
  } else {
    failed++;
    log('  ✗ Desktop UA: sensor detector wrongly fired', colors.red);
  }

  // ---- Mobile UA with straight-line touch trajectory → kinematics detector fires ----
  const straightTouchResult = await makeRequest('/api/verify', {
    headers: { 'User-Agent': mobileUA, 'Accept-Language': 'en-US,en;q=0.9' },
    body: {
      siteKey: 'test',
      signals: {
        behavioral: {
          totalPoints: 0, trajectoryLength: 0, approachPoints: 0, keyEvents: 0,
          touchEvents: 25, touchTotalPoints: 25,
          touchForceMin: 0.3, touchForceMax: 0.7, touchForceVariance: 0.04,
          touchRadiusMin: 12, touchRadiusMax: 20, touchRadiusVariance: 6,
          touchUniqueIdentifiers: 2,
          touchStraightLineRatio: 0.95,
          touchMicroTremorScore: 0.3,
          touchDirectionChanges: 3,
          interactionDuration: 1500,
        }
      }
    }
  });
  const kinematicsReasons = (straightTouchResult.detections || [])
    .filter(d => d.category === 'behavioral')
    .map(d => d.reason || '');
  const kinematicsFired = kinematicsReasons.some(r => /too straight|automation pattern/i.test(r));
  if (kinematicsFired) {
    passed++;
    log('  ✓ Straight-line touch path triggers kinematics detector', colors.green);
  } else {
    failed++;
    log('  ✗ Straight-line touch path did not trigger kinematics detector', colors.red);
    log(`    Behavioral reasons: ${kinematicsReasons.join(' | ')}`, colors.dim);
  }
}

// Adaptive challenge cost. The escalation lives on the wall-clock floor rather
// than on difficulty, because a native solver clears difficulty 6 in about a
// millisecond while a budget phone spends about sixteen seconds on it — so
// raising difficulty taxes slow devices and constrains nobody.
async function testAdaptiveChallengeCost() {
  log('\n[Adaptive Challenge Cost]', colors.cyan);

  const { createHash } = await import('crypto');
  const solve = (prefix, difficulty, signalsHash) => {
    const target = '0'.repeat(difficulty);
    for (let nonce = 0; nonce < 10000000; nonce++) {
      const hash = createHash('sha256').update(`${prefix}:${signalsHash}:${nonce}`).digest('hex');
      if (hash.startsWith(target)) return { nonce, hash };
    }
    return null;
  };

  const challengeFor = async (ip) => {
    const res = await fetch(`${SERVER_URL}/api/pow/challenge?siteKey=adaptive`, {
      headers: { 'X-Forwarded-For': ip },
    });
    return res.json();
  };

  // A visitor who has done nothing wrong pays exactly what everyone paid before
  // adaptive cost existed.
  const clean = await challengeFor('192.0.2.150');
  if (clean.difficulty === 4 && clean.minAgeMs === 1500) {
    passed++;
    log('  ✓ A clean source pays the baseline (difficulty 4, 1500ms)', colors.green);
  } else {
    failed++;
    log(`  ✗ A clean source should pay the baseline, got difficulty ${clean.difficulty} / ${clean.minAgeMs}ms`, colors.red);
  }

  // Drive one address to a strong verdict repeatedly, then confirm its next
  // challenge costs more time — and no more hashing than the cap allows.
  const abuser = '192.0.2.151';
  // navigator.webdriver === true is dispositive, so this lands at or above the
  // 0.8 the ledger requires. Anything weaker is deliberately not recorded.
  const botSignals = {
    behavioral: { totalPoints: 0, trajectoryLength: 0, keyEvents: 0, touchEvents: 0 },
    environmental: { webdriver: true, automationFlags: { plugins: 0 } },
  };
  for (let i = 0; i < 6; i++) {
    await fetch(`${SERVER_URL}/api/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': abuser },
      body: JSON.stringify({ siteKey: 'adaptive', signals: botSignals }),
    });
  }

  const escalated = await challengeFor(abuser);
  if (escalated.minAgeMs > clean.minAgeMs) {
    passed++;
    log(`  ✓ A source with strong verdicts is charged more time (${escalated.minAgeMs}ms vs ${clean.minAgeMs}ms)`, colors.green);
  } else {
    failed++;
    log(`  ✗ A source with strong verdicts should be charged more time, got ${escalated.minAgeMs}ms`, colors.red);
  }

  if (escalated.difficulty <= 5) {
    passed++;
    log(`  ✓ Difficulty stays at or below 5 under escalation (got ${escalated.difficulty})`, colors.green);
  } else {
    failed++;
    log(`  ✗ Difficulty reached ${escalated.difficulty}; the escalation belongs on the time floor`, colors.red);
  }

  // Submitting before that source's floor is scored — but as contributory
  // evidence, not as a verdict, because an older cached client does not know to
  // wait and would otherwise be punished for the delay it was never told about.
  const signals = {
    behavioral: {
      totalPoints: 80, trajectoryLength: 350, interactionDuration: 1500,
      velocityVariance: 0.8, microTremorScore: 0.6, directionChanges: 15,
      mouseEventRate: 60, approachPoints: 12,
    },
    environmental: { automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 } },
    meta: { challengeNonce: escalated.nonce },
  };
  const signalsJson = JSON.stringify(signals);
  const signalsHash = createHash('sha256').update(signalsJson).digest('hex');
  const solution = solve(escalated.prefix, escalated.difficulty, signalsHash);

  // Past the universal baseline, short of this source's own floor.
  await new Promise((r) => setTimeout(r, 1700));

  const res = await fetch(`${SERVER_URL}/api/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': abuser },
    body: JSON.stringify({
      siteKey: 'adaptive',
      signals,
      signalsJson,
      powSolution: {
        challengeId: escalated.challengeId,
        nonce: solution.nonce,
        hash: solution.hash,
        signalsHash,
      },
    }),
  });
  const verdict = await res.json();
  const reasons = (verdict.detections || []).map((d) => d.reason || '');
  const early = reasons.find((r) => r.includes('before the required delay'));
  const tooFast = reasons.find((r) => r.includes('solved too fast'));

  if (early) {
    passed++;
    log('  ✓ Submitting before the source-specific floor is detected', colors.green);
  } else {
    failed++;
    log(`  ✗ Submitting before the source-specific floor was not detected. Reasons: ${reasons.join(' | ')}`, colors.red);
  }

  if (!tooFast) {
    passed++;
    log('  ✓ Past the universal baseline, the strong "too fast" detection stays quiet', colors.green);
  } else {
    failed++;
    log('  ✗ The strong "too fast" detection fired past the universal baseline', colors.red);
  }
}

async function testProofOfWork() {
  log('\n[Proof of Work]', colors.cyan);

  const { createHash } = await import('crypto');

  // Helper: solve PoW with optional signalsHash
  function solvePoW(prefix, difficulty, signalsHash = null) {
    const target = '0'.repeat(difficulty);
    const inputPrefix = signalsHash ? `${prefix}:${signalsHash}` : prefix;
    let nonce = 0;
    const maxIterations = 10000000;

    while (nonce < maxIterations) {
      const input = `${inputPrefix}:${nonce}`;
      const hash = createHash('sha256').update(input).digest('hex');
      if (hash.startsWith(target)) {
        return { nonce, hash };
      }
      nonce++;
    }
    return null;
  }

  // Test getting a PoW challenge
  try {
    const challengeResponse = await fetch(`${SERVER_URL}/api/pow/challenge?siteKey=test`);
    const challenge = await challengeResponse.json();

    if (challenge.challengeId && challenge.prefix && challenge.difficulty && challenge.nonce) {
      passed++;
      log(`  ✓ PoW challenge endpoint works (difficulty: ${challenge.difficulty}, has nonce)`, colors.green);
    } else {
      failed++;
      log(`  ✗ PoW challenge response missing fields (need challengeId, prefix, difficulty, nonce)`, colors.red);
      return;
    }

    // Build signals with challengeNonce
    const signals = {
      behavioral: {
        totalPoints: 80, trajectoryLength: 350,
        interactionDuration: 1500, velocityVariance: 0.8,
        microTremorScore: 0.6, directionChanges: 15,
        mouseEventRate: 60, approachPoints: 12,
      },
      environmental: {
        automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 }
      },
      meta: {
        challengeNonce: challenge.nonce,
      }
    };

    const signalsJson = JSON.stringify(signals);
    const signalsHash = createHash('sha256').update(signalsJson).digest('hex');

    log(`    Solving PoW with signalsHash (difficulty: ${challenge.difficulty})...`, colors.dim);
    const solution = solvePoW(challenge.prefix, challenge.difficulty, signalsHash);

    if (!solution) {
      failed++;
      log(`  ✗ Failed to solve PoW within iteration limit`, colors.red);
      return;
    }

    passed++;
    log(`  ✓ PoW solved in ${solution.nonce} iterations`, colors.green);

    // Submit with valid PoW solution + signal commitment
    const validPoWResult = await makeRequest('/api/verify', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
      },
      body: {
        siteKey: 'test',
        signals,
        signalsJson,
        powSolution: {
          challengeId: challenge.challengeId,
          nonce: solution.nonce,
          hash: solution.hash,
          signalsHash
        },
        powTiming: { duration: 500, iterations: solution.nonce, difficulty: challenge.difficulty }
      }
    });

    // Should not have "No PoW solution provided" detection
    const hasNoPowDetection = (validPoWResult.detections || []).some(
      d => d.reason && d.reason.includes('No PoW solution')
    );
    if (!hasNoPowDetection) {
      passed++;
      log(`  ✓ Valid PoW solution accepted (score: ${validPoWResult.score.toFixed(3)})`, colors.green);
    } else {
      failed++;
      log(`  ✗ Valid PoW solution was not accepted`, colors.red);
    }

    // Should not have signal tampering detection
    const hasTamperDetection = (validPoWResult.detections || []).some(
      d => d.reason && d.reason.includes('tampered')
    );
    if (!hasTamperDetection) {
      passed++;
      log(`  ✓ Signal commitment verified successfully`, colors.green);
    } else {
      failed++;
      log(`  ✗ Valid signal commitment was flagged as tampered`, colors.red);
    }

    // Should not have nonce mismatch detection
    const hasNonceMismatch = (validPoWResult.detections || []).some(
      d => d.reason && d.reason.includes('nonce mismatch')
    );
    if (!hasNonceMismatch) {
      passed++;
      log(`  ✓ Challenge nonce verified successfully`, colors.green);
    } else {
      failed++;
      log(`  ✗ Valid challenge nonce was flagged as mismatch`, colors.red);
    }

    // Test: PoW solution replay attack (same solution used twice)
    const replayResult = await makeRequest('/api/verify', {
      headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0' },
      body: {
        siteKey: 'test',
        signals: {},
        powSolution: {
          challengeId: challenge.challengeId,
          nonce: solution.nonce,
          hash: solution.hash,
          signalsHash
        }
      }
    });

    const hasReplayDetection = (replayResult.detections || []).some(
      d => d.reason && (d.reason.includes('already_used') || d.reason.includes('not_found'))
    );
    if (hasReplayDetection) {
      passed++;
      log(`  ✓ PoW replay attack prevented`, colors.green);
    } else {
      failed++;
      log(`  ✗ PoW replay attack not detected`, colors.red);
    }

  } catch (error) {
    failed++;
    log(`  ✗ PoW test error: ${error.message}`, colors.red);
  }

  // Test: No PoW solution provided
  const noPoWResult = await makeRequest('/api/verify', {
    headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0' },
    body: { siteKey: 'test', signals: {} }
  });

  const hasMissingPoWDetection = (noPoWResult.detections || []).some(
    d => d.reason && d.reason.includes('No PoW solution')
  );
  if (hasMissingPoWDetection) {
    passed++;
    log(`  ✓ Missing PoW solution detected`, colors.green);
  } else {
    failed++;
    log(`  ✗ Missing PoW not detected`, colors.red);
  }

  // Test: Invalid PoW hash
  const invalidHashResult = await makeRequest('/api/verify', {
    headers: { 'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0' },
    body: {
      siteKey: 'test',
      signals: {},
      powSolution: { challengeId: 'fake-challenge-id', nonce: 12345, hash: 'invalidhash123' }
    }
  });

  const hasInvalidPoWDetection = (invalidHashResult.detections || []).some(
    d => d.reason && (d.reason.includes('PoW verification failed') || d.reason.includes('not_found'))
  );
  if (hasInvalidPoWDetection) {
    passed++;
    log(`  ✓ Invalid PoW solution rejected`, colors.green);
  } else {
    failed++;
    log(`  ✗ Invalid PoW solution was not rejected`, colors.red);
  }
}

async function testSignalCommitment() {
  log('\n[Signal Commitment]', colors.cyan);

  const { createHash } = await import('crypto');

  try {
    // Get a fresh challenge
    const challengeResponse = await fetch(`${SERVER_URL}/api/pow/challenge?siteKey=test`);
    const challenge = await challengeResponse.json();

    // Build legitimate signals
    const signals = {
      behavioral: {
        totalPoints: 80, trajectoryLength: 350,
        interactionDuration: 1500, velocityVariance: 0.8,
        microTremorScore: 0.6, directionChanges: 15,
        mouseEventRate: 60, approachPoints: 12,
      },
      environmental: {
        automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 }
      },
      meta: { challengeNonce: challenge.nonce }
    };

    const signalsJson = JSON.stringify(signals);
    const signalsHash = createHash('sha256').update(signalsJson).digest('hex');

    // Solve PoW with correct signalsHash
    const target = '0'.repeat(challenge.difficulty);
    const inputPrefix = `${challenge.prefix}:${signalsHash}`;
    let nonce = 0;
    let hash = '';
    while (nonce < 10000000) {
      const input = `${inputPrefix}:${nonce}`;
      hash = createHash('sha256').update(input).digest('hex');
      if (hash.startsWith(target)) break;
      nonce++;
    }

    // Now submit with TAMPERED signals (different from signalsJson)
    const tamperedSignals = { ...signals, behavioral: { ...signals.behavioral, totalPoints: 0 } };

    const tamperResult = await makeRequest('/api/verify', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      body: {
        siteKey: 'test',
        signals: tamperedSignals,
        signalsJson: JSON.stringify(tamperedSignals), // Tampered signalsJson won't match signalsHash
        powSolution: {
          challengeId: challenge.challengeId,
          nonce: nonce,
          hash: hash,
          signalsHash: signalsHash // Original hash from pre-tamper signals
        },
        powTiming: { duration: 500, iterations: nonce, difficulty: challenge.difficulty }
      }
    });

    const hasTamperDetection = (tamperResult.detections || []).some(
      d => d.reason && d.reason.includes('tampered')
    );
    if (hasTamperDetection) {
      passed++;
      log(`  ✓ Tampered signals detected (signalsHash mismatch)`, colors.green);
    } else {
      failed++;
      log(`  ✗ Tampered signals not detected`, colors.red);
      log(`    Detections: ${(tamperResult.detections || []).map(d => d.reason).join('; ')}`, colors.dim);
    }

  } catch (error) {
    failed++;
    log(`  ✗ Signal commitment test error: ${error.message}`, colors.red);
  }
}

async function testChallengeNonce() {
  log('\n[Challenge Nonce]', colors.cyan);

  const { createHash } = await import('crypto');

  try {
    // Get a fresh challenge
    const challengeResponse = await fetch(`${SERVER_URL}/api/pow/challenge?siteKey=test`);
    const challenge = await challengeResponse.json();

    // Build signals with WRONG challengeNonce
    const signals = {
      behavioral: {
        totalPoints: 80, trajectoryLength: 350,
        interactionDuration: 1500, velocityVariance: 0.8,
        microTremorScore: 0.6, directionChanges: 15,
        mouseEventRate: 60, approachPoints: 12,
      },
      environmental: {
        automationFlags: { chrome: true, platform: 'MacIntel', plugins: 5 }
      },
      meta: { challengeNonce: 'wrong-nonce-value' }
    };

    const signalsJson = JSON.stringify(signals);
    const signalsHash = createHash('sha256').update(signalsJson).digest('hex');

    // Solve PoW
    const target = '0'.repeat(challenge.difficulty);
    const inputPrefix = `${challenge.prefix}:${signalsHash}`;
    let nonce = 0;
    let hash = '';
    while (nonce < 10000000) {
      const input = `${inputPrefix}:${nonce}`;
      hash = createHash('sha256').update(input).digest('hex');
      if (hash.startsWith(target)) break;
      nonce++;
    }

    const nonceResult = await makeRequest('/api/verify', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      body: {
        siteKey: 'test',
        signals,
        signalsJson,
        powSolution: {
          challengeId: challenge.challengeId,
          nonce: nonce,
          hash: hash,
          signalsHash
        },
        powTiming: { duration: 500, iterations: nonce, difficulty: challenge.difficulty }
      }
    });

    const hasNonceMismatch = (nonceResult.detections || []).some(
      d => d.reason && d.reason.includes('nonce mismatch')
    );
    if (hasNonceMismatch) {
      passed++;
      log(`  ✓ Wrong challenge nonce detected`, colors.green);
    } else {
      failed++;
      log(`  ✗ Wrong challenge nonce not detected`, colors.red);
      log(`    Detections: ${(nonceResult.detections || []).map(d => d.reason).join('; ')}`, colors.dim);
    }

  } catch (error) {
    failed++;
    log(`  ✗ Challenge nonce test error: ${error.message}`, colors.red);
  }
}

// =============================================================================
// Main
// =============================================================================

async function runTests() {
  log(`\n${colors.bold}FCaptcha Detection Test Suite${colors.reset}`);
  log(`Testing against: ${SERVER_URL}\n`, colors.dim);

  const serverUp = await testHealthEndpoint();
  if (!serverUp) {
    log('\nServer is not running. Start it with:', colors.yellow);
    log('  cd server-node && npm install && node server.js', colors.dim);
    log('  # or', colors.dim);
    log('  cd server-go && go run .', colors.dim);
    log('  # or', colors.dim);
    log('  cd server-python && pip install -r requirements.txt && python server.py\n', colors.dim);
    process.exit(1);
  }

  await testBotUserAgents();
  await testHeadlessBrowserDetection();
  await testDatacenterIPDetection();
  await testHeaderAnalysis();
  await testBrowserConsistency();
  await testBehavioralSignals();
  await testVisionAIDetection();
  await testFormAnalysis();
  await testAdvancedDetections();
  await testPlaywrightDetection();
  await testStealthArtifactDetection();
  await testMissingPoWHardFail();
  await testTightenedExemptions();
  await testAccessibilityFalsePositives();
  await testForwardingHeaderTrust();
  await testGenuineBrowserArtifacts();
  await testTouchSubmitIsNotProgrammatic();
  await testMobileSensorDetection();
  await testProofOfWork();
  await testAdaptiveChallengeCost();
  await testSignalCommitment();
  await testChallengeNonce();
  await testKeystrokeCadence();
  await testHeadRequests();
  await testTokenVerification();
  await testInvisibleMode();

  // Summary
  log(`\n${colors.bold}═══════════════════════════════════════${colors.reset}`);
  log(`${colors.bold}Test Results${colors.reset}`);
  log(`${colors.bold}═══════════════════════════════════════${colors.reset}`);
  log(`  ${colors.green}Passed: ${passed}${colors.reset}`);
  log(`  ${colors.red}Failed: ${failed}${colors.reset}`);
  log(`  Total:  ${passed + failed}`);

  if (failed === 0) {
    log(`\n${colors.green}${colors.bold}All tests passed!${colors.reset}\n`);
  } else {
    log(`\n${colors.red}${colors.bold}Some tests failed.${colors.reset}\n`);
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
