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
  const goodHeadersResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: { siteKey: 'test', signals: {} }
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
  const consistentResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
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
  const humanBehaviorResult = await makeRequest('/api/verify', {
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
  const legitimateResult = await makeRequest('/api/verify', {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    body: {
      siteKey: 'test',
      signals: {
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

async function testTokenVerification() {
  log('\n[Token Verification]', colors.cyan);

  // First get a valid token
  const verifyResult = await makeRequest('/api/verify', {
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
          microTremorScore: 0.6,
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
      body: { token: verifyResult.token }
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
    body: { token: 'invalid-token-here' }
  });

  if (!invalidResult.valid) {
    passed++;
    log(`  ✓ Invalid token rejected`, colors.green);
  } else {
    failed++;
    log(`  ✗ Invalid token was accepted`, colors.red);
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
          interactionDuration: 2000,
          velocityVariance: 0.5,
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

async function testProofOfWork() {
  log('\n[Proof of Work]', colors.cyan);

  // Test getting a PoW challenge
  try {
    const challengeResponse = await fetch(`${SERVER_URL}/api/pow/challenge?siteKey=test`);
    const challenge = await challengeResponse.json();

    if (challenge.challengeId && challenge.prefix && challenge.difficulty) {
      passed++;
      log(`  ✓ PoW challenge endpoint works (difficulty: ${challenge.difficulty})`, colors.green);
    } else {
      failed++;
      log(`  ✗ PoW challenge response missing fields`, colors.red);
      return;
    }

    // Solve the PoW challenge
    const { createHash } = await import('crypto');
    const target = '0'.repeat(challenge.difficulty);
    let nonce = 0;
    let hash = '';
    const maxIterations = 10000000; // Safety limit

    log(`    Solving PoW (difficulty: ${challenge.difficulty})...`, colors.dim);

    while (nonce < maxIterations) {
      const input = `${challenge.prefix}:${nonce}`;
      hash = createHash('sha256').update(input).digest('hex');

      if (hash.startsWith(target)) {
        break;
      }
      nonce++;
    }

    if (!hash.startsWith(target)) {
      failed++;
      log(`  ✗ Failed to solve PoW within iteration limit`, colors.red);
      return;
    }

    passed++;
    log(`  ✓ PoW solved in ${nonce} iterations`, colors.green);

    // Submit with valid PoW solution
    const validPoWResult = await makeRequest('/api/verify', {
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
            microTremorScore: 0.6,
          },
          environmental: {
            automationFlags: {
              chrome: true,
              platform: 'MacIntel',
              plugins: 5,
            }
          }
        },
        powSolution: {
          challengeId: challenge.challengeId,
          nonce: nonce,
          hash: hash
        }
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

    // Test: PoW solution replay attack (same solution used twice)
    const replayResult = await makeRequest('/api/verify', {
      headers: {
        'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0',
      },
      body: {
        siteKey: 'test',
        signals: {},
        powSolution: {
          challengeId: challenge.challengeId,
          nonce: nonce,
          hash: hash
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
    headers: {
      'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0',
    },
    body: {
      siteKey: 'test',
      signals: {}
    }
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
    headers: {
      'User-Agent': 'Mozilla/5.0 Chrome/120.0.0.0',
    },
    body: {
      siteKey: 'test',
      signals: {},
      powSolution: {
        challengeId: 'fake-challenge-id',
        nonce: 12345,
        hash: 'invalidhash123'
      }
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
  await testProofOfWork();
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
