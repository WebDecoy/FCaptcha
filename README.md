# F***Captcha

**Open source CAPTCHA that blocks bots, vision AI agents, and automation - with a single click or less.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python)
![Node](https://img.shields.io/badge/Node-20+-339933?logo=node.js)
![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker)

**[Try the Live Demo](https://webdecoy.com/product/fcaptcha-demo/)**

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/WebDecoy/FCaptcha)
[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/template?referralCode=webdecoy&template=https://github.com/WebDecoy/FCaptcha)

FCaptcha is a modern CAPTCHA system designed to detect everything: traditional bots, headless browsers, automation frameworks, CAPTCHA farms, and the new generation of AI agents — from vision models that screenshot-and-click to computer-use agents that drive a real browser over the Chrome DevTools Protocol.

## Features

- **Single click or invisible** - Checkbox mode like Turnstile/reCAPTCHA v2, or invisible mode like reCAPTCHA v3
- **AI agent detection** - Catches vision agents (screenshot→API→click), DOM/CDP-driven agents (Claude in Chrome, Operator-style computer use), and synthetic input that reports `isTrusted: true` — via input-event forensics and LLM think-time cadence
- **Declared-agent identification** - Flags self-declaring agents (ClaudeBot, GPTBot, ChatGPT-User, PerplexityBot, Bytespider…) and Web Bot Auth (RFC 9421) signed requests, surfaced as a distinct category so your app can choose to *allow* polite agents and block the rest
- **Proof of Work** - Server-verified SHA-256 hashcash with 256-bit HMAC signing, per-challenge nonces, and signal commitment that binds the challenge to the collected signals
- **Comprehensive bot detection** - Headless browsers, WebDriver, Puppeteer, Playwright, Selenium, plus CDP console-attach detection
- **Behavioral biometrics** - 40+ signals including micro-tremor, velocity/acceleration curves, trajectory analysis, coalesced pointer events, and teleport-click detection
- **Mobile-native** - Touch kinematics and passive device-sensor entropy, with accessibility exemptions for keyboard-only and touch users
- **TLS fingerprinting** - JA3 (client-supplied) and JA4 (un-spoofable, from a trusted reverse proxy) matched against known automation tools
- **Credential stuffing protection** - Form interaction analysis, timing, and programmatic submit/fill detection
- **Self-hosted & privacy-first** - No external dependencies, no persistent fingerprinting, no cross-site tracking
- **Open algorithm** - Transparent, confidence-weighted scoring across ~12 categories, fully auditable
- **Multi-language servers** - Go, Python, or Node.js, kept in lockstep

## Quick Start

### Docker (recommended)

One command to deploy:

```bash
docker run -d -p 3000:3000 -e FCAPTCHA_SECRET=my-secret ghcr.io/webdecoy/fcaptcha
```

This gives you:
- API at `http://localhost:3000/api/*`
- Client JS at `http://localhost:3000/fcaptcha.js`
- Demo page at `http://localhost:3000/demo/`

With Redis (for distributed state):

```bash
FCAPTCHA_SECRET=my-secret docker compose -f docker/docker-compose.yml up -d
```

Deploy to Fly.io:

```bash
fly launch --copy-config
fly secrets set FCAPTCHA_SECRET=my-secret
```

Build from source:

```bash
docker build -f docker/Dockerfile -t fcaptcha .
docker run -d -p 3000:3000 -e FCAPTCHA_SECRET=my-secret fcaptcha
```

### Run from Source

Pick your language:

**Go (fastest)**
```bash
cd server-go
go build -o fcaptcha-server
FCAPTCHA_SECRET=your-secret ./fcaptcha-server
```

**Python (FastAPI)**
```bash
cd server-python
pip install -r requirements.txt
FCAPTCHA_SECRET=your-secret python server.py
```

**Node.js (Express)**
```bash
cd server-node
npm install
FCAPTCHA_SECRET=your-secret node server.js
```

### 2. Add to Your Site

**Checkbox Mode (Interactive)**

```html
<script src="https://your-server.com/fcaptcha.js"></script>
<div id="captcha"></div>

<script>
  FCaptcha.configure({ serverUrl: 'https://your-server.com' });

  FCaptcha.render('captcha', {
    siteKey: 'your-site-key',
    callback: (token) => {
      document.getElementById('token').value = token;
    }
  });
</script>
```

**Invisible Mode (Zero-Click)**

```html
<script src="https://your-server.com/fcaptcha.js"></script>

<script>
  FCaptcha.configure({ serverUrl: 'https://your-server.com' });

  // Auto-protect all forms
  FCaptcha.invisible({
    siteKey: 'your-site-key',
    autoScore: true
  });

  // Or manually score specific actions
  const result = await FCaptcha.execute('your-site-key', {
    action: 'login'
  });

  if (result.score < 0.5) {
    // Likely human
  }
</script>
```

**React (no library required)**

The widget exposes a global API, so a small hook is all you need — no wrapper package to install or maintain.

```jsx
import { useEffect, useState, useCallback, useRef } from 'react';

function useFCaptcha({ serverUrl, siteKey }) {
  const [ready, setReady] = useState(typeof window !== 'undefined' && !!window.FCaptcha);

  useEffect(() => {
    if (window.FCaptcha) {
      window.FCaptcha.configure({ serverUrl });
      setReady(true);
      return;
    }
    const script = document.createElement('script');
    script.src = `${serverUrl}/fcaptcha.js`;
    script.async = true;
    script.onload = () => {
      window.FCaptcha.configure({ serverUrl });
      setReady(true);
    };
    document.head.appendChild(script);
    return () => { script.remove(); };
  }, [serverUrl]);

  const execute = useCallback(
    (action) => window.FCaptcha.execute(siteKey, { action }),
    [siteKey]
  );

  return { ready, execute };
}

// Invisible mode — get a token at submit time
function LoginForm() {
  const { ready, execute } = useFCaptcha({
    serverUrl: 'https://your-server.com',
    siteKey: 'your-site-key',
  });

  async function onSubmit(e) {
    e.preventDefault();
    const { token } = await execute('login');
    await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: e.target.email.value, fcaptchaToken: token }),
    });
  }

  return (
    <form onSubmit={onSubmit}>
      <input name="email" type="email" required />
      <button disabled={!ready}>Sign in</button>
    </form>
  );
}

// Checkbox mode — render the interactive widget
function FCaptchaCheckbox({ siteKey, serverUrl, onVerify }) {
  const ref = useRef(null);
  const { ready } = useFCaptcha({ serverUrl, siteKey });

  useEffect(() => {
    if (!ready || !ref.current) return;
    const widgetId = window.FCaptcha.render(ref.current, { siteKey, callback: onVerify });
    return () => window.FCaptcha.reset(widgetId);
  }, [ready, siteKey, onVerify]);

  return <div ref={ref} />;
}
```

The same pattern works in Vue, Svelte, Solid, and Angular — the widget is framework-agnostic. If you'd rather not write the glue, opening an issue describing how you want to consume it helps us decide whether to ship an official wrapper.

### 3. Verify on Your Backend

```go
// Go
resp, _ := http.Post("https://your-server.com/api/token/verify",
    "application/json",
    strings.NewReader(`{"token": "...", "secret": "your-secret"}`))

var result map[string]interface{}
json.NewDecoder(resp.Body).Decode(&result)

if result["valid"].(bool) && result["score"].(float64) < 0.5 {
    // Valid request from human
}
```

```python
# Python
import requests

result = requests.post('https://your-server.com/api/token/verify',
    json={'token': '...', 'secret': 'your-secret'}
).json()

if result['valid'] and result['score'] < 0.5:
    # Valid request from human
```

```javascript
// Node.js
const result = await fetch('https://your-server.com/api/token/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: '...', secret: 'your-secret' })
}).then(r => r.json());

if (result.valid && result.score < 0.5) {
  // Valid request from human
}
```

## How It Works

FCaptcha collects signals across many categories and blends them into a single confidence-weighted score (weights sum to 1.0 and are tunable per deployment). The major surfaces:

### Proof of Work (Invisible Layer)
Before any verification, clients must solve a SHA-256 hashcash challenge:
- **Challenge fetched on page load** - solving runs in the background across parallel Web Workers (one per ~2 CPU cores)
- **Non-blocking** - users never see it, computation happens while they fill forms
- **Hardened** - 256-bit HMAC-signed challenges, one-time use, replay-protected, with a server-generated per-challenge nonce the client must echo back
- **Signal commitment** - the client hashes its collected signals into the PoW input (`prefix:signalsHash:nonce`) and the server verifies the signals weren't tampered with after solving
- **Difficulty scaling** - datacenter IPs and high-rate requesters get harder puzzles
- **Forces compute cost** - each attempt requires ~100-500ms of CPU time

This makes credential stuffing expensive: even if a bot passes all other checks, it still burns compute for every attempt.

### Behavioral Biometrics
- Mouse trajectory, velocity, and acceleration curves
- Micro-tremor detection (humans have natural hand shake at 3-25Hz)
- Click precision, approach directness, pre-click exploration, overshoot corrections
- **Input-event forensics** — coalesced pointer-event batches (real mice coalesce several hardware samples per frame; CDP-injected moves don't), `movementX/Y` vs. position-delta coherence, and teleport clicks (a click dispatched at coordinates with no approach trajectory)
- **Think-time cadence** — the agent act → screenshot → inference → act loop leaves bursts of activity separated by multi-second perfect silence
- **Mobile-native** — touch kinematics (multi-touch, force/radius variance) and passive device-sensor entropy, exempting genuine touch and keyboard-only users

### Environmental & Automation
- WebDriver / automation framework detection (Selenium, Puppeteer, Playwright, PhantomJS, Nightmare, Watir)
- **CDP detection** — legacy ChromeDriver/Selenium globals plus a Runtime/DevTools console-attach probe that catches any attached protocol client, even when JS globals are scrubbed
- Headless browser indicators, plugin/feature checks, UA ↔ platform consistency
- Canvas / WebGL / Audio fingerprinting (session-scoped only)
- **TLS fingerprinting** — JA3 (client-supplied) and JA4 (read from a trusted reverse-proxy header, un-spoofable by the client) matched against known automation tools

### Temporal Signals
- Proof of Work timing (reveals API round-trip latency)
- Interaction timing patterns and event-sequence analysis
- Page-load-to-interaction timing

### Form Interaction
- Programmatic `form.submit()` and programmatic-click detection
- **Programmatic fill** — content that appears with zero keystrokes and zero pastes (Playwright `fill()` / `element.value=`)
- Time from page load to submission; events-before-submit (no events = bot)
- Textarea keystroke analysis — paste ratio, typing speed, rhythm/cadence, keydown/keyup ratio

### Declared Agents & Reputation
- Self-identifying AI-agent user-agents (ClaudeBot, Claude-User, GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot, Google-Extended, CCBot, Bytespider, meta-externalagent, Amazonbot, cohere-ai, …)
- Web Bot Auth (RFC 9421 HTTP Message Signatures) signed-request identification
- Datacenter / VPN / proxy IP reputation and reverse-DNS heuristics (with a 2s lookup timeout so request handlers never block)

## AI Agent Detection

FCaptcha targets three classes of modern AI agent, each with a different tell.

### 1. Vision agents (screenshot → API → click)

A vision agent takes a screenshot, sends it to a vision model (GPT-4V, Claude, etc.) for click coordinates, and executes the click. That pattern is exploitable:

| Signal | Human | Vision agent |
|--------|-------|-----------|
| Mouse movement | Natural curves, micro-tremor | Smooth/linear paths |
| Pre-click behavior | Exploration, hesitation | Direct path to target |
| Click trajectory | Approach path to the target | Teleport — click with no preceding movement |
| Coordinate precision | Slight variance | Pixel-perfect |
| PoW timing | Consistent with local execution | Delayed by API round-trip |

### 2. Computer-use / CDP agents (driving a real browser)

Agents like Claude in Chrome (via `chrome.debugger`) or Operator-style tools (via Playwright/CDP) drive a *real* browser, so their input events report `isTrusted: true` and slip past global-based checks. Their **shape** still betrays them:

| Signal | Human | CDP-driven agent |
|--------|-------|-----------|
| Coalesced pointer events | Multiple hardware samples per frame | Single-entry batches (synthetic) |
| `movementX/Y` vs. position | Coherent | Incoherent / zero while position changes |
| Activity cadence | Continuous, noisy idle | Bursts separated by multi-second silence (think time) |
| Field entry | Per-character keystrokes | Programmatic fill — value set, no keys/pastes |
| Protocol surface | None | DevTools/Runtime console consumer attached |

### 3. Declared agents (the agentic web)

Many legitimate agents and crawlers identify themselves — by user-agent (ClaudeBot, GPTBot, PerplexityBot, …) or by cryptographically signing requests with **Web Bot Auth** (RFC 9421). FCaptcha flags these as a distinct `declared_ai` category with high confidence and low default severity, so your application can apply policy — allow polite/verified agents, block undeclared automation — rather than treating every agent as an attacker.

## API Reference

### GET /api/pow/challenge
Get a Proof of Work challenge. Called automatically by the client on page load.

```json
// Request: GET /api/pow/challenge?siteKey=your-site-key

// Response
{
  "challengeId": "abc123...",
  "prefix": "abc123:1703356800000:4",
  "difficulty": 4,
  "expiresAt": 1703357100000,
  "nonce": "f1e2d3...",
  "sig": "def456..."
}
```

The `nonce` is generated per-challenge by the server; the client echoes it back in `signals.meta.challengeNonce` and the server verifies it, preventing challenge replay.

Difficulty scales based on:
- Datacenter IPs: +1 difficulty
- High request rate: +1 difficulty (max 6)

### POST /api/verify
Verify a checkbox CAPTCHA submission.

```json
// Request
{
  "siteKey": "your-site-key",
  "signals": { /* collected signals */ },
  "signalsJson": "{...}",            // canonical serialization, hashed for signal commitment
  "powSolution": {
    "challengeId": "abc123...",
    "nonce": 68455,
    "hash": "0000abc...",
    "signalsHash": "9f86d0..."       // SHA-256 of signalsJson, bound into the PoW input
  },
  "powTiming": { "duration": 230, "iterations": 41000, "difficulty": 4 }
}

// Response
{
  "success": true,
  "score": 0.15,
  "token": "...",
  "recommendation": "allow"
}
```

`signalsJson` is sent alongside `signals` for deterministic hashing across languages; the server recomputes `SHA-256(signalsJson)` and checks it matches `powSolution.signalsHash`, so signals can't be swapped after the proof of work is solved. `powTiming` is sent separately (not inside the committed signals) to avoid a chicken-and-egg with PoW timing.

### POST /api/score
Get a score for invisible mode.

```json
// Request
{
  "siteKey": "your-site-key",
  "signals": { /* collected signals */ },
  "action": "login",
  "powSolution": {
    "challengeId": "abc123...",
    "nonce": 68455,
    "hash": "0000abc..."
  }
}

// Response
{
  "success": true,
  "score": 0.12,
  "token": "...",
  "action": "login"
}
```

### POST /api/token/verify
Verify a previously issued token (server-side).

```json
// Request
{
  "token": "...",
  "secret": "your-secret"
}

// Response
{
  "valid": true,
  "site_key": "your-site-key",
  "score": 0.15,
  "timestamp": 1703356800
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FCAPTCHA_SECRET` | Secret key for token signing | (required) |
| `PORT` | Server port | 3000 |
| `REDIS_URL` | Redis URL for distributed state | (in-memory) |
| `TRUSTED_JA4_HEADERS` | Comma-separated reverse-proxy header names carrying a JA4 TLS fingerprint (e.g. set by nginx/Cloudflare). Only these are trusted as un-spoofable | (none) |
| `FCAPTCHA_CLIENT_PATH` | Explicit path to `client/fcaptcha.js` for same-origin widget serving | (auto-probed) |
| `FCAPTCHA_SERVE_CLIENT` | (Python) Serve the widget at `/fcaptcha.js`; set `false` to host the client on a separate CDN | `true` |
| `FCAPTCHA_PPROF` | (Go) Enable the pprof debug server (`1`/`true`/`yes`/`on`) | off |
| `FCAPTCHA_PPROF_ADDR` | (Go) Listen address for pprof when enabled — keep it loopback-only | `127.0.0.1:3001` |

### Score Thresholds

| Score | Recommendation |
|-------|----------------|
| < 0.3 | Allow - likely human |
| 0.3 - 0.6 | Challenge - uncertain |
| > 0.6 | Block - likely bot |

## Project Structure

```
fcaptcha/
├── client/
│   └── fcaptcha.js          # Client-side widget, signal collection, parallel PoW Web Workers
├── server-go/
│   ├── main.go              # Go HTTP server + same-origin widget serving
│   ├── scoring.go           # Scoring engine, PoW verification, behavioral/vision/CDP detectors
│   ├── detection.go         # IP reputation, headers, declared-AI, JA3/JA4, form analysis
│   ├── scoring_test.go      # Go unit tests
│   └── go.mod
├── server-python/
│   ├── server.py            # Python/FastAPI server + PoW + detectors
│   ├── detection.py         # IP reputation, headers, declared-AI, JA3/JA4, form analysis
│   └── requirements.txt
├── server-node/
│   ├── server.js            # Node.js/Express server + PoW + detectors
│   ├── detection.js         # IP reputation, headers, declared-AI, JA3/JA4, form analysis
│   └── package.json
├── test/
│   └── test-detection.js    # End-to-end detection test suite (runs against a live server)
├── demo/
│   └── index.html           # Interactive demo page
├── docker/
│   ├── Dockerfile           # Multi-stage build (Go binary + client + demo)
│   └── docker-compose.yml   # Docker compose with Redis
├── .github/workflows/
│   ├── docker-publish.yml   # GHCR publish on release
│   └── npm-publish.yml      # npm publish on release
├── .dockerignore
├── ARCHITECTURE.md          # Technical architecture documentation
└── README.md
```

> All three servers implement the same detection engine and must stay in sync. The Go scoring is unit-tested (`go test ./server-go/...`); `test/test-detection.js` exercises the full pipeline against a running server.

## Development

```bash
# Run Go server
cd server-go && go run .

# Run Python server
cd server-python && python server.py

# Run Node server
cd server-node && node server.js

# Open demo
open demo/index.html
```

### Running Tests

Go unit tests (no server required):

```bash
cd server-go && go test ./...
```

End-to-end detection suite (runs against a live server):

```bash
# Start a server first (any language)
cd server-node && node server.js &

# Run the suite
node test/test-detection.js
```

Coverage spans bot user-agents, headless/CDP detection, declared AI agents, datacenter/IP reputation, HTTP header and TLS (JA3/JA4) analysis, browser consistency, behavioral and input-event-forensics signals, vision/agent detection, form interaction (paste + programmatic fill), proof of work, token verification, and invisible-mode scoring.

## Contributing

Contributions welcome! Please read [ARCHITECTURE.md](ARCHITECTURE.md) first. AI-agent detection is built out in phases — declared agents and input-event forensics have shipped; hosted-agent environment composites, accessibility-tree honeypots, cross-session correlation, and Web Bot Auth signature *verification* are still open.

Areas that could use help:
- Web Bot Auth signature verification (currently identifies signed requests; verifying against the agent's published JWKS would let you safely *allow* verified agents)
- Cross-session / per-fingerprint behavioral correlation (the durable defense against source-patched browsers)
- Machine learning-based scoring
- Admin dashboard and analytics
- WebAssembly-based PoW for better mobile performance
- Redis-backed distributed state (currently in-memory)

When adding or changing a detector, apply it to **all three** server implementations (Go, Python, Node) so they stay in sync.

## License

MIT License - use freely, contribute back if you can.

---

**Privacy Note**: FCaptcha is designed with privacy in mind. No persistent fingerprinting, no cross-site tracking, no PII collection. All fingerprints are session-scoped and used only for bot detection.
