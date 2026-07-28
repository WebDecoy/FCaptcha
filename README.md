# F***Captcha

**Open source CAPTCHA that blocks bots, vision AI agents, and automation - with a single click or less.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python)
![Node](https://img.shields.io/badge/Node-20+-339933?logo=node.js)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker)](https://github.com/WebDecoy/FCaptcha/pkgs/container/fcaptcha)

**[Try the Live Demo](https://webdecoy.com/product/fcaptcha-demo/)**

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/WebDecoy/FCaptcha)
[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/template?referralCode=webdecoy&template=https://github.com/WebDecoy/FCaptcha)

FCaptcha is a modern CAPTCHA system designed to detect everything: traditional bots, headless browsers, automation frameworks, CAPTCHA farms, and the new generation of AI agents — from vision models that screenshot-and-click to computer-use agents that drive a real browser over the Chrome DevTools Protocol.

## Features

- **Single click or invisible** - Checkbox mode like Turnstile/reCAPTCHA v2, or invisible mode like reCAPTCHA v3
- **AI agent detection** - Catches vision agents (screenshot→API→click), DOM/CDP-driven agents (Claude in Chrome, Operator-style computer use), and synthetic input that reports `isTrusted: true` — via input-event forensics and LLM think-time cadence
- **Declared & verified agents** - Flags self-declaring agents (ClaudeBot, GPTBot, ChatGPT-User, PerplexityBot, Bytespider…) and *cryptographically verifies* Web Bot Auth (RFC 9421) signed requests against the agent's published key directory, surfaced as a distinct category so your app can *allow* polite/verified agents and block the rest
- **Proof of Work** - Server-verified SHA-256 hashcash with 256-bit HMAC signing, per-challenge nonces, and signal commitment that binds the challenge to the collected signals
- **Comprehensive bot detection** - Headless browsers, WebDriver, Puppeteer, Playwright, Selenium, plus CDP console-attach detection
- **Behavioral biometrics** - 40+ signals including micro-tremor, velocity/acceleration curves, trajectory analysis, coalesced pointer events, and teleport-click detection
- **Mobile-native** - Touch kinematics and passive device-sensor entropy, with accessibility exemptions for keyboard-only and touch users
- **TLS fingerprinting** - JA3 (client-supplied) and JA4 (un-spoofable, from a trusted reverse proxy) matched against known automation tools
- **Credential stuffing protection** - Form interaction analysis, timing, and programmatic submit/fill detection
- **Self-hosted & privacy-first** - No external dependencies, no persistent fingerprinting, no cross-site tracking
- **Input forensics** - Typing cadence and modality (keystrokes vs. paste vs. a value assigned into the DOM), scroll morphology, and platform contradictions like a Ctrl+V paste from a browser claiming macOS
- **Open algorithm** - Transparent, evidence-accumulating scoring across ~12 categories, fully auditable
- **Measured, not asserted** - A [benchmark harness](bench/) captures real browser traces for 14 human personas (keyboard-only, screen-reader, touch, tremor, elderly, DevTools-open, privacy-extension…) and reports a per-signal false-positive budget in CI. Every threshold in the behavioural layer was derived from it
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

FCaptcha collects signals across many categories and blends them into a single score (category weights sum to 1.0 and are tunable per deployment). The major surfaces:

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
- **Scroll morphology** — a wheel or trackpad advances the page tens of pixels per event; `scrollIntoView()` covers the whole page in one. Measured separation: 109px vs. 704px per event. Stands down for keyboard users, since PageDown legitimately jumps a viewport

### Environmental & Automation
- WebDriver / automation framework detection (Selenium, Puppeteer, Playwright, PhantomJS, Nightmare, Watir)
- **CDP detection** — legacy ChromeDriver/Selenium globals plus a Runtime/DevTools console-attach probe that catches any attached protocol client, even when JS globals are scrubbed
- Headless browser indicators, plugin/feature checks, UA ↔ platform consistency
- Canvas / WebGL / Audio fingerprinting (session-scoped only)
- **TLS fingerprinting** — JA3 (client-supplied) and JA4. JA4 is computed **natively from the ClientHello** when the Go server terminates TLS itself (`FCAPTCHA_TLS_CERT`/`FCAPTCHA_TLS_KEY`), which no client can assert; behind a terminating proxy it falls back to a trusted header. Only JA4-TLS is implemented — the rest of the JA4 family is licensed non-commercially and cannot ship here

### Temporal Signals
- Proof of Work timing (reveals API round-trip latency)
- Interaction timing patterns and event-sequence analysis
- Page-load-to-interaction timing

### Form Interaction
- Programmatic `form.submit()` and programmatic-click detection
- **Programmatic fill** — content that appears with zero keystrokes and zero pastes (Playwright `fill()` / `element.value=`)
- Time from page load to submission; events-before-submit (no events = bot)
- Textarea keystroke analysis — paste ratio, typing speed, rhythm/cadence, keydown/keyup ratio
- **Typing cadence floors** — inter-key interval *and* key hold time both below the human range. Measured on real hardware: humans 226.9ms median with 4549 variance and 82ms holds; a scripted agent 7.9ms, variance 8, 7.8ms holds. Gated behind a ten-keystroke minimum and a no-paste requirement, because a paste is two keydowns a millisecond apart and people paste constantly
- **Paste/platform contradiction** — Ctrl+V from a client claiming macOS, or Meta+V from one claiming Windows, *with the paste actually landing*. No threshold and no calibration: the client has disagreed with itself. Requiring a completed paste keeps it off the Windows switcher fat-fingering Ctrl+V on a new Mac, where that combination does nothing

### Declared Agents & Reputation
- Self-identifying AI-agent user-agents (ClaudeBot, Claude-User, GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot, Google-Extended, CCBot, Bytespider, meta-externalagent, Amazonbot, cohere-ai, …)
- Web Bot Auth (RFC 9421 HTTP Message Signatures) — cryptographic signature verification against the agent's published key directory (verified / forged / unverified), Go + Node
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

Many legitimate agents and crawlers identify themselves — by user-agent (ClaudeBot, GPTBot, PerplexityBot, …) or by cryptographically signing requests with **Web Bot Auth** (RFC 9421). FCaptcha verifies those signatures against the agent's published key directory:

- **verified** → a distinct `declared_ai` category (high confidence, low default severity) — a trustworthy identity your app can *allow* by policy.
- **forged** (signature fails cryptographic verification) → a contributory bot signal — affirmative evidence of a spoofed identity claim.
- **unverified** (unreachable/blocked directory, timeout) → fails open to a presence-only signal; a directory it couldn't fetch is never treated as proof of spoofing.

So declared and verified agents get policy handling instead of being treated as attackers, and a bot can't buy leniency just by attaching three unsigned headers. (Go + Node verify cryptographically; the Python server still identifies by header presence.)

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
| `TRUSTED_PROXIES` | Comma-separated CIDRs/IPs of peers allowed to set `X-Forwarded-For`, `X-Real-IP` and the TLS-fingerprint headers. `*` trusts every peer, `none` trusts none. See [Trusted proxies](#trusted-proxies) | loopback + private ranges |
| `FCAPTCHA_SITE_KEYS` | Comma-separated allowlist of accepted site keys. Unset accepts any key (zero-config self-hosting); unlisted keys are folded into a shared overflow bucket rather than allocating their own rate-limit/fingerprint state | (any) |
| `FCAPTCHA_MAX_SITE_KEYS_PER_IP` | Distinct site keys one IP may allocate state for before the excess is folded into the overflow bucket. The cap itself is unconditional | 8 |
| `TRUSTED_JA4_HEADERS` | Comma-separated reverse-proxy header names carrying a JA4 TLS fingerprint (e.g. set by nginx/Cloudflare). Only these names are read, and only from a peer in `TRUSTED_PROXIES` | (none) |
| `FCAPTCHA_TLS_CERT` / `FCAPTCHA_TLS_KEY` | Serve HTTPS directly (Go server). Terminating TLS here is what makes **native JA4** possible — the fingerprint is computed from the ClientHello rather than taken on trust from a proxy. Behind Railway/Cloudflare/nginx, leave unset and use `TRUSTED_JA4_HEADERS` | (none, plain HTTP) |
| `FCAPTCHA_CLIENT_PATH` | Explicit path to `client/fcaptcha.js` for same-origin widget serving | (auto-probed) |
| `FCAPTCHA_SERVE_CLIENT` | (Python) Serve the widget at `/fcaptcha.js`; set `false` to host the client on a separate CDN | `true` |
| `FCAPTCHA_PPROF` | (Go) Enable the pprof debug server (`1`/`true`/`yes`/`on`) | off |
| `FCAPTCHA_PPROF_ADDR` | (Go) Listen address for pprof when enabled — keep it loopback-only | `127.0.0.1:3001` |
| `FCAPTCHA_LOG_VERDICTS` | Log one privacy-safe JSON line per `/api/verify` and `/api/score` (score, recommendation, category scores, and per-hit category/score/confidence). Omits IP, user agent, raw signals, and free-text detection reasons. For observability/tuning (`1`/`true`/`yes`/`on`) | off |
| `FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW` | Also include the free-text detection `reason` in verdict logs. **Reasons can contain visitor-derived data** (reverse-DNS hostnames, UA/header fragments, form field ids) — only enable in trusted debugging contexts with no privacy obligations. Requires `FCAPTCHA_LOG_VERDICTS` | off |

### Trusted proxies

Every IP-derived check — datacenter ranges, Tor/VPN, rate limiting, token IP
binding, PoW difficulty — is only as good as the address the server is handed.
`X-Forwarded-For` and `X-Real-IP` are set by whoever opened the connection, so
FCaptcha reads them **only when the peer is in `TRUSTED_PROXIES`**. Any other
caller is attributed to its socket address, and a forged header is ignored. The
same gate covers `X-JA3-Hash` and any header named in `TRUSTED_JA4_HEADERS`.

The default — loopback plus the private and link-local ranges — covers nginx on
`127.0.0.1`, a sidecar proxy, and an in-cluster ingress with no configuration,
while a server exposed directly to the internet sees public peers and therefore
ignores their headers.

Set it explicitly when your proxy reaches FCaptcha from an address outside those
ranges — a Cloudflare Tunnel, a load balancer in another VPC, or a PaaS edge
(Railway's is in the RFC 6598 CGNAT block):

```bash
TRUSTED_PROXIES=100.64.0.0/10 ./fcaptcha-server   # Railway
```

If you get this wrong in the *unsafe* direction nothing breaks visibly, so
FCaptcha logs it: a peer that sends forwarding headers but is not trusted
produces a one-time warning naming the address to add. Check your logs after
deploying — an unlisted proxy means every visitor is being attributed to it,
which quietly ruins rate limiting and IP reputation.

`*` trusts every peer and restores the spoofing bypass — use it only when an edge
you control always overwrites the headers. `none` (or an empty value) always uses
the socket address. Each server logs the resolved set on startup. Full details in
[INSTALLATION.md](INSTALLATION.md#trusted-proxies).

### Score Thresholds

| Score | Recommendation |
|-------|----------------|
| < 0.3 | Allow - likely human |
| 0.3 - 0.6 | Challenge - uncertain |
| > 0.6 | Block - likely bot |

### How the score is composed

Within a category, detections combine as **noisy-OR** — each is treated as
independent evidence of strength `score x confidence`, and the category is the
probability that at least one is right. Categories then contribute by weight.

This replaced a confidence-weighted mean, which had a property nobody intended:
corroborating evidence *lowered* the verdict. A browser reporting
`navigator.webdriver = true` and nothing else scored 0.95 in the headless
category; the same browser also caught with no plugins, a software renderer and
five more automation tells scored **0.686**, because each additional signal was
individually weaker than the first and pulled the average down. Evidence now
accumulates, and an isolated low-confidence hit counts for *less* than it used
to rather than setting a whole category.

**Self-declared automation sets a floor.** A weighted sum across eleven
categories means no single fact can consume much of the budget, so a blatant
local agent used to land near 0.5 — "challenge", not "block". Detections marked
`dispositive` now floor the score at 0.9. The bar for that mark is that a
browser *cannot produce the signal without being automated*: `navigator.webdriver`
(W3C-specified, its whole purpose is to announce automation) and
ChromeDriver/Puppeteer injected globals. The DevTools console-attach probe is
deliberately excluded — the benchmark's human panel proves it fires on a
developer with DevTools open.

This does not catch a stealth agent that patches the flag before the page sees
it, and is not meant to. It closes the case where an agent is not trying to hide.

## Project Structure

```
fcaptcha/
├── client/
│   └── fcaptcha.js          # Client-side widget, signal collection, parallel PoW Web Workers
├── server-go/
│   ├── main.go              # Go HTTP server + same-origin widget serving
│   ├── scoring.go           # Scoring engine, PoW verification, behavioral/vision/CDP detectors
│   ├── detection.go         # IP reputation, headers, declared-AI, JA3/JA4, form analysis
│   ├── clientip.go          # Trusted-proxy client IP resolution (TRUSTED_PROXIES)
│   ├── sitekeys.go          # Bounds on state a client-supplied siteKey can allocate
│   ├── inputforensics.go    # Typing cadence/modality, scroll morphology, platform coherence
│   ├── ja4.go               # Native JA4-TLS from the ClientHello (Go 1.24+, stdlib only)
│   ├── scoring_test.go      # Go unit tests
│   ├── clientip_test.go     # Trusted-proxy unit tests
│   └── go.mod
├── server-python/
│   ├── server.py            # Python/FastAPI server + PoW + detectors
│   ├── detection.py         # IP reputation, headers, declared-AI, JA3/JA4, form analysis
│   ├── clientip.py          # Trusted-proxy client IP resolution (TRUSTED_PROXIES)
│   ├── sitekeys.py          # Bounds on state a client-supplied siteKey can allocate
│   ├── inputforensics.py    # Typing cadence/modality, scroll morphology, platform coherence
│   ├── test_clientip.py     # Trusted-proxy unit tests
│   └── requirements.txt
├── server-node/
│   ├── server.js            # Node.js/Express server + PoW + detectors
│   ├── detection.js         # IP reputation, headers, declared-AI, JA3/JA4, form analysis
│   ├── clientip.js          # Trusted-proxy client IP resolution (TRUSTED_PROXIES)
│   ├── limits.js            # LRU-bounded stores + siteKey cardinality guard
│   ├── inputforensics.js    # Typing cadence/modality, scroll morphology, platform coherence
│   ├── clientip.test.js     # Trusted-proxy unit tests
│   └── package.json
├── bench/
│   ├── capture/             # Drives real Chromium, intercepts the /api/verify body
│   ├── corpus/captured/     # Committed real browser traces (14 human + 8 agent personas)
│   ├── lib/                 # Corpus schema, browser-paced PoW client, metrics, reporting
│   ├── run-bench.js         # Replay + per-signal FP budgets + CI gate
│   └── README.md            # What the numbers do and do not establish — read first
├── test/
│   └── test-detection.js    # End-to-end detection test suite (runs against a live server)
├── demo/
│   └── index.html           # Interactive demo page
├── docker/
│   ├── Dockerfile           # Multi-stage build (Go binary + client + demo)
│   └── docker-compose.yml   # Docker compose with Redis
├── .github/workflows/
│   ├── bench.yml            # Unit tests + E2E + gated detection benchmark
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

Coverage spans bot user-agents, headless/CDP detection, declared AI agents, datacenter/IP reputation, HTTP header and TLS (JA3/JA4) analysis, browser consistency, behavioral and input-event-forensics signals, vision/agent detection, form interaction (paste + programmatic fill), accessibility false positives, proof of work, token verification, and invisible-mode scoring.

> The three servers do not all pass the full suite. It is written against the Node
> implementation; Go and Python have documented divergences (Python maps
> `datacenter` onto `BOT` and has no `datacenter` category; neither implements the
> advanced headless fingerprint checks). Baseline before assuming a regression.

### Detection benchmark

`bench/` measures what the detection layer actually does to real users. It drives
a real Chromium through real input events, intercepts the `/api/verify` body the
widget produces, and replays that labeled corpus against a running server —
reporting a false-positive rate per persona, a true-positive rate per agent
class, and a per-signal FP budget that gates CI.

```bash
cd bench && npm install && npm run install-browsers
node capture/record.js          # one-time; the corpus is committed
node run-bench.js               # human FPR, agent TPR, per-signal budgets
node run-bench.js --gate        # non-zero exit when a signal is over budget
```

**Read [bench/README.md](bench/README.md) before quoting any number from it.**
A 0% false-positive rate there means "no sample in this corpus crossed the
threshold" — not "0% of real users would". Fourteen scripted personas are a
structural stand-in for fourteen kinds of user, not a population sample, and the
panel's environment is partly reconstructed because an automated browser
announces itself. The harness documents both limits rather than burying them.

What it is good for is catching regressions and false positives that reasoning
alone misses. Its first runs found seven, including mouse-trajectory checks
firing on users who have no mouse, a touch exemption that a plain tap could not
satisfy, and forwarding headers scored as suspicious on every visitor behind a
reverse proxy.

## Contributing

Contributions welcome! Please read [ARCHITECTURE.md](ARCHITECTURE.md) first. AI-agent detection is built out in phases — declared agents, input-event forensics, Web Bot Auth signature verification, the measurement harness, and typing/scroll/platform-coherence forensics have shipped; hosted-agent environment composites, accessibility-tree honeypots, and cross-session correlation are still open.

The most useful contribution right now is **captured traces from real browsers
driven by real people**. The benchmark corpus is currently scripted personas from
a single machine, which bounds what any false-positive number from it can mean.
`bench/corpus/captured/` takes new samples directly — see [bench/README.md](bench/README.md).

Areas that could use help:
- Web Bot Auth verification for the Python server (Go and Node verify cryptographically against the agent's published key directory; Python still identifies by header presence — no maintained Python library yet)
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
