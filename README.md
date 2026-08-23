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

- **Drop-in for Turnstile / reCAPTCHA / hCaptcha** - Serves the same `siteverify` contract on the same paths, so migrating an existing backend is a base-URL change; tokens carry a signed `hostname` and `action` your app can check
- **Single click or invisible** - Checkbox mode like Turnstile/reCAPTCHA v2, or invisible mode like reCAPTCHA v3
- **AI agent detection** - Catches vision agents (screenshot→API→click), DOM/CDP-driven agents (Claude in Chrome, Operator-style computer use), and synthetic input that reports `isTrusted: true` — via input-event forensics and LLM think-time cadence
- **Declared & verified agents** - Flags self-declaring agents (ClaudeBot, GPTBot, ChatGPT-User, PerplexityBot, Bytespider…) and *cryptographically verifies* Web Bot Auth (RFC 9421) signed requests against the agent's published key directory, surfaced as a distinct category so your app can *allow* polite/verified agents and block the rest
- **Proof of Work** - Server-verified SHA-256 hashcash with 256-bit HMAC signing, per-challenge nonces, and signal commitment that binds the challenge to the collected signals. A liveness and timing gate rather than a cost function — see [what it does and does not buy you](#what-the-proof-of-work-does-and-does-not-buy-you)
- **Comprehensive bot detection** - Headless browsers, WebDriver, Puppeteer, Playwright, Selenium, plus CDP console-attach detection
- **Behavioral biometrics** - 40+ signals including micro-tremor, velocity/acceleration curves, trajectory analysis, coalesced pointer events, and teleport-click detection
- **Localized** - The widget ships 34 languages with automatic detection from `<html lang>` or the browser, right-to-left layout for Arabic/Hebrew/Persian, and a `strings` override for anything not bundled
- **Mobile-native** - Touch kinematics and passive device-sensor entropy, with accessibility exemptions for keyboard-only and touch users
- **TLS fingerprinting** - JA3 (client-supplied) and JA4 (un-spoofable, from a trusted reverse proxy) matched against known automation tools
- **Credential stuffing protection** - Form interaction analysis, timing, and programmatic submit/fill detection
- **Self-hosted & privacy-first** - No cookies, no third-party data sharing, no cross-site tracking. Nothing is written to disk and every retention window is enumerated in [COMPLIANCE.md](COMPLIANCE.md). Available on npm/CDN with Subresource Integrity when you'd rather not host the widget yourself
- **Accessible, and tested for it** - No visual or audio puzzle to fail. The widget's WCAG 2.2 AA position is verified in CI — contrast, focus visibility that survives a host stylesheet, target size, reflow, reduced motion — alongside a benchmark panel of screen-reader, keyboard-only, motor-tremor and elderly personas whose false-positive budget fails the build when exceeded
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

Docker Compose (single instance):

```bash
FCAPTCHA_SECRET=my-secret docker compose -f docker/docker-compose.yml up -d
```

FCaptcha state is currently process-local by default. The Go server can use
`REDIS_URL` to share PoW challenges, token replay protection, Siteverify
idempotency, rate limits, suspicion, fingerprint cardinality, and site-key
rotation guards across replicas. Challenge and token consumption are atomic.
It refuses to start if configured Redis is unavailable and fails closed if it
becomes unavailable later.

With `REDIS_URL`, the Go server can run multiple replicas. Node currently shares
PoW challenge/claim state only; its other stores remain local, so it must remain
single-instance. Python does not yet use Redis and must also remain
single-instance.

Kubernetes:

```bash
helm install fcaptcha ./charts/fcaptcha \
  --namespace fcaptcha --create-namespace \
  --set secret=$(openssl rand -hex 32)

helm test fcaptcha -n fcaptcha
```

The chart refuses to install without a signing key — see
[charts/fcaptcha](charts/fcaptcha/README.md), which also covers the
`trustedProxies` setting that matters more behind an ingress controller than
anywhere else.

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

**Where the widget comes from**

Two options, and the tradeoff is real:

```html
<!-- Self-hosted: served by your FCaptcha server, same-origin. -->
<script src="https://your-server.com/fcaptcha.js"></script>

<!-- CDN: no server needed to try it, pinned and integrity-checked. -->
<script
  src="https://cdn.jsdelivr.net/npm/@webdecoy/fcaptcha-client@1.31.0/dist/fcaptcha.min.js"
  integrity="sha384-…"
  crossorigin="anonymous"></script>
```

Self-hosting stays the default and is what every server does out of the box: no
third party sees your visitors, and there is no external dependency to fail. The
CDN build exists because "add one script tag" is the first thing anyone tries,
and requiring a running server before that is a poor first five minutes.

If you use the CDN, **pin the version and use the integrity hash**. The digest
for each release is published in that release's notes and in
`dist/integrity.json` inside the package; `npm run integrity` in `client/` prints
it for any local build. Without `integrity`, a compromised CDN can replace your
captcha with anything it likes.

The minified bundle is 67 KB, 18 KB over the wire with Brotli.

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

**Language**

The widget picks a language automatically: an explicit `lang` option, else
`data-lang` on the container, else the page's `<html lang>`, else the browser's
`navigator.language`, else English. The page outranks the browser deliberately —
a widget should match the form around it rather than the reader's locale.

```html
<!-- nothing to configure: inherits from the page -->
<html lang="de"> … <div id="captcha"></div>

<!-- or state it -->
<script>FCaptcha.render('captcha', { siteKey, lang: 'ja' });</script>

<!-- or per element, for the auto-rendered form -->
<div data-fcaptcha="your-site-key" data-lang="pt-BR"></div>

<!-- or site-wide -->
<script>FCaptcha.configure({ serverUrl: '…', lang: 'fr' });</script>
```

Region tags fall back to their base language, so `de-AT` resolves to `de`;
`pt-BR` and `zh-TW` have their own entries where the wording differs. Arabic,
Hebrew and Persian render right-to-left.

Shipped: `ar bg ca cs da de el en es fa fi fr he hi hu id it ja ko ms nb nl pl
pt pt-BR ro ru sk sv th tr uk vi zh-CN zh-TW` — `FCaptcha.languages()` returns
the live list.

Not on the list, or want different wording? Override any of the five strings —
no fork required:

```js
FCaptcha.render('captcha', {
  siteKey,
  lang: 'is',
  strings: {
    label: 'Ég er ekki vélmenni',
    verifying: 'Staðfesti…',
    verified: 'Staðfest',
    failed: 'Staðfesting mistókst',
    retry: 'Staðfesting mistókst. Reyndu aftur.',
  },
});
```

Overrides are HTML-escaped, so a string coming from a CMS or locale file cannot
turn the widget into an injection point.

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

**Already using Turnstile, reCAPTCHA or hCaptcha?** Point the verification call
you already have at your FCaptcha server — the contract is identical:

```diff
- https://challenges.cloudflare.com/turnstile/v0/siteverify
+ https://your-server.com/turnstile/v0/siteverify
```

```bash
curl -X POST https://your-server.com/turnstile/v0/siteverify \
  -d "secret=your-secret" -d "response=$TOKEN"
# {"success":true,"challenge_ts":"...","hostname":"example.com","action":"login",
#  "cdata":"","error-codes":[],"score":0.11}
```

See [POST /turnstile/v0/siteverify](#post-turnstilev0siteverify--drop-in-compatibility)
for the full contract, including `hostname`/`action` checking and
`idempotency_key`.

**Or use the native endpoint**, which returns FCaptcha's own shape:

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

## Privacy, accessibility and compliance

The properties a procurement review asks about, with the evidence behind them in
[COMPLIANCE.md](COMPLIANCE.md):

| | |
|---|---|
| **Cookies** | None. No consent banner needed for FCaptcha |
| **Third parties** | None. No SaaS, no telemetry, no phone-home, no CDN requirement |
| **Persistence** | Nothing written to disk. All state in memory, 5 minutes to 1 hour, enumerated |
| **Data location** | Your server, wherever you run it |
| **Automated decisions** | Every score itemised with a human-readable reason, so an Article 22 decision can be explained rather than quoted |
| **Accessibility** | No visual or audio puzzle. WCAG 2.2 AA criteria verified in CI; relevant to the European Accessibility Act |
| **False positives** | Measured against a labelled human panel on every run, with a per-signal budget that fails the build |

The accessibility work is tested rather than asserted, which is the part worth
checking: `test/browser/tests/a11y.spec.ts` computes contrast from what the
browser actually paints, focuses the control under a host stylesheet that
suppresses outlines globally, and measures the target box. Those checks were
written after an audit found the previous palette failing on seven counts,
including the checkbox border at 1.72:1.

## How It Works

FCaptcha collects signals across many categories and blends them into a single score (category weights sum to 1.0 and are tunable per deployment). The major surfaces:

### Proof of Work (Invisible Layer)
Before any verification, clients must solve a SHA-256 hashcash challenge:
- **Challenge fetched on page load** - solving runs in the background across parallel Web Workers (one per ~2 CPU cores)
- **Non-blocking** - users never see it, computation happens while they fill forms
- **Hardened** - 256-bit HMAC-signed challenges, one-time use, replay-protected, with a server-generated per-challenge nonce the client must echo back
- **Signal commitment** - the client hashes its collected signals into the PoW input (`prefix:signalsHash:nonce`) and the server verifies the signals weren't tampered with after solving
- **Difficulty scaling** - datacenter IPs and high-rate requesters get harder puzzles
- **Costs a real browser ~100-600ms** - measured: 0.12s on a desktop, 0.58s on a throttled low-end phone

### What the proof of work does and does not buy you

It is a **liveness and timing gate, not a cost function.** Be clear-eyed about this,
because the distinction decides whether the design is doing what you think.

The parts that hold up are the un-spoofable ones. The server signs each challenge,
allows it once, and measures the gap between issuing it and receiving a solution on
its own clock. A solution returned in under 1.5 seconds is scored as too fast
regardless of what the client claims, so a visitor cannot arrive with a
pre-computed answer, and each token costs an attacker a real 1.5 seconds of wall
clock per identity.

What the compute cost does **not** do is price an attacker out. Treat the hash as
a gate, not a toll, and do not lean on it as a rate limiter — that job belongs to
the timing floor above, and to IP and site-key limits.

This is also why SHA-256 having GPUs and ASICs behind it is not the weakness it
appears to be, and why swapping in a memory-hard function (Argon2id, RandomX)
would not help. Measured in a real browser, a difficulty-1 Argon2id search at
64MiB costs a throttled low-end phone **6.46s** against **0.58s** for what ships
today, plus a 64MB allocation and 28KB of WASM. That is a large, regressive cost
to honest mobile users for no gain in the constraint that actually binds. Numbers
in [bench/POW-PRIMITIVE.md](bench/POW-PRIMITIVE.md).

If you want proof of work to genuinely raise an attacker's cost, the lever is the
server-measured elapsed time, not the hash. That is what the adaptive cost keys
on.

The challenge is also bound to the source network that acquired that price
(IPv4 `/24`, IPv6 `/56`). This prevents an attacker from obtaining baseline-cost
challenges through an unrelated clean proxy and submitting them from an already
suspicious source, while tolerating nearby address rotation on mobile networks.

Each challenge carries a `minAgeMs`: how long it must be held before a solution
is accepted without penalty. A visitor who has done nothing wrong gets the same
1500ms floor the server has always applied. A source that has recently produced
strong bot verdicts gets more, up to 15 seconds — which takes it from roughly 40
tokens a minute to four, on hardware no amount of money can speed up.

Difficulty barely moves, and now caps at 5 rather than 6. Difficulty 6 costs a
native solver about a millisecond and a budget Android phone about sixteen
seconds; escalating there taxes the slowest legitimate devices and constrains
nobody. Being on a datacenter address no longer raises difficulty at all — a
real person on a corporate VPN or iCloud Private Relay was paying several seconds
of blocked hashing for a shared IP — and raises the time floor instead, which a
hosted scraper feels as reduced throughput and a person filling in a form does
not feel at all.

The client is told `minAgeMs` and waits it out, so for an ordinary visitor the
cost is a short delay rather than a worse score. That distinction matters most
for anyone sharing an egress address with whatever earned the delay. A client
that submits early anyway is scored, but only as contributory evidence — an
older cached client does not know to wait, and should not be treated as
automation for it.

Suspicion is held per (site key, address) for 15 minutes, records only verdicts
at or above 0.8, and stores nothing but timestamps. It is not cross-session
correlation and should not grow into it.

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
  "minAgeMs": 1500,
  "expiresAt": 1703357100000,
  "nonce": "f1e2d3...",
  "sig": "def456..."
}
```

The `nonce` is generated per-challenge by the server; the client echoes it back in `signals.meta.challengeNonce` and the server verifies it, preventing challenge replay.

`minAgeMs` is how long the client should hold the solved challenge before
submitting. The bundled client does this for you. Both fields are covered by
`sig`, so neither can be talked down on the way back.

Cost scales with what the requesting source has recently been caught doing:

| source | difficulty | minAgeMs |
|---|---|---|
| clean, or unknown | 4 | 1500 |
| 1–2 recent strong bot verdicts | 4 | 4000 |
| 3–5 | 5 | 8000 |
| 6+ | 5 | 15000 |

Datacenter addresses, high request rates and exceeded rate limits raise the time
floor only — never the difficulty. See [what proof of work does and does not buy
you](#what-the-proof-of-work-does-and-does-not-buy-you) for why.

### Preconditions: what a token requires beyond a good score

A token is issued only when **all** of these hold. They are checked outside the
score on purpose — a score threshold answers "how suspicious is this visitor",
which is the wrong question to ask of a caller that never completed the
challenge:

| Precondition | `reason` when it fails |
|---|---|
| The score is below the success threshold (0.5) | (score speaks for itself) |
| A **valid proof of work** for a challenge this server issued, with the signals bound to it | `pow_not_satisfied` |
| The minting origin is permitted, if `FCAPTCHA_ALLOWED_HOSTNAMES` is set | `hostname_not_allowed` |

The widget solves a proof of work on every path and aborts rather than submit
without one, so a request that arrives without a valid solution did not come from
the widget. Missing, forged, or unbound solutions are also `dispositive`: they
floor the reported score at 0.9, so an integrator risk-banding on the score sees
the same verdict the gate did.

This matters more than it looks. The final score is a weighted sum across ~12
categories, so **any one category contributes at most its own weight** — the
`bot` category caps at 0.13 against a 0.5 threshold. Before v1.23.0 that meant a
bare `curl` with no proof of work and no browser was issued a valid token: every
detector fired correctly and the aggregation discarded the verdict.

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

`secret` is **required** and checked against `FCAPTCHA_VERIFY_SECRET` (defaulting
to `FCAPTCHA_SECRET`). Until v1.22.0 it was accepted and silently ignored, which
meant anyone who could reach the endpoint could spend a token — set
`FCAPTCHA_LEGACY_UNAUTH_VERIFY=true` for one release if you need the old
behaviour while you update your backend.

`remoteip` is optional. When supplied, it must be the visitor IP associated with
the original browser request and is checked against the token. When omitted, no
IP check is performed. The API never uses the verification caller's socket
address for this check because that caller is normally your backend server.

```json
// Request
{
  "token": "...",
  "secret": "your-secret",
  "remoteip": "203.0.113.10"
}

// Response
{
  "valid": true,
  "site_key": "your-site-key",
  "score": 0.15,
  "timestamp": 1703356800,
  "hostname": "example.com",
  "action": "login",
  "cdata": "order-42"
}
```

A wrong or missing secret answers `401` with
`{"valid": false, "reason": "invalid_secret"}`.

### POST /turnstile/v0/siteverify — drop-in compatibility

FCaptcha also answers the siteverify contract that Turnstile, reCAPTCHA and
hCaptcha share, on all three paths:

```
POST /turnstile/v0/siteverify
POST /recaptcha/api/siteverify
POST /siteverify
```

Every backend SDK, CMS plugin and code snippet written against those services
speaks this shape already, so **migrating is a base-URL change**: point your
existing verification call at your FCaptcha server and keep the rest.

```bash
curl -X POST https://your-server.com/turnstile/v0/siteverify \
  -d "secret=your-secret" \
  -d "response=$TOKEN" \
  -d "remoteip=203.0.113.5"
```

Form-encoded and JSON bodies are both accepted.

| Parameter | Required | Meaning |
|-----------|----------|---------|
| `secret` | yes | Your `FCAPTCHA_VERIFY_SECRET` (defaults to `FCAPTCHA_SECRET`) |
| `response` | yes | The token from the widget |
| `remoteip` | no | Visitor IP; when supplied it must match the token's binding |
| `idempotency_key` | no | Lets a retry return the first answer instead of tripping the single-use guard |

```json
// Success
{
  "success": true,
  "challenge_ts": "2026-08-19T17:12:35.000Z",
  "hostname": "example.com",
  "action": "login",
  "cdata": "order-42",
  "error-codes": [],
  "score": 0.11
}

// Failure
{ "success": false, "error-codes": ["invalid-input-response"] }
```

`score` is the one addition to the contract — ignore it for pass/fail, or use it
to risk-band without a second call. Error codes use the upstream vocabulary:
`missing-input-secret`, `invalid-input-secret`, `missing-input-response`,
`invalid-input-response`, `bad-request`, `timeout-or-duplicate`,
`internal-error`.

**Verify `hostname` and `action` in your backend.** They are signed into the
token, so they are the mechanism that stops a token minted on someone else's
page — or minted for a different action — from being spent on yours:

```js
const r = await verify(token);
if (!r.success) return reject();
if (r.hostname !== 'example.com') return reject();  // key lifted from your page
if (r.action !== 'login') return reject();          // token minted elsewhere on your site
```

Set `action` (and optionally `cdata`) when you request the token —
`FCaptcha.execute(siteKey, { action: 'login' })` — and they are bound into it.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FCAPTCHA_SECRET` | Secret key for token signing | (required) |
| `FCAPTCHA_INSECURE_DEV_MODE` | Explicitly use the public development signing key. Local-only escape hatch; never expose a server with this enabled | off |
| `FCAPTCHA_VERIFY_SECRET` | Credential a backend presents to `/api/token/verify` and the siteverify endpoints. Split it from `FCAPTCHA_SECRET` so a leaked verify credential cannot also mint tokens | (`FCAPTCHA_SECRET`) |
| `FCAPTCHA_LEGACY_UNAUTH_VERIFY` | Restore the pre-1.22.0 behaviour where token verification accepted any caller. One release of migration cover; **do not leave it on** | off |
| `FCAPTCHA_ALLOWED_HOSTNAMES` | Comma-separated hostnames permitted to mint tokens, matched against the request's `Origin` (then `Referer`). Unset accepts any origin. A request with no derivable origin (native app, server-side call) is always allowed — an attacker who can forge an `Origin` would just forge a listed one | (any) |
| `PORT` | Server port | 3000 |
| `REDIS_URL` | Reserved; distributed state is not implemented yet | (unused) |
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
│   └── docker-compose.yml   # Single-instance Docker Compose deployment
├── .github/workflows/
│   ├── bench.yml            # Unit tests + E2E + gated detection benchmark
│   ├── docker-publish.yml   # GHCR publish on release
│   └── npm-publish.yml      # npm publish on release
├── .dockerignore
├── ARCHITECTURE.md          # Technical architecture documentation
└── README.md
```

> All three servers implement the same detection engine and must stay in sync. Each has unit tests that run in CI, and `test/test-detection.js` exercises the full pipeline against a running server.

## Development

```bash
# Run Go server
cd server-go && FCAPTCHA_SECRET=local-development-secret go run .

# Run Python server
cd server-python && FCAPTCHA_SECRET=local-development-secret python server.py

# Run Node server
cd server-node && FCAPTCHA_SECRET=local-development-secret node server.js

# Open demo
open demo/index.html
```

### Running Tests

Unit tests, no server required. All three run in CI on every pull request.

```bash
cd server-go     && go test -race ./...              # Go
cd server-node   && npm test                         # Node
cd server-python && python -m unittest discover -p "test_*.py"   # Python
```

The Python tests are plain functions collected by a decorator rather than
`TestCase` methods, so `testkit.py` bridges them into `unittest` — run a single
file directly (`python test_sitekeys.py`) for readable per-test output. Discovery
and direct execution both report the same set; if the discovered count drops, a
file has stopped being discoverable.

The measurement harness has its own tests:

```bash
cd bench && npm test
```

End-to-end detection suite (runs against a live server):

```bash
# Start a server first (any language)
cd server-node && FCAPTCHA_SECRET=fcaptcha-test-suite-secret node server.js &

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

Contributions welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first. AI-agent detection is built out in phases — declared agents, input-event forensics, Web Bot Auth signature verification, the measurement harness, and typing/scroll/platform-coherence forensics have shipped; hosted-agent environment composites, accessibility-tree honeypots, and cross-session correlation are still open.

The most useful contribution right now is **captured traces from real browsers
driven by real people**. The benchmark corpus is currently scripted personas from
a single machine, which bounds what any false-positive number from it can mean.
`bench/corpus/captured/` takes new samples directly — see [bench/README.md](bench/README.md).

Other open areas are listed in [CONTRIBUTING.md](CONTRIBUTING.md#what-is-most-useful-right-now),
along with how to run the test suites and what to measure before adding a detector.

When adding or changing a detector, apply it to **all three** server implementations (Go, Python, Node) so they stay in sync.

Security problems go to [SECURITY.md](SECURITY.md), not the issue tracker.

## License

MIT License - use freely, contribute back if you can.

---

**Privacy Note**: FCaptcha is designed with privacy in mind. No persistent fingerprinting, no cross-site tracking, no PII collection. All fingerprints are session-scoped and used only for bot detection.
