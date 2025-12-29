# F***Captcha

**Open source CAPTCHA that blocks bots, vision AI agents, and automation - with a single click or less.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?logo=python)
![Node](https://img.shields.io/badge/Node-20+-339933?logo=node.js)

**[Try the Live Demo](https://webdecoy.com/product/fcaptcha-demo/)**

FCaptcha is a modern CAPTCHA system designed to detect everything: traditional bots, headless browsers, automation frameworks, CAPTCHA farms, and the new generation of vision-based AI agents.

## Features

- **Single click or invisible** - Checkbox mode like Turnstile/reCAPTCHA v2, or invisible mode like reCAPTCHA v3
- **Vision AI detection** - Specifically tuned to detect screenshot→API→click automation patterns
- **Proof of Work** - Server-verified SHA-256 challenges that force compute cost on attackers
- **Comprehensive bot detection** - Headless browsers, WebDriver, Puppeteer, Playwright, Selenium
- **Behavioral analysis** - 40+ signals including micro-tremor, velocity variance, trajectory analysis
- **Credential stuffing protection** - Form interaction analysis, timing detection, programmatic submit detection
- **Self-hosted** - No external dependencies, run on your own infrastructure
- **Privacy-first** - No persistent fingerprinting, no cross-site tracking
- **Open algorithm** - Transparent scoring, fully auditable
- **Multi-language servers** - Go, Python, or Node.js - pick your stack

## Quick Start

### 1. Run the Server

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

**Docker (any language)**
```bash
# Go
docker build -t fcaptcha server-go/
docker run -p 3000:3000 -e FCAPTCHA_SECRET=your-secret fcaptcha

# Python
docker build -t fcaptcha server-python/
docker run -p 3000:3000 -e FCAPTCHA_SECRET=your-secret fcaptcha

# Node
docker build -t fcaptcha server-node/
docker run -p 3000:3000 -e FCAPTCHA_SECRET=your-secret fcaptcha
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

FCaptcha collects signals across multiple categories:

### Proof of Work (Invisible Layer)
Before any verification, clients must solve a SHA-256 hashcash challenge:
- **Challenge fetched on page load** - solving happens in background via Web Worker
- **Non-blocking** - users never see it, computation happens while they fill forms
- **Server-verified** - one-time use, replay protected, signed challenges
- **Difficulty scaling** - datacenter IPs and high-rate requesters get harder puzzles
- **Forces compute cost** - each attempt requires ~100-500ms of CPU time

This makes credential stuffing expensive: even if a bot passes all other checks, it still burns compute for every attempt.

### Behavioral Signals (40% weight)
- Mouse trajectory, velocity, acceleration curves
- Micro-tremor detection (humans have natural hand shake at 3-25Hz)
- Click precision and approach patterns
- Pre-click exploration behavior
- Overshoot corrections
- Straight-line ratio detection

### Environmental Signals (35% weight)
- WebDriver/automation framework detection (Selenium, Puppeteer, Playwright, PhantomJS, Nightmare, Watir)
- Headless browser indicators
- Canvas/WebGL/Audio fingerprinting
- Plugin and browser feature checks
- User-Agent pattern matching

### Temporal Signals (15% weight)
- Proof of Work timing (reveals API round-trip latency)
- Interaction timing patterns
- Event sequence analysis
- Page load to interaction timing

### Form Interaction Signals (10% weight)
- Programmatic form.submit() detection
- Time from page load to submission
- Events before submit (no events = bot)
- Textarea keyboard analysis (paste detection, typing speed, rhythm)

## Vision AI Detection

Modern AI agents work like this:
1. Take screenshot
2. Send to vision API (GPT-4V, Claude, etc.)
3. Get click coordinates
4. Execute click

This pattern has exploitable characteristics:

| Signal | Human | Vision AI |
|--------|-------|-----------|
| Mouse movement | Natural curves, micro-tremor | Smooth/linear paths |
| Pre-click behavior | Exploration, hesitation | Direct path to target |
| Click timing | Variable, 200-800ms | Consistent, often faster |
| Coordinate precision | Slight variance | Pixel-perfect |
| PoW timing | Consistent with local execution | Delayed by API round-trip |

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
  "sig": "def456..."
}
```

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
  "powSolution": {
    "challengeId": "abc123...",
    "nonce": 68455,
    "hash": "0000abc..."
  }
}

// Response
{
  "success": true,
  "score": 0.15,
  "token": "...",
  "recommendation": "allow"
}
```

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
│   └── fcaptcha.js          # Client-side widget, signal collection, PoW Web Worker
├── server-go/
│   ├── main.go              # Go HTTP server
│   ├── scoring.go           # Scoring engine + PoW verification
│   ├── detection.go         # IP reputation, header analysis, browser checks
│   ├── go.mod
│   └── Dockerfile
├── server-python/
│   ├── server.py            # Python/FastAPI server + PoW
│   ├── detection.py         # Detection modules
│   ├── requirements.txt
│   └── Dockerfile
├── server-node/
│   ├── server.js            # Node.js/Express server + PoW
│   ├── detection.js         # Detection modules
│   ├── package.json
│   └── Dockerfile
├── test/
│   └── test-detection.js    # Comprehensive test suite (50 tests)
├── demo/
│   └── index.html           # Interactive demo page
├── docker/
│   └── docker-compose.yml   # Docker compose for Go + Redis
├── ARCHITECTURE.md          # Technical architecture documentation
└── README.md
```

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

```bash
# Start a server first (any language)
cd server-node && node server.js &

# Run the test suite
node test/test-detection.js

# Expected output: 50 tests, all passing
```

The test suite covers:
- Bot user-agent detection (10 tests)
- Headless browser detection (3 tests)
- Datacenter IP detection (9 tests)
- HTTP header analysis (3 tests)
- Browser consistency checks (4 tests)
- Behavioral signal analysis (2 tests)
- Vision AI detection (3 tests)
- Form interaction analysis (6 tests)
- Proof of Work (6 tests)
- Token verification (2 tests)
- Invisible mode scoring (2 tests)

## Contributing

Contributions welcome! Please read the architecture docs first.

Areas that could use help:
- Machine learning-based scoring
- Integration libraries (React, Vue, etc.)
- Admin dashboard
- External IP intelligence API integration (IPQualityScore, etc.)
- WebAssembly-based PoW for better mobile performance
- Redis-backed distributed state (currently in-memory)

## License

MIT License - use freely, contribute back if you can.

---

**Privacy Note**: FCaptcha is designed with privacy in mind. No persistent fingerprinting, no cross-site tracking, no PII collection. All fingerprints are session-scoped and used only for bot detection.
