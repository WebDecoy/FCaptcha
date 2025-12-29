# @webdecoy/fcaptcha

Open source CAPTCHA with Proof of Work, bot detection, and Vision AI protection.

## Installation

```bash
npm install @webdecoy/fcaptcha
```

## Quick Start

```javascript
const { createScoringEngine } = require('@webdecoy/fcaptcha');

// Create a scoring engine
const engine = createScoringEngine({
  secret: process.env.FCAPTCHA_SECRET
});

// Generate a PoW challenge
const challenge = engine.generateChallenge('my-site', clientIP);

// Verify a submission
const result = engine.verify(signals, clientIP, siteKey, userAgent, headers, powSolution);

if (result.success) {
  // User passed verification
  console.log('Score:', result.score);
  console.log('Token:', result.token);
}
```

## Features

- **Proof of Work** - SHA-256 challenges that force compute cost on attackers
- **Vision AI Detection** - Detects screenshot→API→click automation patterns
- **Bot Detection** - Headless browsers, WebDriver, Puppeteer, Playwright, Selenium
- **Behavioral Analysis** - 40+ signals including micro-tremor and velocity variance
- **Privacy-First** - No persistent fingerprinting or cross-site tracking

## Exports

```javascript
const {
  ScoringEngine,        // Main verification engine
  PoWChallengeStore,    // Challenge storage
  RateLimiter,          // Rate limiting
  FingerprintStore,     // Fingerprint tracking
  detection,            // Detection utilities
  createScoringEngine,  // Factory function
  createMiddleware,     // Express middleware factory
} = require('@webdecoy/fcaptcha');
```

## Documentation

Full documentation: [github.com/webdecoy/fcaptcha](https://github.com/webdecoy/fcaptcha)

## License

MIT
