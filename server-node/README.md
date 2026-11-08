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
  secret: process.env.FCAPTCHA_SECRET,
  // Required for multiple processes or replicas: provide one implementation
  // whose claim(signature) operation is atomic and shared (for example Redis).
  tokenStore: sharedTokenStore
});

// Generate a PoW challenge
const challenge = engine.generateChallenge('my-site', clientIP);

// Verify a submission
const result = engine.verify(
  signals, clientIP, siteKey, userAgent, headers, powSolution,
  signalsJson, powTiming,
  { hostname: 'app.example.com', action: 'login', cdata: sessionId }
);

if (result.success) {
  // User passed verification
  console.log('Score:', result.score);
  console.log('Token:', result.token);
}
```

Engines in one Node process share the default replay store. Multiple processes
or replicas must inject one shared atomic `tokenStore`; otherwise no in-memory
implementation can enforce one-time redemption across them.

`createMiddleware()` binds tokens to the request `Origin`/`Referer` and the
submitted `action`/`cdata`. Its `tokenVerifyHandler` is server-to-server and
requires `secret` in the request body. Set `verifySecret` in middleware options
to split that credential from the signing secret. A relying backend must compare
the returned `hostname` and `action` with the values expected for the protected
operation before granting it.

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
  TokenStore,           // Process-local replay store / custom-store interface
  detection,            // Detection utilities
  createScoringEngine,  // Factory function
  createMiddleware,     // Express middleware factory
} = require('@webdecoy/fcaptcha');
```

## Documentation

Full documentation: [github.com/webdecoy/fcaptcha](https://github.com/webdecoy/fcaptcha)

## License

MIT
