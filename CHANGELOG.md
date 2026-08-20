# Changelog

Notable changes per release. Full notes, including the reasoning behind each
change, are on the [releases page](https://github.com/WebDecoy/FCaptcha/releases).

This file exists because FCaptcha is a security dependency: anyone deciding
whether to take an upgrade should be able to see what moved without reading a
diff. **Breaking changes and anything security-relevant are called out
explicitly.**

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [Semantic Versioning](https://semver.org/) — with the caveat
that pre-2.0 it has used minor bumps for behaviour changes that a stricter
reading would call major. Read the **Breaking** entries rather than the number.

## [1.27.0] — 2026-08-20

### Fixed
- **A browser detectable only by how it moves could not be blocked.** A
  source-patched browser scrubs every JS-observable automation flag, so it trips
  no environmental category — and since the weighted sum keeps that unused
  budget, such a browser had a ceiling of 0.41 against a 0.5 threshold. The
  corpus sample tripped seven correct behavioural detections and scored 0.234,
  allowed. The score is now floored at 0.6 when two or more behavioural
  categories independently agree. Constants swept against the labelled corpus;
  no human in the 126-sample panel reaches two agreeing behavioural categories at
  any threshold tested.
- The benchmark harness timed its challenge wait from before requesting the
  challenge rather than from receiving it, so network latency ate the margin and
  the gate failed intermittently.

### Added
- `COMPLIANCE.md` — what is collected, what is retained and for how long,
  verified against the source. Written for a DPO or a procurement questionnaire.

## [1.26.0] — 2026-08-20

### Added
- A Helm chart (`charts/fcaptcha`), which the ArtifactHub registration had been
  pointing at for months without one existing. Refuses to install without a
  signing key, warns when replicas or trusted proxies are misconfigured, and
  ships a `helm test` that checks more than liveness.
- SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, this changelog, and issue/PR
  templates — including a dedicated false-positive report.

### Fixed
- **`HEAD` returned 405 on the Go and Python servers** for `/health` and
  `/fcaptcha.js`. Express routes HEAD to its GET handler, so Node was correct and
  nothing compared them. Caching proxies revalidate with HEAD and uptime monitors
  probe with it, so a 405 reads as an outage on a working server.

## [1.25.0] — 2026-08-20

### Added
- `@webdecoy/fcaptcha-client` — the browser widget as its own npm package, so a
  CDN URL exists and trying FCaptcha no longer requires standing up a server.
- Minified build: 131.8 KB → 67.6 KB, 17.5 KB over the wire with Brotli.
- Subresource Integrity digests for both widget files, published per release. If
  you load the widget from a CDN, pin the version and use the hash.

## [1.24.0] — 2026-08-20

### Added
- The widget is localized into 34 languages, detected from an explicit `lang`
  option, `data-lang`, the page's `<html lang>`, or the browser. Right-to-left
  layout for Arabic, Hebrew and Persian. A `strings` option overrides any key.

### Fixed
- **Accessibility:** the checkbox had no accessible name — `role="checkbox"` sat
  beside an unassociated label, so screen readers announced "checkbox, not
  checked" and nothing else. State changes (verifying / verified / failed) were
  also never announced. Both fixed.
- The Go and Python servers served the widget without a charset, so non-ASCII
  strings would render as mojibake on any page not already UTF-8.
- `/api/score` now reports the `reason` a token was withheld, matching
  `/api/verify`.

## [1.23.0] — 2026-08-19

### Security
- **A valid proof of work is now required for a token.** It was previously
  scored as evidence rather than enforced, and because the final score is a
  weighted sum in which any category contributes at most its own weight (`bot`
  is 0.13, against a 0.5 threshold), a bare `curl` sending
  `{"siteKey":"x","signals":{}}` was issued a valid token — on every server,
  every time. Every detector fired correctly; the aggregation discarded the
  verdict. Present in 1.21.0 and earlier.
- Missing, unverifiable and nonce-unbound solutions are now `dispositive`, so
  the reported score is 0.9 rather than 0.4.

### Fixed
- The three servers emitted mutually unverifiable tokens (Go padded base64url,
  Node unpadded, Python a differently-spaced signing payload). Only surfaced in
  a mixed fleet, where the instance validating a token is not the one that
  minted it. All three now agree, and accept the old encodings.

### Breaking
- A custom client calling `/api/verify` directly must complete the handshake.
  There is no flag to restore the old behaviour — it was a bypass.

## [1.22.0] — 2026-08-19

### Added
- Turnstile / reCAPTCHA / hCaptcha `siteverify` compatibility on
  `/turnstile/v0/siteverify`, `/recaptcha/api/siteverify` and `/siteverify`.
  Migrating an existing backend integration is a base-URL change.
- Tokens carry a signed `hostname`, `action` and `cdata`, so a backend can reject
  a token minted on another site or for a different action.
- `FCAPTCHA_VERIFY_SECRET`, `FCAPTCHA_ALLOWED_HOSTNAMES`, and `idempotency_key`
  support for safe retries.

### Security
- **`secret` is now checked on token verification.** All three servers accepted
  the parameter and ignored it, so anyone who could reach `/api/token/verify`
  could spend a token — and since tokens are single-use, burn a real visitor's.
  The README had always documented sending it, which made the omission worse.

### Breaking
- `/api/token/verify` requires `secret`. `FCAPTCHA_LEGACY_UNAUTH_VERIFY=true`
  restores the old behaviour for one release.

## [1.21.0] — 2026-07-28

### Added
- Adaptive challenge cost: escalation moved to wall-clock (`minAgeMs`) rather
  than proof-of-work difficulty, priced from a per-source suspicion ledger.
  Datacenter addresses no longer raise difficulty.

## [1.20.0] — 2026-07-28

### Fixed
- Signal accuracy: `webdriver_configurable` and `chrome_runtime_missing` fire on
  genuine Chrome. Measured on the bench, then removed.

## [1.19.0] – [1.19.2] — 2026-07-28

### Added
- Native JA4-TLS fingerprinting from the ClientHello when the Go server
  terminates TLS itself, rather than trusting a proxy header. Go 1.24.
- Node and Python container images.

### Fixed
- The published Docker image returned 404 for `/fcaptcha.js` for three months
  (`resolveClientPath` did not probe `./static/`). A smoke test now catches it.

## [1.18.0] — 2026-07-28

### Added
- The measurement harness (`bench/`): a labelled corpus, a replayer, and
  per-signal false-positive budgets enforced in CI. Every threshold in the
  behavioural layer was re-derived from it.
- Input forensics v2: typing cadence, paste/platform contradictions,
  programmatic fill, scroll morphology, font/OS coherence.

### Fixed
- **Score aggregation within a category is now noisy-OR, not a confidence-weighted
  mean.** The mean made corroborating evidence *lower* the verdict: WebDriver
  alone scored 0.950, and WebDriver plus seven more automation signals scored
  0.686.
- Dispositive signals (`navigator.webdriver`, driver-injected globals) set a 0.9
  floor, because a weighted sum across ~12 categories otherwise caps a blatant
  local agent near 0.5.

## [1.17.0] — 2026-07-27

### Added
- Web Bot Auth protocol-00 typed directory discovery.
- Bounded per-siteKey state: caller-supplied site keys could allocate unbounded
  server memory.

## [1.16.0] — 2026-07-27

### Security
- Trusted-proxy client IP resolution. `X-Forwarded-For` and `X-Real-IP` are read
  only from a peer in `TRUSTED_PROXIES`; previously any client could claim a
  clean residential address and skip the datacenter, Tor/VPN and rate-limit
  checks.

### Breaking
- Deployments behind a reverse proxy must set `TRUSTED_PROXIES` or every visitor
  is attributed to the proxy.

## [1.15.0] — 2026-07-24

### Added
- Web Bot Auth (RFC 9421) signature verification against the agent's published
  key directory, for Go and Node. A signature claiming an identity and failing to
  prove it is the interesting outcome.

## [1.14.0] — 2026-06-29

### Added
- Stealth-patch artifact detection for cloud AI agents.

## [1.11.0] – [1.13.0] — 2026-06

### Added
- Declared AI agent detection (ClaudeBot, GPTBot, PerplexityBot and similar) as
  its own category, so a deployment can allow polite agents and block the rest.
- Input-event forensics and think-time cadence.

### Fixed
- Proof-of-work deadlock and reverse-DNS timeout.

## [1.6.0] – [1.10.2] — 2026-03 → 2026-06

### Added
- Signal commitment binding the challenge to the collected signals, per-challenge
  nonces, full 256-bit HMAC signatures.
- Parallel client-side proof of work; single-origin widget delivery;
  mobile-native detection.

### Security
- HMAC signatures are no longer truncated to 64 bits.

## [1.0.0] – [1.5.0] — 2026-02

Initial releases: proof of work, behavioural biometrics, headless and automation
detection, Docker images and one-command deploys, keystroke cadence analysis.

[1.27.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.27.0
[1.26.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.26.0
[1.25.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.25.0
[1.24.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.24.0
[1.23.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.23.0
[1.22.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.22.0
[1.21.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.21.0
[1.20.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.20.0
[1.18.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.18.0
[1.17.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.17.0
[1.16.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.16.0
[1.15.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.15.0
[1.14.0]: https://github.com/WebDecoy/FCaptcha/releases/tag/v1.14.0
