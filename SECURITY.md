# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use [GitHub's private vulnerability reporting](https://github.com/WebDecoy/FCaptcha/security/advisories/new),
which is enabled on this repository. If that is unavailable to you, email
**hello@webdecoy.com** with `FCaptcha security` in the subject.

What helps most, roughly in order:

- What the issue lets an attacker do, stated plainly.
- A reproduction. A `curl` command or a short script beats prose.
- Which server implementations you checked. Go, Python and Node are separate
  codebases kept in sync by hand, so a finding in one is often — but not
  always — present in the other two.
- The version or commit.

You do not need a working exploit, and you do not need to be sure. A clear
description of something that looks wrong is worth sending.

### What to expect

- **Acknowledgement within 3 working days.** If you have not heard back, assume
  the mail went astray and ping the issue tracker without details.
- An assessment, including whether we agree it is a vulnerability and why.
- A fix in a release, with credit in the release notes unless you would rather
  not be named.

This is a small project without a paid security team; there is no bug bounty.
What there is, is a genuine interest in being told.

## Scope

In scope: anything in this repository — the three servers, the browser widget,
the benchmark harness, and the published `@webdecoy/fcaptcha` and
`@webdecoy/fcaptcha-client` packages and container images.

Particularly interesting:

- **Token forgery or replay** — minting a token without completing a challenge,
  or spending one twice.
- **Verification bypass** — anything that gets a passing verdict without doing
  the work. See the note below on scoring.
- **Signal spoofing that is cheap and general** — a technique that makes any
  automated browser score like a human, as distinct from a hand-tuned evasion of
  one detector.
- **Anything that harms legitimate visitors** — a false positive that can be
  induced remotely, a way to get another user blocked, or a denial of service
  against the scoring path.

## A note on what counts as a vulnerability here

This is a detection system, so "I evaded a detector" and "I broke the security
model" are different claims, and it is worth being explicit about which is which.

**Individual detector evasion is expected.** Every behavioural and environmental
signal can be defeated by someone willing to spend enough effort — that is the
nature of the problem, and the scoring is designed around accumulating evidence
rather than relying on any single tell. A patched Chromium that hides
`navigator.webdriver` is not a vulnerability report; it is the adversary the
roadmap already assumes. Please do send it if the technique is cheap, general,
and defeats many signals at once.

**Structural bypasses are vulnerabilities.** Anything that skips the mechanism
rather than beating it: forging a token, replaying a challenge, getting a token
without a valid proof of work, making the server trust a header it should not.

A worked example of the second kind, fixed in v1.23.0: the proof of work was
scored as evidence rather than enforced as a precondition, and because the final
score is a weighted sum in which any one category contributes at most its own
weight, a bare `curl` sending `{"siteKey":"x","signals":{}}` was issued a valid
token. Every detector fired correctly; the aggregation discarded the verdict.
That is the shape of a report worth sending.

## Supported versions

The latest minor release receives security fixes. Given how young this project
is, older lines are not maintained — upgrade rather than expect a backport.

| Version | Supported |
|---------|-----------|
| 1.34.x  | Yes       |
| < 1.34  | No        |

## Deployment notes that are security-relevant

Several ways to make a correct build insecure, documented because they are easy
to get wrong and fail quietly:

- **`FCAPTCHA_SECRET`** signs every token and is required. Servers refuse to
  start without it or when it equals the public development key. The explicit
  `FCAPTCHA_INSECURE_DEV_MODE=1` escape hatch exists only for local development;
  a deployment using it can have tokens minted by anyone.
- **`TRUSTED_PROXIES`** decides whose `X-Forwarded-For` is believed. Left
  unset behind a proxy, every visitor is attributed to the proxy and rate
  limiting collapses onto one address. Set wrong, a client can claim any IP.
  See [Trusted proxies](README.md#trusted-proxies).
- **`FCAPTCHA_LEGACY_UNAUTH_VERIFY`** disables the secret check on token
  verification. It exists only as one release of migration cover and should not
  be on.
- **Check `hostname` and `action`** from the verification response. They are
  signed into the token so that a token minted on another site, or for another
  action, can be rejected — but only if you look.
- **Pin and integrity-check the widget** if you load it from a CDN. A captcha is
  the control deciding whether a request is trusted; a CDN that can silently
  replace it can switch it off. Digests are published with each release.
