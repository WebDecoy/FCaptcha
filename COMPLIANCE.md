# Privacy and compliance

Written for whoever has to sign off on deploying this — a DPO, a security reviewer,
or a procurement questionnaire. It states what FCaptcha collects, what it keeps,
and for how long, including the parts that are less flattering.

Nothing here is legal advice. FCaptcha is self-hosted software: you are the
controller, and the obligations are yours. What this page does is make the facts
available so you can answer for them.

## The short answer

- **No cookies.** None are set, so no consent banner is needed for FCaptcha.
- **No third parties.** Signals go to your server and stop there. There is no
  FCaptcha SaaS, no telemetry, no phone-home, no CDN requirement.
- **Nothing is written to disk.** All state is in memory and expires on a timer,
  the longest being one hour.
- **No cross-site or cross-session tracking.** Nothing identifies a returning
  visitor, by design and by construction — the state that could is discarded
  before it would be useful for that.
- **But it does fingerprint.** Canvas, WebGL, audio and font measurements are
  collected and scored. See [What is collected](#what-is-collected). This is more
  than some alternatives collect, and pretending otherwise would be dishonest.

## What is collected

The widget gathers signals in the browser and sends them to **your** server for
scoring. Nothing is transmitted anywhere else.

### Behavioural

Mouse and pointer movement, touch kinematics, scroll behaviour, keyboard timing
(**timing only — never key values**), focus events, and the time between page
load and interaction.

Keystroke handling is worth being precise about, because it is the signal people
worry about: FCaptcha records *when* keys were pressed and how long they were
held, and the **length** of the value in a field. It does not record which keys,
and it does not record field contents. There is no keylogger here.

If you audit `client/fcaptcha.js` you will find comparisons against `event.key` —
checking for `Control`/`Shift`/`Meta` to exclude modifiers from timing, and for
`v`/`a` to recognise paste and select-all shortcuts. Those comparisons happen in
the browser and produce a boolean or a count. The key itself is never stored and
never transmitted; the only key-derived value that leaves the browser is its
length, at `client/fcaptcha.js:314`, which carries the comment *"Don't store
actual keys."*

### Environmental

Screen and viewport dimensions, platform, language, timezone, hardware
concurrency, device memory, installed fonts, WebGL vendor/renderer, audio context
parameters, and hashes derived from canvas, WebGL, audio and DOMRect rendering.

Plus automation markers — `navigator.webdriver`, driver-injected globals, CDP
artefacts — which are the actual point of the exercise.

### Network

Your server sees the client IP, User-Agent and request headers, as any web server
does. If a TLS fingerprint (JA3/JA4) is available from your reverse proxy, it is
used.

### Not collected

No cookies. No localStorage or sessionStorage. No persistent identifier of any
kind. No key values, no field contents, no page content, no browsing history, no
data from other sites.

## What is retained, and for how long

All of it is in process memory. **There is no database and nothing is written to
disk.** Restart the server and every value below is gone.

| State | Keyed on | Lifetime |
|---|---|---|
| Proof-of-work challenges | site key + IP | 5 minutes |
| Spent PoW solutions (replay guard) | solution hash | 10 minutes |
| Spent tokens (replay guard) | token signature | 10 minutes |
| Suspicion ledger (adaptive cost) | site key + IP | 15 minutes |
| Rate-limit counters | site key + IP | 60-second windows |
| Site-key state bounds | IP | 1 hour |
| Siteverify idempotency cache | caller-supplied key | 5 minutes |
| TLS fingerprints, when terminating TLS | connection | 5 minutes |

Two honest details:

**The client IP is held in memory in raw form**, as the key of those short-lived
maps. It is not hashed there, and it is not written anywhere. (The IP *inside an
issued token* is hashed — a truncated SHA-256 — because that value travels.)

**Issued tokens carry** the site key, a timestamp, the score, a hashed IP, and the
hostname, action and customer data your integration supplied. Tokens are valid for
5 minutes and single-use.

## Logging

Off by default. A self-hosted FCaptcha emits **no per-request logs** unless you
turn them on.

`FCAPTCHA_LOG_VERDICTS=1` emits one JSON line per verification: score,
recommendation, category scores, and per-detection category/score/confidence. It
deliberately omits IP, User-Agent, and raw signals.

`FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW=1` additionally includes free-text detection
reasons, which **can contain visitor-derived data** — reverse-DNS hostnames,
User-Agent fragments, form field ids. Do not enable it where you have privacy
obligations. It exists for debugging and says so in its own warning at startup.

## Automated decision-making

FCaptcha produces a score that your application acts on, which may engage GDPR
Article 22 depending on what you do with it. Two properties help:

**Every decision is explainable.** The verification response contains the
individual detections with their category, score, confidence and a human-readable
reason. You can tell a data subject *why* — "no mouse movement was recorded before
the click," "the browser reported `navigator.webdriver`." This is not a model
whose output cannot be accounted for.

**The algorithm is open.** Weighted categories, noisy-OR within a category, a
documented floor for dispositive signals. Auditable in the source, and described
in [the README](README.md#how-the-score-is-composed).

## Accessibility

Relevant to the European Accessibility Act as well as to not excluding people.

FCaptcha is invisible or a single click — there is no visual puzzle, no distorted
text, no image grid, and therefore no audio alternative to get wrong. The widget
exposes a proper `checkbox` role with an accessible name, announces state changes
through a live region, and carries its resolved language so screen readers
pronounce it correctly.

More usefully, the accessibility claims are **measured**. The benchmark harness
carries keyboard-only, screen-reader, touch, motor-tremor, elderly and
high-latency personas, and CI fails when any signal fires on the human panel more
often than its budget allows. Detectors have been removed for firing on those
personas. See [bench/README.md](bench/README.md).

## Compared with ALTCHA

ALTCHA is the closest open-source alternative and makes privacy its central
claim. Its four documented claims — no cookies or fingerprinting, processing on
your servers, no identifiable information, no third-party dependencies — are worth
taking seriously, and FCaptcha meets three of the four.

**Where ALTCHA collects less:** it does not fingerprint. No canvas, no WebGL, no
font enumeration. That difference is real and this page is not going to obscure
it — it is the direct consequence of the two products solving different problems.
A proof-of-work check establishes that a client did some work. It does not
establish that a client is a browser driven by a person, which is what detecting
an automated agent requires, and there is no way to determine that without
observing the environment.

**Where FCaptcha is ahead:**

**There is no cloud tier to leak into.** ALTCHA's Sentinel — the tier carrying its
IP intelligence, geo-location, threat-intel and NLP classification — is a hosted
service. Those features mean visitor data reaching a third party, with the DPA and
transfer questions that follow. FCaptcha has no hosted tier: the open-source
product is the whole product, and it cannot phone home because there is nowhere
for it to phone.

**The decision is explainable, not a model output.** Sentinel's classifier is
NLP/ML returning a likelihood score. FCaptcha's is a documented weighted sum over
named detections, each with a reason string. Under Article 22 that is the
difference between showing a data subject the reasoning and showing them a number.

**The false-positive rate is measured and published.** ALTCHA documents WCAG
compliance; it publishes no false-positive data. FCaptcha reports a per-signal
false-positive rate against a labelled human panel on every CI run, and the build
fails when a signal exceeds its budget. For an accessibility or
non-discrimination argument, "we measure whether we exclude people, here are the
numbers, and here is the harness — run it yourself" is a materially stronger
position than a compliance assertion.

**Retention is enumerated rather than asserted.** The table above exists. We are
not aware of an equivalent.

The summary: **ALTCHA collects less; FCaptcha accounts for more.** FCaptcha
processes more signals because detecting an automated browser requires observing
one, and this page exists so that the extra processing is disclosed, bounded,
explainable and measured rather than quietly extensive. Every signal is listed
above, every retention window is enumerated, nothing leaves your server, and the
false-positive cost is measured in CI. Weigh that against your own requirement.

## Answering a questionnaire

| Question | Answer |
|---|---|
| Are cookies set? | No |
| Is consent required for FCaptcha? | No cookie consent. Assess the fingerprinting under your own lawful basis |
| Is data sent to a third party? | No |
| Where is data processed? | Your server, wherever you run it |
| Is anything written to disk? | No |
| How long is data retained? | In memory only; 5 minutes to 1 hour, see the table |
| Is there a DPA? | Not applicable — no processor. You self-host |
| Is personal data transferred internationally? | Not by FCaptcha |
| Is there automated decision-making? | It produces a score; the decision is yours. Every score is itemised and explainable |
| Can a decision be explained to a data subject? | Yes — detections carry categories and reasons |
| Is there a data subject to erase? | No stored record keyed to a person; state expires within the hour regardless |
| Is it accessible? | No visual or audio puzzle; measured against assistive-technology personas in CI |

## Reducing collection further

If your assessment says the fingerprinting is more than you want:

- `FCAPTCHA_LOG_VERDICTS` unset (the default) means no per-request logging.
- Serve the widget from your own origin, which is the default, so no third-party
  request is made at all.
- The signal collectors in `client/fcaptcha.js` are individually removable. Doing
  so weakens detection, and you should measure the effect with `bench/` rather
  than assume it.

Security-relevant deployment settings are in [SECURITY.md](SECURITY.md).
