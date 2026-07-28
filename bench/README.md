# FCaptcha measurement harness

A labeled corpus, a replayer, and per-signal false-positive accounting.

FCaptcha has always made claims about false positives — that keyboard-only users
are exempt, that privacy extensions are safe, that touch users are not treated as
bots — and until this existed, none of them were measured. This is the apparatus
that makes those claims checkable, including when they turn out to be wrong.

```bash
# 1. start any server
cd ../server-node && npm start        # or server-go: go run .   /   server-python: python server.py

# 2. record the corpus from a real browser (one-time; commit the result)
cd ../bench && npm install && npm run install-browsers
node capture/record.js

# 3. measure
node run-bench.js                     # human FPR, agent TPR, per-signal budgets
node run-bench.js --gate              # non-zero exit when a signal is over budget
node run-bench.js --json out.json     # machine-readable
```

---

## What the numbers do and do not establish

This is the part to read before quoting anything from the output.

**The corpus is captured, not sampled.** Traces come from a real Chromium driven
through real input events, so the signal payloads are exactly what the client
produces — including fields nobody remembered were there. What it is *not* is a
sample of the human population. Fourteen personas driven by scripted input are a
structural stand-in for fourteen kinds of user, not evidence about how often real
users of each kind get flagged.

So: **a 0% FPR here means "no sample in this corpus crossed the threshold". It
does not mean 0% of real users would.** The report prints sample counts next to
every rate for that reason.

**Provenance is tracked per sample and the reporter keeps the tiers apart:**

| | what it is | what it can support |
|---|---|---|
| `captured` | recorded from a real browser under real input | a claim about observed behaviour |
| `derived` | a capture with its numeric fields jittered ±15% | robustness near observed behaviour |
| `synthetic` | hand-authored from a paper or vendor writeup | regression detection only |

Headline rates are computed from `captured` + `derived` only. Synthetic samples
are measured and shown, never folded into a false-positive figure.

**The human panel's environment is partly reconstructed.** This is the harness's
sharpest limitation and it is structural: the only way to produce repeatable real
input events is to drive the browser with an automation tool, and an automated
browser announces itself — `navigator.webdriver` is true, the plugin array is
empty, `window.chrome` is missing, the viewport equals the window, WebRTC
surfaces no local candidates, WebGL falls back to SwiftShader.

Left alone, every "human" persona would be a false positive and the harness would
report a 100% FPR that says nothing about humans and everything about Playwright.
So `capture/normalize.js` restores what the same machine's ordinary Chrome
reports, and the affected samples carry `caveats: ["environment-normalized"]`,
which the report prints next to any figure derived from them.

The consequence, stated plainly: **this panel measures behavioural false
positives well and environmental ones weakly.** Trajectory, velocity variance,
tremor, cadence and timing are genuinely captured. Much of the environment is
reconstructed. A published FPR from this corpus is a claim about behavioural
signals.

**Two artifacts cannot be normalized away**, and are called out rather than
hidden:

- *Pointer-move coalescing.* Real pointer streams coalesce; CDP-injected ones do
  not. Anything driven over CDP looks synthetic to that check, so it fires on the
  human panel at ~70%. This is a property of the recorder, not of FCaptcha, and
  it cannot be fixed without input that does not come from an automation
  protocol.
- *Console consumer attached.* The recorder *is* a CDP client. For the
  `devtools-open` persona that is the condition under test and is kept; for the
  rest it is cleared post-capture, recorded as `console-attached-cleared`.

**Normalization must reproduce a measured browser, not an idealised one.** This is
the rule the panel learned the hard way. `normalize.js` used to pin the
`navigator.webdriver` descriptor non-configurable and add a `chrome.runtime`
object, on the belief that a real Chrome has both. Measured in Chrome 150, it has
neither: WebIDL defines the attribute as configurable, and `chrome.runtime` is
only exposed to pages an extension declares `externally_connectable` for.

The panel was therefore *cleaner than any real browser*, and — because the client
had checks for exactly those two properties — no human persona could trip them.
The bench reported a 0.00% false-positive rate for two signals that fire on every
genuine Chrome, and could not have reported anything else.

**Anything pinned in `normalize.js` is a signal this panel cannot see.** Pin as
little as possible, pin it to values measured from a real browser, and treat a 0%
rate for a pinned property as an artifact of the pinning rather than a result.

**The honest way to close all of this** is captures from real browsers driven by
real people. The corpus format accepts them directly — drop a `captured` sample
into `corpus/captured/` and it is measured like any other. Until those exist,
this is the floor, not the ceiling.

---

## Why the harness paces itself

Two deliberate slowdowns, both load-bearing:

**The PoW solver is throttled to browser speed.** Node's `crypto.createHash` runs
well over a million short SHA-256s per second; a browser worker using
`crypto.subtle` manages a fraction of that. The server scores solve rate and
flags anything above ~1M/s as "impossibly fast", and separately flags a
challenge-to-solution gap under 1.5s. An unthrottled harness trips both on every
sample and measures nothing but itself. `lib/pow.js` paces the solve and waits
out the challenge age, so `duration` stays true wall-clock — a fabricated
duration would be measuring the fabrication.

**Every sample gets its own client IP.** The server escalates PoW difficulty per
`pow:{siteKey}:{ip}`, so a few hundred samples from one address would spend the
run solving 16.7M-hash challenges *and* pick up rate-limit detections that the
earlier samples never saw — the measurement would drift with position in the
corpus. Samples present a distinct RFC 5737 documentation address via
`X-Forwarded-For`, which works because loopback is in the default trusted-proxy
set. Agent classes that really do arrive from datacenter ranges can say so with
`clientIp`.

---

## The gate

`--gate` fails the run on:

- **any signal over the 0.3% per-sample FP budget**, and
- **any replay error** (an incomplete run must not read as a pass).

It *warns without failing* on aggregate FPR and per-class TPR. Those are
population claims and this corpus is not a population sample; gating on them
would dress a regression check up as evidence about real users. The per-signal
budget is different in kind — it is a regression check on this fixed corpus,
which is exactly what it can support.

---

## Layout

```
bench/
  run-bench.js            replay + report + gate
  capture/
    record.js             drives Chromium, intercepts the /api/verify body
    input.js              per-persona input choreography
    normalize.js          undoes automation artifacts (documented, auditable)
  lib/
    corpus.js             sample schema, provenance rules, jitter
    pow.js                browser-paced proof-of-work client
    replay.js             per-sample client IPs, bounded concurrency
    metrics.js            per-persona FPR, per-class TPR, per-signal budgets
    report.js             terminal rendering
    rng.js                seeded PRNG — same seed, same corpus
  tools/
    compare-aggregation.js  score-composition schemes measured side by side
  corpus/captured/        committed traces
```

---

## What it found

The first runs against v1.17.0 surfaced seven defects, all since fixed. They are
listed here because "the harness paid for itself" is a claim that should also be
checkable.

1. **Users with no mouse were flagged for an unnaturally direct mouse path.** The
   client reports directness `1` when there is no path to measure, so the check
   fired on every keyboard-only, screen-reader and touch user — precisely the
   populations its neighbouring checks exempt.

2. **The touch exemption needed 3 touch events; a plain tap produces 1.** A
   mobile user who taps without scrolling first collected three agent
   detections, including "Zero mouse, touch, or keyboard events recorded" at
   confidence 0.9.

3. **Forwarding headers were scored as suspicious even from a trusted proxy** —
   a permanent bot detection on every visitor to every proxied deployment. It
   fired on 100% of the human panel *and* 100% of the agent corpus; a signal
   that fires on everyone separates nobody.

4. **Corroborating evidence made the verdict weaker.** Category scores were a
   confidence-weighted mean, so a browser reporting `navigator.webdriver = true`
   scored 0.95 alone and 0.686 once seven more automation tells were added.
   Replaced with noisy-OR (`tools/compare-aggregation.js` compares the
   candidates on identical evidence).

5. **Slow users were read as automated.** "Mouse event rate abnormally low" fired
   on the elderly and motor-slow personas, "Mouse velocity too consistent" on
   motor-slow. Slowness is what those users produce; it is also what the checks
   look for. Both now stand down when the movement independently looks like a
   hand — on this corpus every human persona clears that bar (tremor 1.00, 22–49
   direction changes, 1–4 corrections) and every agent misses it (tremor
   0.04–0.16, 0–1 changes, 0 corrections).

6. **uvicorn was resolving client IPs behind FCaptcha's back.** It enables
   `X-Forwarded-For` handling by default, rewriting `request.client` whenever the
   real peer is loopback — so the Python server evaluated the *visitor's* address
   against the trusted-proxy list instead of the proxy's. Behind a same-host
   reverse proxy every request logged an untrusted-peer warning and picked up a
   spurious detection. The same class of problem as chi's `middleware.RealIP`,
   removed from the Go server in v1.16.0, and Express's `trust proxy`, disabled
   in Node. Now `proxy_headers=False`.

7. **Pasting was treated as a bot behaviour.** "Textarea filled mostly by paste"
   fired on 100% of the `paste-by-human` persona. People paste addresses, error
   messages, snippets and one-time codes constantly; a form filled by paste alone
   is an ordinary afternoon. What distinguishes the spam bot is that pasting is
   *all* it did, so the check now also requires the absence of pointer or touch
   activity. Surfaced the moment a realistic pasting persona was added.

Measured effect on the human panel: touch 0.385 → 0.040, keyboard-only 0.206 →
0.040, screen-reader 0.190 → 0.035, elderly 0.299 → 0.097, motor-slow 0.289 →
0.088. Agent true-positive rate at the PRD's 0.8 threshold: 0% → 100% for every
captured class.

---

## Workstream C — what the corpus measured

The typing, paste and scroll personas exist to calibrate input forensics v2 on
real hardware, because the PRD is explicit that FP-Agent's published numbers are
observations rather than constants — they move with browser version and machine
load. These are this machine's:

| signal | human | scripted agent |
|---|---|---|
| inter-key interval | min 114.6ms, median 226.9ms | max 25.9ms, median 7.9ms |
| interval variance | 4549 | 8 |
| key hold (dwell) | min 41.4ms, median 82.0ms | max 25.5ms, median 7.8ms |
| scroll max step | 109px | 704px |

The distributions do not overlap, so the shipped thresholds sit in the empty
space between them rather than hugging either side. Re-derive them on your own
hardware if you fork this.

Two results worth recording because they changed the design:

- **Gesture duration does not separate scrolling.** The obvious metric —
  `scrollIntoView` produces a zero-duration gesture — measured 0.00 for *both*
  populations, because three jumps 30ms apart segment into one gesture with a
  plausible 60ms duration. Distance *per event* separates them cleanly instead:
  a wheel notch moves tens of pixels and emits an event each time; an API call
  covers the whole page in one.
- **A human paste is arithmetically identical to a fast agent.** `paste-by-human`
  measured 2 keystrokes 0.8ms apart with zero variance — exactly the shape the
  cadence floor looks for. That is why the check requires ten keystrokes, no page
  paste and no field paste before it will look at cadence at all.

### Two classes still score below the bar, and both should

- **`declared-crawler` (0.419).** A self-identifying ClaudeBot is deliberately
  low-severity: it is honest about what it is, and whether to serve it is a
  policy decision for the operator, not a block. Scoring under 0.8 is the design.
- **`source-patched` (0.234).** A patched Chromium with every JS-observable
  automation flag scrubbed, on a residential IP, whose only tell is that the
  movement is wrong. It trips nothing dispositive, so the floor cannot help, and
  the behavioural layer does not carry the case alone. **This is the real open
  problem**, and the number is here so it stays visible rather than being
  averaged into a headline. Closing it is what workstreams C, D and F are for.
