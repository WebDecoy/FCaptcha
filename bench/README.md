# FCaptcha measurement harness

A labeled corpus, a replayer, and per-signal false-positive accounting.

For separate browser measurements with Camoufox, automated Firefox controls,
and manual browser sessions, see [the browser recorder](capture/CAMOUFOX.md).
Those research outputs are kept outside the committed human corpus.
Browser-internal agents have a separate
[driver-free paired protocol](capture/BROWSER_INTERNAL.md). Results remain
capture-specific until that protocol covers multiple sessions and modes.

FCaptcha has always made claims about false positives — that keyboard-only users
are exempt, that privacy extensions are safe, that touch users are not treated as
bots — and until this existed, none of them were measured. This is the apparatus
that makes those claims checkable, including when they turn out to be wrong.

```bash
# 1. start any server
cd ../server-node && FCAPTCHA_SECRET=benchmark-test-secret-0123456789abcdef0123456789abcdef npm start

# 2. record the corpus from a real browser (one-time; commit the result)
cd ../bench && npm install && npm run install-browsers
node capture/record.js

# 3. measure
node run-bench.js                     # human FPR, agent TPR, per-signal budgets
node run-bench.js --gate              # non-zero exit when a signal is over budget
node run-bench.js --json out.json     # machine-readable
node run-bench.js --hosted-smoke --server https://fcaptcha.example.com --site-key demo
                                      # bounded production deployment check
node tools/analyze-paired-observations.js
                                      # rank paired agent/control differences
node tools/compare-server-parity.js \
  --server node=http://localhost:3001 \
  --server go=http://localhost:3002 \
  --server python=http://localhost:3003 \
  --strict
                                      # require exact base-corpus detector parity

On macOS, run the server and the harness under `caffeinate -i -s` for anything
unattended. Maintenance Sleep pauses both processes together; a challenge
fetched just before a pause is past its five-minute lifetime when the solve
resumes, and the gate reports it as `PoW verification failed: challenge_expired`
on whichever personas were in flight.
```

---

## What the numbers do and do not establish

This is the part to read before quoting anything from the output.

**The corpus is captured, not sampled.** Many traces come from real browsers, so
the signal payloads are exactly what the client produces — including fields
nobody remembered were there. That does not by itself make the label real-human
evidence. Scripted accessibility and behaviour personas are structural
stand-ins; manual sessions and paired human controls are observed behaviour.
Neither is a sample of the human population, and repeated sessions from one
operator do not establish how often real users get flagged.

So: **a 0% FPR here means "no sample in this corpus crossed the threshold". It
does not mean 0% of real users would.** The report prints sample counts next to
every rate for that reason.

**Three independent fields describe every sample:**

| field | examples | what it answers |
|---|---|---|
| `provenance` | `captured`, `derived`, `self-reported`, `synthetic` | how the payload came into existence |
| `captureMethod` | `manual-browser`, `browser-internal`, `external-cdp`, `automated-browser` | how the browser or payload was actuated |
| `labelEvidence` | `verified-human`, `paired-human-control`, `simulated-human`, `observed-agent` | why the human/agent label is believed |

Only captured `verified-human` and `paired-human-control` rows support an
observed false-positive result. Simulated and self-reported human fixtures are
replayed and shown but never folded into that result or its gate. Derived rows
are grouped under their source capture: they report whether any jittered child
crossed a boundary, but never increase the number of people or capture families.
Changing `--derive` therefore cannot dilute or amplify a gate.

The configured 0.3% per-signal budget is a product target, not a population
estimate from this corpus. With fewer than 334 independent human observations,
one observed hit already exceeds it. A passing gate means no non-exempt signal
crossed the target in the observed capture families; it does not establish a
population FPR below 0.3%.

### Cross-server detector parity

The shared conformance suite protects token, proof-of-work, and wire-contract
security invariants. The benchmark additionally compares detector verdicts
across the Go, Node, and Python production servers. It replays base samples only
with one isolated site key per sample. CI runs the comparison with `--strict`,
so recommendation, experimental blocking decision, observation statuses,
normalized detections, category scores, full experimental details, and exact
scores must all match before a release can pass. The non-strict mode remains
available for local diagnosis when a change intentionally starts as an
outcome-only comparison. Floating-point output is normalized to eight decimal
places.

Derived variants run only in the primary regression job because they add
robustness coverage, not another server contract.

### Paired observation analysis

`node tools/analyze-paired-observations.js` compares the captured
`browser-internal` cohort with its `browser-internal-control` partners. Pairing
uses capture mode plus the numeric sample index, so missing or duplicated
partners fail loudly instead of being silently compared with the wrong run.

The analyzer flattens scalar signal fields and summarizes numeric arrays by
count, mean, minimum, maximum and standard deviation. It excludes operational
metadata, identifiers, hashes, tokens and timestamps. A numeric candidate is
ranked against every captured human sample using a strict zero-false-positive
threshold. Categorical candidates must repeat; unique per-request values cannot
be unioned into a fake separator. A **promotion candidate** must catch every
paired agent, keep one direction in every pair, produce zero captured-human
false positives and survive leave-one-pair-out evaluation. Even then it is a
research candidate, not authorization to enforce: an independent environment
must reproduce it first.

Promotion also requires complete observation coverage: the candidate field
must exist in every pair and every captured-human sample. The report prints the
human observation count for each feature. A new telemetry field can be studied
with sparse historical coverage, but cannot be promoted until the human panel
has been recaptured with that field.

Write the complete machine-readable result when reviewing or attaching a run:

```bash
node tools/analyze-paired-observations.js \
  --json test-results/paired-observations.json \
  --top 20
```

Use `--mode form` (or another capture-mode slug) to evaluate telemetry that is
available only in one cohort. The zero-false-positive screen still uses every
captured human sample that contains the candidate field. Always run the default
all-mode analysis as the separate generalization check; a mode-specific result
does not establish cross-mode coverage.

The same analyzer supports separately labeled external-driver cohorts. For the
real-Chrome CDP protocol, use `--agent-group browser-harness-cdp-agent` and
`--control-group browser-harness-cdp-control`; see
[`capture/EXTERNAL_CDP.md`](capture/EXTERNAL_CDP.md). Never combine that cohort
with `browser-internal`: attaching over CDP is a materially different actuation
path and security boundary.

Derived and self-reported samples never participate. The report also prints the
largest distribution shifts separately, because an interesting paired change
can still overlap humans and be unsafe as a detector.

**The simulated human panel's environment is partly reconstructed.** This is a
structural limitation of those regression fixtures: repeatable scripted input
uses an automation tool, and an automated browser announces itself —
`navigator.webdriver` is true, the plugin array is empty, `window.chrome` is
missing, the viewport equals the window, WebRTC surfaces no local candidates,
and WebGL falls back to SwiftShader.

Left alone, every simulated "human" persona would report automation artifacts
that say nothing about legitimate users and everything about Playwright. So
`capture/normalize.js` restores what the same machine's ordinary Chrome reports,
and the affected samples carry `caveats: ["environment-normalized"]`. These rows
remain regression coverage under `simulated-human`; they no longer enter the
observed-human denominator.

The consequence, stated plainly: **the simulated panel is good at finding
behavioural regressions and weak as evidence about real people.** Trajectory,
velocity variance, tremor, cadence and timing are genuinely produced by the
scripted choreography. Much of the environment is reconstructed. Only manual
and paired-control rows enter the observed result.

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
into `corpus/captured/` and it is measured like any other. The initial manual
panel covers one macOS machine; more people, hardware and operating systems are
still needed. This is the floor, not the ceiling.

The manual recorder launches no browser automation. After completing a capture,
import its request into the corpus with explicit browser and input labels:

```bash
python3 capture/camoufox_bench.py --manual --modes widget \
  --environment-label 'Chrome 156, macOS, default settings' \
  --expected-client-version 1.52.0 \
  --out test-results/chrome-trackpad

node tools/import-manual-capture.js \
  --report test-results/chrome-trackpad/report.json \
  --out corpus/captured/human-chrome-macos-trackpad.json \
  --group real-trackpad --scenario chrome-macos-trackpad \
  --input 'built-in trackpad and keyboard' \
  --expected-client-version 1.52.0
```

The importer refuses automated or normalized reports, strips the consumed
challenge nonce, retains only replay-relevant request headers, records the
served client version and hash plus a hash of the source report, and will not
overwrite an existing corpus file or sample id. With an expected version it
also requires the release's versioned neutral input telemetry.

### Checking a hosted deployment

Do not point the normal benchmark at a shared production server. Derived samples
are useful against a fresh local instance, but hundreds of requests from one
public egress address correctly trigger production rate limits. A reverse proxy
may also replace the documentation-range addresses the harness supplies, so
per-source signals then describe the replayer's shared egress rather than the
labeled personas.

Use the bounded hosted smoke mode instead:

```bash
node run-bench.js \
  --hosted-smoke \
  --server https://fcaptcha.example.com \
  --site-key demo-site-key \
  --origin https://demo.example.com
```

This mode requires an explicit HTTPS server and site key, fixes derivation at
zero and concurrency at one, and selects four base captures: one human and one
agent payload for each of `/api/verify` and `/api/score`. It reports only whether
the endpoint contracts completed. Scores, recommendations, signals, FPR, TPR,
budgets, and gates are deliberately omitted because hosted proxy topology makes
those values non-comparable. Any replay error returns exit status 2.

Pass `--origin` when the site key is hostname-restricted. The harness sends that
exact HTTPS origin on the challenge and scoring requests, matching a browser on
the deployed demo. Origins with a path, query, fragment, credentials, or a
non-HTTPS scheme are rejected. Omit the option only for deployments that
intentionally allow native or server-side clients without an Origin header.

`--hosted-smoke` refuses `--gate`, `--json`, research imports, and workload
overrides. Run the normal `--gate` command against a fresh local server for
release evidence.

### Replaying consented hosted-demo research

The hosted demo exposes an authenticated NDJSON export of explicitly consented
research traces. Replay the current export without putting the bearer token in
shell history:

```bash
cd bench
FCAPTCHA_CAPTURE_EXPORT_TOKEN="$(security find-generic-password \
  -w -s fcaptcha-capture-export)" \
  node run-bench.js --research-export
```

For an export already downloaded through an approved secret-handling workflow:

```bash
node run-bench.js --research-input /path/to/fcaptcha-captures.ndjson
```

To stream an export directly into the benchmark without writing it to disk:

```bash
approved-export-command | node run-bench.js --research-stdin
```

Standard input is subject to the same 64 MiB limit and strict schema validation
as file and HTTPS imports.

For a shared hosted server, add `--research-only`. This replays only the
ephemeral research records, isolates every sample under its own temporary site
key, prints a dedicated exploratory report (including versioned experimental
observations), and refuses `--gate` and `--json`:

```bash
approved-export-command | node run-bench.js --research-stdin \
  --research-only --server https://fcaptcha.example.com
```

The importer accepts only schema-v1 self-reported human records, caps input at
64 MiB and 5,000 records, refuses redirects and non-HTTPS export URLs, and never
accepts the bearer token as a command-line argument. Use `--research-url` for
another HTTPS FCaptcha deployment. The importer independently removes
record IDs, rotating subject IDs, capture/expiry timestamps, stored verdicts,
screen geometry, user agents, challenge/session/site identifiers, and field
names. The in-memory sample carries browser, OS, input method, and endpoint only, and uses
`self-reported` provenance so these traces can reveal coverage gaps without
being mistaken for trusted ground truth. Imported samples exist only in process
memory: raw samples are never written to `corpus/` or the JSON report, or
expanded into derived samples. This preserves the demo's seven-day retention
boundary instead of turning short-lived consent into a permanent repository
artifact.

### What the first manual sessions changed

Four trackpad-and-keyboard sessions were recorded without browser automation:

| browser | sessions | coalesced max | direction changes | overshoots | captured score |
|---|---:|---:|---:|---:|---:|
| Chrome 156 | 2 | 2, 2 | 44, 55 | 0, 0 | 0.029, 0.029 |
| Safari 26.6 | 1 | 3 | 33 | 0 | 0.038 |
| Firefox 158 | 1 | 2 | 49 | 0 | 0.000 |

Every real session coalesced at least two pointer samples; all five
`stealth-humanized` CDP captures maxed out at one. That supports the coalescing
signal on these observed configurations, but four sessions from one machine are
not enough to claim a population false-positive rate or remove the recorder
artifact exemption from the scripted panel.

The benchmark prints those observe-only candidates in a separate
`Experimental observations` panel. It uses base samples only, keeps trusted and
self-reported humans separate, excludes unknown/unsupported observations from
the displayed detection rate, and never feeds the result into production
scores, signal budgets, or the release gate. This is the measurement path for
deciding whether an experimental candidate has enough real hardware coverage
to graduate; a high agent rate by itself is not sufficient. Candidates that
produce a legitimate-user report are removed rather than retained as noisy
observations.

The sessions also disproved two behavioural assumptions. All four natural
trackpad paths reached the checkbox without an overshoot, and Safari produced a
0.987-direct approach while still carrying saturated tremor and 33 direction
changes. Overshoot and directness now stand down when independent movement
markers already indicate a human hand. With one derived variant per capture,
the corrected corpus reports 0/36 human samples flagged and no signal-budget
failure.

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

**Every sample gets its own source network.** The server keys rate limits and
accumulated suspicion per site key and challenge-network identity (/24 for IPv4,
/56 for IPv6), so a few hundred samples from one network would pick up
escalations the earlier samples never saw — the measurement would drift with
position in the corpus. Samples present distinct RFC 3849 documentation /56s via
`X-Forwarded-For`, which works because loopback is in the default trusted-proxy
set. Agent classes that really do arrive from datacenter ranges can say so with
`clientIp`.

Those addresses are assigned **by position**, not by hashing the sample id, and
that distinction was learned the hard way. Hashing put 180 samples into a
508-address space; by the birthday bound they collided constantly — 25 shared
addresses, 24 of them putting an agent and a human on the same IP. The corpus was
manufacturing shared egress its labels never claimed, and nothing noticed for as
long as no signal was keyed by source. The first one that was, read 12.7% FPR on
a panel whose real answer was zero. `lib/replay.test.js` now holds the pool
collision-free and throws rather than wrapping if the corpus outgrows it.

**Each run namespaces its own server-side state.** The same per-source keying
means a second run against a long-lived server measures the residue of the first.
Measured: one signal fired on 2/75 agents against a fresh server and 74/75
against one already benchmarked. Each run generates a unique site key, so runs
are independent without the harness having to own the server's lifecycle.

**The pacer does not honour the server's `minAgeMs`.** The server tells clients
how long to hold a solved challenge and the shipped client obeys; the harness
deliberately waits a fixed interval just past the universal baseline instead. A
replayer that honoured the delay would satisfy the timing gate by construction,
and the panel could never observe it firing on a human — the same trap as pinning
a property during normalization and then reporting that nothing disagrees with
it. Leaving the pacer fixed means any escalation applied to a human persona shows
up as a signal over budget, which is what it should do.

---

## The gate

`--gate` fails the run on:

- **any signal over the 0.3% per-sample FP budget**, and
- **any replay error** (an incomplete run must not read as a pass), and
- **a fixed-corpus agent regression** below the class floor recorded in
  `agent-regression-floors.json`.

It *warns without failing* on aggregate FPR and per-class TPR. Those are
population claims and this corpus is not a population sample; gating on them
would dress a regression check up as evidence about real users. The per-signal
budget is different in kind — it is a regression check on this fixed corpus,
which is exactly what it can support. The agent regression floors work the same
way: they preserve detection already demonstrated by this corpus without
pretending that the observed rate generalizes to a population. Classes with a
known gap have no regression floor and remain conspicuous warnings.

---

## Layout

```
bench/
  run-bench.js            replay + report + gate
  agent-regression-floors.json
                          minimum rates for classes this corpus already catches
  capture/
    record.js             drives Chromium, intercepts the /api/verify body
    input.js              per-persona input choreography
    normalize.js          undoes automation artifacts (documented, auditable)
    BROWSER_INTERNAL.md   driver-free paired browser-internal capture protocol
    EXTERNAL_CDP.md       isolated external real-Chrome CDP capture protocol
  lib/
    corpus.js             sample schema, provenance rules, jitter
    paired-analysis.js    paired flattening, screening, leave-one-out checks
    pow.js                browser-paced proof-of-work client
    replay.js             per-sample client IPs, bounded concurrency
    metrics.js            per-persona FPR, per-class TPR, per-signal budgets
    report.js             terminal rendering
    rng.js                seeded PRNG — same seed, same corpus
  tools/
    analyze-paired-observations.js
                            ranks repeatable agent/control differences
    compare-aggregation.js  score-composition schemes measured side by side
    import-browser-internal-capture.js
                            validates and imports driver-free agent captures
    import-external-driver-capture.js
                            validates pinned external-driver captures
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

### Remaining classes and the retired v1.48.0 stealth-CDP result

- **`declared-crawler` (0.600 on the v1.48.0 corpus).** A self-identifying ClaudeBot is deliberately
  low-severity: it is honest about what it is, and whether to serve it is a
  policy decision for the operator, not a block. Scoring under 0.8 is the design.
- **`source-patched` (0.600 on the v1.48.0 corpus).** A patched Chromium with every JS-observable
  automation flag scrubbed, on a residential IP, whose only tell is that the
  movement is wrong. It trips nothing dispositive, so the floor cannot help, and
  the behavioural layer does not carry the case alone. **This is the real open
  problem**, and the number is here so it stays visible rather than being
  averaged into a headline. Closing it is what workstreams C, D and F are for.
- **`stealth-cdp-agent` is a declared gap again.** The v1.48.0 rule combined
  30+ pointer samples, a low movement-delta ratio, an attached console consumer,
  and a first interaction under 250ms. Issue #212 supplied a real Edge verdict
  showing that ordinary continuous mouse movement during page load can satisfy
  the complete conjunction. The production floor and the associated
  `pointer-movement-never-zero` observation are therefore removed. The raw
  bounded measurements remain in captures for research, but they produce no
  detection or observation until paired evidence establishes a safe separator.
- **`browser-internal` has ten measured pairs, not a detector.** Five driver-free
  Chrome Auto Browse widget captures scored 0.000–0.030; their same-browser,
  same-profile manual controls scored 0.000–0.045. Five invisible captures
  scored 0.000–0.016; all five paired controls scored 0.000. Every capture
  produced a valid token, was allowed, and stayed below the human threshold.
  The agent and control distributions overlap on the current behavioral and
  environment features. One agent run scrolled much more than its control, but
  the pattern did not repeat and heavy scrolling is ordinary human behavior.
  This cohort establishes that the class exists in the corpus and documents a
  current detection limit. It is not evidence of a population rate or a safe
  separating signal, so no browser-internal regression floor or production
  enforcement is set from it.

  Chromium's actor implementation supplies a narrower measurement target for
  the next paired capture: its default click path emits a pointer move to the
  resolved target, waits 5ms, then dispatches mousedown; incremental typing also
  uses fixed key-down and key-up delays. The client therefore reports bounded,
  content-free `clickPrelude` and `keyTiming` summaries under `inputForensics`.
  These fields contain counts, means, variances and ratios only—no coordinates,
  key identities or field values. They remain neutral telemetry: no detector or
  observation consumes them until a new same-browser agent/control cohort shows
  a repeated separation and independent human coverage supports a threshold.

  Expanding the cohort also exposed two false-positive paths. The replayer had
  treated every corpus entry as `/api/verify`; it now retains and replays the
  reviewed capture endpoint so invisible samples stay on `/api/score`. A real
  trackpad control also clicked 1.62px from target center, inside the former
  standalone “unnaturally accurate” threshold. That weak click-precision signal
  was removed from all three servers because precise human clicks require no
  automation and the signal had no independent corroboration.

  The first paired control also invalidated the standalone “First interaction too
  soon after page load” heuristic: the person moved at 30.7ms while Auto Browse
  first interacted at 244.7ms. That signal separated in the wrong direction and
  was removed from all three servers. Contextual form timing checks and the
  retired stealth-CDP conjunction no longer uses that timing signal.
