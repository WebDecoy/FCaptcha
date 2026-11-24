# External real-Chrome CDP capture

This lane measures an external automation tool controlling a real Chrome
instance over the Chrome DevTools Protocol (CDP). It is separate from both the
automated Camoufox/Playwright controls and the `browser-internal` cohort.

The first target is
[`browser-use/browser-harness`](https://github.com/browser-use/browser-harness)
release `v0.1.13`, commit
`c24e5072ee66f8499bacd663f4f4bcb089bc4492`. Record a different release only as
a new, explicitly pinned cohort.

## Isolation boundary

Browser Harness attaches to an entire Chrome instance, not just the benchmark
tab. Never attach it to an everyday or signed-in browser. A valid run requires:

- a new ephemeral Chrome user-data directory containing no accounts, cookies,
  saved credentials, extensions, history, or unrelated tabs;
- Chrome's CDP listener bound to loopback only;
- the FCaptcha recorder and local FCaptcha server reachable only on loopback;
- external network denied for both the dedicated Chrome and driver processes;
- an empty allowlisted environment, read-only source/toolchain inputs,
  scratch-only writes, and bounded process, memory, and wall-clock resources;
- dependencies installed and pinned before target execution, never fetched by
  the target during a capture.

Keep the dedicated profile outside the repository and destroy it after the
raw report has been reviewed and imported. Failed, unavailable, interrupted,
or operator-taken-over attempts are quarantined outside the corpus and are not
detections.

## Recorder protocol

Start the local FCaptcha server exactly as described in
[CAMOUFOX.md](CAMOUFOX.md), with experimental monitoring enabled and a test-only
secret. Start one form capture:

```sh
python3 bench/capture/camoufox_bench.py \
  --external-driver --modes form --observations --timeout 600 \
  --environment-label 'Chrome <exact version>, macOS, ephemeral unsigned profile' \
  --driver-name browser-harness \
  --driver-version 0.1.13 \
  --driver-commit c24e5072ee66f8499bacd663f4f4bcb089bc4492 \
  --expected-client-version 1.51.4 \
  --server http://127.0.0.1:18881 \
  --out bench/test-results/browser-harness-form-0000
```

The recorder prints a fresh loopback URL. Configure the pinned Browser Harness
process to use only the dedicated Chrome CDP endpoint, then direct it to that
URL and ask it to enter the made-up name `Browser test`, follow “Read more”,
return, and submit the benchmark. Do not touch the page after starting the
task. After a scoring request, attest `completed` only if the driver finished
without manual takeover.

Record the paired manual control in the same dedicated Chrome version, profile
configuration, machine, mode, FCaptcha release, and network boundary:

```sh
python3 bench/capture/camoufox_bench.py \
  --manual --modes form --observations --timeout 600 \
  --environment-label 'Chrome <same version>, macOS, ephemeral unsigned profile' \
  --expected-client-version 1.51.4 \
  --server http://127.0.0.1:18881 \
  --out bench/test-results/browser-harness-manual-form-0000
```

Collect at least five complete agent/control pairs. Use a fresh output
directory for every attempt and increment the suffix for both sides together.

## Import

Review the raw report first. It must contain one valid scoring submission, an
exact released-client version and SHA-256, the pinned driver provenance, and a
`completed` operator outcome. It must not contain a token or signing secret.

```sh
node bench/tools/import-external-driver-capture.js \
  --report bench/test-results/browser-harness-form-0000/report.json \
  --out bench/corpus/captured/agent-browser-harness-cdp-form-0000.json \
  --scenario browser-harness-real-chrome-form \
  --index 0 --input 'Browser Harness over loopback CDP' \
  --expected-client-version 1.51.4 \
  --expected-driver-name browser-harness \
  --expected-driver-version 0.1.13 \
  --expected-driver-commit c24e5072ee66f8499bacd663f4f4bcb089bc4492
```

Import each manual report with `import-manual-capture.js`, using group
`browser-harness-cdp-control`, the same numeric index, and the same expected FCaptcha
client version.

## Analysis and promotion

Run the form-specific paired analysis:

```sh
node bench/tools/analyze-paired-observations.js \
  --agent-group browser-harness-cdp-agent \
  --control-group browser-harness-cdp-control \
  --mode form \
  --json test-results/browser-harness-form-pairs.json
```

Then repeat without `--mode` after widget and invisible captures exist. Source
review suggests same-coordinate click press/release, immediate key sequences or
`Input.insertText`, single-event wheel scrolling, and synthetic form events as
measurement hypotheses. They are not detections until paired captures support
them.

A candidate must catch every valid pair, preserve one direction, survive
leave-one-pair-out analysis, and be present for every pair and every captured
human used by the analysis. Independent machine/profile replication is still
required before a separate production scoring change can be proposed.

## Initial Mac mini form cohort

The first form cohort was captured on the Mac mini in five fresh Linux/arm64
containers using Chromium 156.0.8078.79, Browser Harness 0.1.13, and FCaptcha
1.51.4. Every Browser Harness submission scored 0.600 and received a block
recommendation. All five same-configuration manual controls scored 0.108675
and were allowed.

The form-only paired analysis screened all five pairs against 38 captured human
samples. Four research candidates caught 5/5 agents, produced 0/38 captured-
human hits, and survived all five leave-one-pair-out checks:

- `behavioral.scrollMorphology.instantRatio > 0.5`;
- `formAnalysis.typing.inputsWithoutInputType > 0`;
- `formAnalysis.typing.inputsWithoutKeys > 0`;
- `formAnalysis.typing.selectAllShortcuts > 0`.

These results describe one machine, browser build, driver release, task, and
input method. They do not authorize enforcement. Independent machine/profile
replication and a separate reviewed scoring change with false-positive analysis
remain required. Widget and invisible follow-up are also still unmeasured.
