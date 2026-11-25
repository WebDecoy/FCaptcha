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

The follow-up `external-cdp-input-shape-v1` observation requires the complete
synthetic-fill, select-all, and repeated-instant-scroll conjunction. It remains
observe-only and does not alter the production score, recommendation, token,
challenge cost, or blocking policy. Partial shapes that can arise from
dictation, autofill, password managers, keyboard/screen-reader selection,
explicit paste, anchor navigation, switch input, or reduced-motion interfaces
do not produce a detection. The full conjunction still requires independent
accessibility testing before it can be considered for scoring.

Use the consent, isolation, provenance, exclusion, and teardown protocol in
[`ACCESSIBILITY_OBSERVATION.md`](ACCESSIBILITY_OBSERVATION.md) for that testing.

## Independent MacBook replication

Issue #230 was replicated on a second physical machine, a MacBook Pro
`Mac16,6` with an Apple M4 Max and 36 GB RAM, running macOS 26.6.2 on arm64.
The browser and driver ran inside fresh Linux/arm64 containers, so the captured
browser environment was Chromium 156.0.8078.79 with a new unsigned profile for
every attempt. The pinned inputs were:

- Browser Harness 0.1.13 at
  `c24e5072ee66f8499bacd663f4f4bcb089bc4492`;
- capture image `webdecoy/browser-harness-capture:0.1.13`, image ID
  `sha256:fb77195989c998f150e9e01fd1c71f5d19814ca0e21d10b4a69337e88ba0e06f`;
- FCaptcha 1.51.4 client SHA-256
  `4e1e903bb1a12b61e441e84859f18247cda3aad1cd0308c20a04e99b2431c653`;
- FCaptcha source commit
  `c3920f5801cd29e963c6dcffb5df1cdd0ff77bfa` at capture time.

The target browser and driver had a read-only source mount, scratch-only tmpfs,
an internal Docker network with no external egress, a loopback relay to the
test server, no ambient account or profile data, and explicit CPU, memory, PID,
open-file, file-size, disk, and wall-clock limits. `browser_harness_task.py` and
`run_browser_harness_capture.sh` encode the fixed choreography: enter the made-
up name `Browser test`, follow the page anchor, produce one return scroll, and
complete the mode-specific form, widget, or invisible control. Raw reports and
profiles were destroyed after reviewed import.

The retained cohort contains five form pairs plus one widget and one invisible
pair. Every agent replay had production score 0.600; the observation stayed
separate and non-gating. The released-client manual controls were all allowed
at 0.108675. Current-source replay after the false-positive repairs below also
keeps all controls below the production threshold.

| Mode | Agent/control pairs | Observation agent result | Observation control result |
|---|---:|---:|---:|
| Form | 5 | 5 detected, 0 clear, 0 unknown | 0 detected, 5 clear, 0 unknown |
| Widget | 1 | 1 detected, 0 clear, 0 unknown | 0 detected, 1 clear, 0 unknown |
| Invisible | 1 | 1 detected, 0 clear, 0 unknown | 0 detected, 1 clear, 0 unknown |

The form-only analysis screened five complete pairs against all 50 captured
human samples. The cross-mode analysis screened seven complete pairs against
the same 50-human panel. In both reports, `instantRatio > 0.5`,
`inputsWithoutKeys > 0`, and `selectAllShortcuts > 0` caught every agent with
zero human hits, complete field coverage, a consistent direction, and complete
leave-one-pair-out survival. `inputsWithoutInputType` alone is no longer a
zero-human separator because the real Chromium autofill and password-manager
workflows produce that partial shape. The versioned observation deliberately
requires the full conjunction and detected 7/7 independent agents with 0/50
captured-human matches and no unknowns.

Fixed replay of all 98 base corpus samples completed on the current Node, Go,
and Python servers with zero errors and a passing gate on each implementation.
All three reported the same observation result: 7/7 for the independent
Browser Harness group, 0/50 for captured humans, and 0/5 for the accessibility
validation group.

The expanded human evidence exposed two unrelated absence-only false positives:
Go alone scored a long pointer-only session for having no scroll or keyboard,
and all three servers scored browsers with no media devices or speech voices as
headless. Those rules were removed with regression tests. No scoring or
enforcement change for `external-cdp-input-shape-v1` is included here; any such
proposal remains a separate versioned policy change with its own review and
false-positive budget.
