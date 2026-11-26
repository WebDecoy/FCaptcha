# Accessibility observation validation

This protocol collects real, consented human workflows to test the
`external-cdp-input-shape-v1` observation. The observation stays diagnostic:
these captures do not authorize scoring, blocking, recommendation, token,
challenge-cost, or state changes.

Automated accessibility emulation is useful for functional testing, but it is
not human evidence and must not be imported into these cohorts.

## Before each capture

The operator must understand what is recorded and explicitly consent. Use a
fresh browser profile or guest context with no signed-in account, unrelated
tabs, browsing history, saved addresses, personal credentials, or production
data. Use fictional values made only for this test. For a password-manager run,
create a fresh local test vault or profile containing only the fictional test
credential.

Record the exact:

- browser version, operating-system version, profile type, and installed test
  extension version in `--environment-label`;
- workflow id, assistive/input tool name and version, relevant settings, and
  recorder-only form fixture in the structured capture arguments;
- FCaptcha client version with `--expected-client-version`.

Do not open DevTools, attach CDP, use a macro, normalize the environment, or
help the operator with a pointer unless that input is part of the named
workflow. A timeout, refusal, accidental takeover, or mixed-input run is a
failed capture, not a clear observation. Start again in a fresh output
directory and retain the failure only as a diagnostic.

## Capture command

Start the loopback FCaptcha deployment as described in
[`EXTERNAL_CDP.md`](EXTERNAL_CDP.md), then run one recorder per workflow. This
example uses the basic fixture; replace the labels and settings with exact local
values rather than copying them blindly.

```bash
python3 bench/capture/camoufox_bench.py \
  --accessibility-manual --modes form --timeout 600 \
  --server http://127.0.0.1:18881 \
  --environment-label 'Chrome <version>, macOS <version>, fresh unsigned test profile' \
  --manual-workflow screen-reader-keyboard-selection \
  --input-tool-name 'VoiceOver' \
  --input-tool-version 'macOS <version> built-in' \
  --input-tool-settings 'state the exact navigation and selection settings' \
  --form-fixture basic \
  --consent-confirmed --isolated-test-context \
  --expected-client-version 1.52.0 \
  --out bench/test-results/a11y-screen-reader-keyboard-0000
```

The two confirmation flags are provenance declarations, not boilerplate. Do
not pass them unless consent and isolation are true for that run.

Use these recorder-only fixtures:

| Workflow | Suggested id | Fixture | Completion rule |
|---|---|---|---|
| Screen reader plus keyboard | `screen-reader-keyboard-selection` | `basic` | Locate, select, edit, navigate, scroll, and submit with the screen reader and keyboard. |
| Dictation or voice control | `voice-control-form-entry` | `basic` | Enter the fictional value and operate the page with the declared voice workflow. |
| Switch or keyboard navigation | `switch-keyboard-navigation` | `basic` | Complete the page with the declared switch/full-keyboard-access path. |
| Browser autofill | `browser-autofill-form-entry` | `autofill` | Fill all fields from a fictional address saved only in the fresh profile. |
| Password manager | `password-manager-form-entry` | `credentials` | Fill the fictional username/password from the isolated test vault. |
| Explicit paste | `explicit-paste-form-entry` | `basic` | Paste a fictional value using the declared keyboard/menu workflow. |
| Reduced-motion anchor navigation | `reduced-motion-anchor-navigation` | `basic` | Enable the OS/browser reduced-motion setting, use the page anchor in both directions, then submit. |

Do not combine workflows. Separate captures make a match attributable and make
unavailable tools reportable as coverage gaps instead of ambiguous evidence.

## Import and review

The importer requires the workflow id to match the structured raw report. It
copies only replay-relevant headers and signals, removes consumed challenge
state, and preserves a hash of the source report.

```bash
node bench/tools/import-manual-capture.js \
  --report bench/test-results/a11y-screen-reader-keyboard-0000/report.json \
  --out bench/corpus/captured/human-a11y-screen-reader-keyboard-0000.json \
  --group accessibility-screen-reader \
  --scenario chrome-macos-screen-reader-keyboard \
  --input 'VoiceOver and keyboard only' \
  --expected-workflow screen-reader-keyboard-selection \
  --expected-client-version 1.52.0
```

Before committing an imported sample, inspect both files and verify:

1. the raw report contains exactly one `human` sample, `normalization` is
   `none`, the tool/workflow declarations are correct, and no token remains;
2. the corpus sample contains no field values, credentials, account data,
   unrelated URLs, or unrelated profile metadata;
3. the response reports `external-cdp-input-shape-v1` as `detected`, `clear`, or
   `unknown`, separately from the production score and recommendation;
4. fixed replay completes without an error on Node, Go, and Python.

Never turn `unknown` into `clear`. If any real human workflow is detected, keep
the policy observe-only and open a feature/threshold redesign issue before any
further promotion discussion.

## Teardown and gaps

After each workflow, close the test browser, delete the temporary browser
profile or guest data, delete the fictional address or test vault, clear the
clipboard, disable any accessibility setting enabled only for the run, and
stop the loopback recorder/server. Keep the minimal reviewed report and corpus
sample; do not retain screenshots, audio, dictation transcripts, browser
profiles, or vault files.

List unavailable operating-system/tool combinations explicitly in the results
report. Do not synthesize, automate, or relabel a substitute as human evidence.

## MacBook validation results

Issue #231 retained five consented real-operator captures in fresh Chromium
156.0.8078.79 Linux/arm64 profiles on a MacBook Pro M4 Max. Each used only
fictional test data; raw reports, clipboards, local address/credential stores,
and complete browser profiles were destroyed after reviewed import. No retained
sample contains a token, secret, field value, credential, unrelated URL, or
unrelated profile metadata.

| Workflow | Measured evidence | Released-client production result | Observation replay |
|---|---|---|---|
| Explicit paste | One Control-V paste event and one paste input | 0.124675, allow | clear |
| Keyboard navigation | 119 key events, zero pointer points, zero touch events | 0.108675, allow | clear |
| Reduced-motion anchor navigation | Submitted signal and research probe both reported reduced motion | 0.108675, allow | clear |
| Chromium address autofill | Four browser-managed inputs without ordinary input types | 0.108675, allow | clear |
| Chromium password manager | Two browser-managed credential inputs; no values retained | 0.108675, allow | clear |

The partial overlaps are intentional evidence for the conjunction boundary.
Autofill and password-manager fills produced `inputsWithoutInputType`, explicit
paste produced paste telemetry, keyboard navigation produced a long gradual
scroll, and ordinary/reduced-motion anchor navigation reached an instant-scroll
ratio of 0.5. None also produced the synthetic fill, select-all, and repeated-
instant-scroll requirements together.

Current-source fixed replay across Node, Go, and Python used all 98 base corpus
samples. Every server completed with zero errors and a passing gate. For
`external-cdp-input-shape-v1`, the complete 50-human panel reported 0 detected,
50 clear, and 0 unknown; this accessibility group reported 0 detected, 5 clear,
and 0 unknown. The independent Browser Harness group reported 7 detected,
0 clear, and 0 unknown. Production scoring and the observation remained
separate throughout.

The isolated Linux/noVNC environment did not contain a screen reader, speech
input/voice-control stack, or physical switch interface. Host VoiceOver or
Voice Control cannot access the remote Chromium accessibility tree through the
noVNC canvas; using them would measure translated VNC keyboard events rather
than the named assistive workflow. Those three combinations remain explicit
coverage gaps. They were not synthesized or relabeled as human evidence.

No accessibility workflow matched the observation, so no redesign issue was
opened. The policy remains observe-only, and this work contains no scoring or
enforcement change.
