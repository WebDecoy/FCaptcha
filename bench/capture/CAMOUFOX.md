# Browser measurement

This recorder measures Camoufox and automated Firefox controls against a local
FCaptcha server. It captures the real client submission, production verdict,
experimental observations, and backend token validation. It does not change
detectors or normalize browser signals. Detailed findings stay in ignored
`docs/` and `bench/test-results/`.

Install the pinned Python dependencies in a separate environment:

```sh
uv venv bench/.venv --python 3.12
uv pip install --python bench/.venv/bin/python -r bench/capture/requirements-camoufox.txt
bench/.venv/bin/python -m camoufox fetch official/stable/152.0.4-beta.30
bench/.venv/bin/python -m playwright install firefox
```

Start a local FCaptcha server with experimental monitoring enabled (leave
`FCAPTCHA_EXPERIMENTAL_BLOCKING` unset), its default trusted loopback proxy,
and no site-key or hostname allowlist. Export its test signing/verification
secret in the recorder's shell as `FCAPTCHA_SECRET` or `FCAPTCHA_VERIFY_SECRET`.

```sh
bench/.venv/bin/python bench/capture/camoufox_bench.py \
  --server http://127.0.0.1:18881 --repeats 3 \
  --out bench/test-results/browser-measurement
```

The default matrix exercises headed and headless browsers on the widget and
invisible paths. Camoufox runs with humanization off and on; Firefox runs with
default preferences and `privacy.resistFingerprinting`. Each sample launches a
fresh browser. `--display headless`, `--browsers camoufox`, and `--modes invisible`
can narrow the matrix. Headed runs require a display.

The recorder supplies a local page through a loopback proxy. Each sample has
its own site key and documentation-range address to isolate rate limits,
fingerprint history, and challenge costs. This excludes transport, reputation,
and sustained-abuse detection from the measurement. The browser's actual
signal body reaches the server unchanged. Issued tokens are validated and
removed from saved responses; the secret never enters the page or report.

Reports include browser/package versions, the served client hash, source commit,
input seed, raw signals, and per-configuration results. Camoufox generates
fingerprints per launch; the report records those observed signals, not a claim
that future launches will have identical fingerprints. Fresh output directories
prevent accidentally overwriting a previous report. Errors are counted separately
from detection outcomes, and partial results are saved after every attempt.
HTTP request status and page errors are retained to diagnose incomplete runs.
Use `--verdict-log /path/to/server.log` with `FCAPTCHA_LOG_VERDICTS=true` on
the server to join per-sample diagnostics: invisible responses do not include
the full production detection list. Logs are joined by the unique sample site
key, not by request order. `additionalExperimentalBlocks` excludes requests
already over the production score threshold.

To compare the captured signals across local server implementations:

```sh
node bench/capture/replay_browser.js \
  bench/test-results/browser-measurement/report.json \
  bench/test-results/browser-replay.json \
  node=http://127.0.0.1:18881 go=http://127.0.0.1:18882 python=http://127.0.0.1:18883
```

Replay preserves captured signals except for the required fresh challenge
nonce. It solves new proofs and records fresh proof timings; these are scorer
comparisons, not additional live-browser runs. It does not apply the main
corpus replayer's fingerprint normalization.

**Automated Firefox controls are labeled as agents, not humans.** They cannot
measure a human false-positive rate. To record one actual manual session without
launching an automation driver:

```sh
python3 bench/capture/camoufox_bench.py --manual --modes invisible \
  --environment-label 'Firefox, default settings' --timeout 600 \
  --out bench/test-results/firefox-manual
```

Open the printed local URL in your own browser. Use made-up form data. Repeat
with fresh output directories for other browsers, privacy settings, and input
methods. The environment description is operator-declared; a few manual sessions
still do not establish a population false-positive rate.

## Optional research observations

Add `--observations` to automated or manual runs to collect a separate set of
browser observations **after the scoring response**. The probes run as page
scripts, outside the automation driver's isolated world, and upload only to
the local recorder. They do not enter FCaptcha's signals, score, tokens, or
experimental enforcement policy. The production client does not load them.

Use `--control-settings default privacy reduced-motion privacy-reduced-motion`
to expand automated Firefox controls. Reports include the requested settings
and observed browser responses; a privacy setting can mask another preference.
Optional `--camoufox-config /path/to/config.json` labels a separate configuration
experiment. The configuration is copied per launch so library-generated values
cannot leak between repetitions. Configuration experiments must be reported
separately from default-browser measurements.

An unmodified Firefox executable can also provide controls without attaching
Playwright. This checks browser APIs only, using fresh headless profiles; it
does not measure human behavior or token acceptance:

```sh
python3 bench/capture/native_browser_probe.py --browser /path/to/firefox \
  --out bench/test-results/native-control
```

Summarize the separate observations with:

```sh
python3 bench/capture/summarize_observations.py \
  bench/test-results/browser-measurement/report.json \
  bench/test-results/native-control/report.json \
  --out bench/test-results/observation-summary.json
```

The summary counts observations, not detected bots. Unsupported APIs, missing
contexts, and timeouts are unknowns and are excluded from valid observation
counts. Raw data and detailed conclusions remain in ignored research artifacts.
