# Browser-internal agent capture

This lane measures Chrome features that act inside an ordinary signed-in
browser, starting with Chrome Auto Browse (Gemini in Chrome). It attaches no
Playwright, WebDriver, CDP client, extension, or DevTools session. The operator
opens a loopback page in the browser and asks the browser-internal agent to
complete it.

The first result may be that the agent is indistinguishable from a person. That
is valid evidence. Do not add a detector unless repeated paired captures show a
separation that stays clear of the human panel.

## Safety and provenance

- Use a local FCaptcha server and the loopback recorder only. Do not probe the
  hosted demo or send capture traffic to production.
- Use a dedicated browser profile if the feature permits it. Never type account
  credentials or personal data into the capture page.
- Keep raw reports under ignored `bench/test-results/`. Inspect them before
  importing; committed corpus samples contain the scoring signals and selected
  replay headers, not tokens or the signing secret.
- Do not open DevTools during a capture. It changes CDP-adjacent observations.
- A report is `captured` evidence only when the named browser-internal feature
  completed the task. A person taking over mid-task is a failed agent capture,
  not an agent sample.
- If the feature refuses a loopback URL, record that limitation. Do not expose
  the recorder publicly merely to obtain a sample.

## Paired protocol

Use one browser version, machine, profile, network, page mode, and FCaptcha
commit for both sides of each pair:

1. Browser-internal session: the named feature completes the page without human
   clicks or typing after the capture starts.
2. Manual control: disable or stop the feature, then a person completes the same
   task using the same browser profile and hardware.

Capture at least five pairs in widget mode and five in invisible mode. Use a
fresh output directory for every attempt. Record failed or unavailable attempts
separately; never turn them into detections or silently discard them.

Start a local server exactly as described in [CAMOUFOX.md](CAMOUFOX.md), with
experimental monitoring enabled and a test secret. Then run one agent capture:

```sh
python3 bench/capture/camoufox_bench.py \
  --external-agent --modes widget --observations --timeout 600 \
  --environment-label 'Chrome <exact version>, macOS, signed-in test profile' \
  --agent-label 'Chrome Auto Browse (Gemini)' \
  --server http://127.0.0.1:18881 \
  --out bench/test-results/chrome-auto-browse-widget-0000
```

Open the printed URL in that profile. Ask the feature to enter the made-up name
`Browser test`, follow the page's “Read more” link, return to the check, and
complete it. Do not touch the page after issuing the task.

Record the paired manual control with the same mode and environment label:

```sh
python3 bench/capture/camoufox_bench.py \
  --manual --modes widget --observations --timeout 600 \
  --environment-label 'Chrome <same version>, macOS, signed-in test profile' \
  --server http://127.0.0.1:18881 \
  --out bench/test-results/chrome-manual-widget-0000
```

Repeat both commands with `--modes invisible`. Increment the output suffix for
each pair.

## Import and benchmark

After reviewing the report and confirming the agent completed the whole task,
import each browser-internal capture through the dedicated importer:

```sh
node bench/tools/import-browser-internal-capture.js \
  --report bench/test-results/chrome-auto-browse-widget-0000/report.json \
  --out bench/corpus/captured/agent-browser-internal-widget-0000.json \
  --scenario chrome-auto-browse-widget \
  --index 0 --input 'browser-internal pointer and keyboard'
```

Import the paired human report with `import-manual-capture.js`. The agent
importer rejects human, externally driven, normalized, incomplete, and unlabeled
reports. Both importers strip stale challenge state, retain replay-relevant
headers, and hash the source report.

Run the ordinary benchmark. The first real agent sample removed the former
`gap/browser-internal/0000` marker; do not reintroduce a no-data marker while
captured samples exist. Report base captures separately from correlated derived
variants.

Before proposing enforcement, compare every candidate signal against its paired
manual control and the full human panel. A useful observation is not
automatically a safe production detector.

## Current measured result

The initial Chrome 156 campaign contains five widget pairs and five invisible
pairs. All 20 captures produced valid tokens and were allowed. Agent scores
range from 0.000 to 0.030; paired human controls range from 0.000 to 0.045.
Their current behavioral and environment signals overlap, so this campaign does
not support browser-internal enforcement. Retain the samples as a regression
cohort and require new paired evidence before adding a detector or score floor.
Each imported sample retains `/api/verify` or `/api/score` as non-secret capture
metadata so benchmark replay preserves widget versus invisible server context.
