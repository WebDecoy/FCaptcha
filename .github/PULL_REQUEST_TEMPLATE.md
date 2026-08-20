## What and why

<!-- What changes, and the reasoning. Long is fine — this codebase documents why. -->

## Checklist

- [ ] Detection changes are applied to **all three** servers (Go, Python, Node), or
      this does not touch detection
- [ ] Server unit tests pass (`go test -race`, `npm test`, `unittest discover`)
- [ ] `node test/test-detection.js` passes against a running server
- [ ] `cd bench && node run-bench.js --gate` passes — no signal over its
      false-positive budget
- [ ] New thresholds are **measured** on the bench, not guessed or borrowed
- [ ] No persona in the human panel scores higher than before (keyboard-only,
      screen-reader, touch, tremor, elderly, high-latency)

## If this adds a detector

Which is it? See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-detector) — the
weighted sum means an under-weighted category can be certain and still never
change a verdict.

- [ ] **Evidence** — correlates with automation, scored with an honest confidence
- [ ] **Precondition** — the mechanism was skipped; gated outside the score
- [ ] **Dispositive** — a browser cannot produce this without being automated

## Breaking changes

<!-- Anything an existing integrator must do. Write "none" if none. -->
