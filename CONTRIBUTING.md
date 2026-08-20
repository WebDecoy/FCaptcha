# Contributing

## The rule that matters most

**A change to detection lands in all three servers.** Go, Python and Node are
separate implementations of the same algorithm, kept in sync by hand. A detector
added to one and not the others means the same visitor is scored differently
depending on which server answered — and because nothing fails when they drift,
it stays wrong until somebody notices.

The same applies to the wire format. Tokens were mutually unverifiable across the
three servers for months (Go emitted padded base64url, Node unpadded, Python
signed a payload with different JSON spacing) because each only ever verified its
own. Byte-identical fixtures in `server-*/…siteverify` tests now pin that; keep
them in step.

## What is most useful right now

**Captured traces from real browsers driven by real people.** The benchmark
corpus is scripted personas from a single machine, which bounds what any
false-positive number derived from it can mean. `bench/corpus/captured/` takes
new samples directly — see [bench/README.md](bench/README.md). This is the single
highest-value contribution to the project, above any feature.

Other open areas:

- Web Bot Auth verification for the Python server. Go and Node verify
  cryptographically against the agent's published key directory; Python still
  identifies by header presence, because there is no maintained Python library.
- Cross-session / per-fingerprint behavioural correlation — the durable defence
  against source-patched browsers.
- An escalation path for a flagged visitor. Today a false positive is a dead end
  with no recourse, which is the largest product gap.
- `/metrics`, and the score histogram an operator needs to tune their threshold.
- Redis-backed distributed state (currently in-memory).
- WebAssembly proof of work for better low-end mobile performance.

## Before you open a pull request

```bash
# server unit tests
cd server-go     && go vet ./... && go test -race ./...
cd server-node   && npm test
cd server-python && pip install -r requirements.txt && python -m unittest discover -p 'test_*.py'

# end-to-end, against a running server
cd server-node && npm start &
node test/test-detection.js

# the widget in a real browser
cd client && npm install && npm run build      # so the minified comparison has something to compare
cd test/browser && npm install && npx playwright install chromium && npm test

# the false-positive gate
cd bench && npm install && node run-bench.js --gate
```

CI runs all of this. The bench gate is the one that blocks on a number: a signal
firing on the human panel more often than its budget allows fails the build.

## Adding a detector

Read [the note on scoring](README.md#how-the-score-is-composed) first, because
the aggregation is not obvious and has bitten before.

The final score is a **weighted sum across ~12 categories, so any one category
contributes at most its own weight**. `bot` is weighted 0.13 against a 0.5
threshold. A detector added to an under-weighted category can be completely
certain and still never change a verdict — which is exactly how the proof of work
went unenforced until v1.23.0.

So, before writing one, decide which kind of thing you have:

- **Evidence** — correlates with automation, could be wrong. Score it, pick a
  confidence honestly, and expect it to matter only in combination.
- **A precondition** — the mechanism was skipped rather than beaten. Gate on it
  outside the score, the way a missing proof of work or an unlisted hostname is
  handled. Do not express this as a high score and hope.
- **Dispositive** — a browser cannot produce this without being automated
  (`navigator.webdriver`, driver-injected globals). Mark it `Dispositive` and it
  floors the score. The bar is high on purpose: "the console is attached" does
  not qualify, because a developer with DevTools open trips it.

Then measure it. Every threshold in the behavioural layer came from the bench
rather than from intuition or from another project's published numbers, and a new
one should too. `node run-bench.js` reports the per-signal false-positive rate
against the human panel; if your detector fires on the screen-reader or
motor-tremor persona, that is a finding about the detector.

## Accessibility

Non-negotiable, and repeatedly the thing that catches people out. The bench
carries keyboard-only, screen-reader, touch, tremor, elderly and high-latency
personas because each of them looks like automation to a naive detector: no mouse
movement, unnaturally slow input, no micro-tremor, perfectly consistent timing.

Existing exemptions (keyboard-only users with no pointer events, touch users) are
load-bearing. If a change makes one of those personas score higher, that is a
false positive on a real user, not a tuning opportunity.

## Style

Match the surrounding code — the servers each read like idiomatic code in their
own language rather than a transliteration of one another.

Comments explain **why**, not what. The codebase leans heavily on this: most
non-obvious constants and every unusual decision carry the reasoning and often
the measurement that produced them. If you find yourself writing a number, write
down where it came from.

Commit messages follow Conventional Commits (`feat(scope):`, `fix(scope):`,
`chore(scope):`) with a body that explains the reasoning. Long is fine.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).
