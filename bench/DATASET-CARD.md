# FCaptcha benchmark corpus — dataset card

## Purpose

The corpus is a versioned regression and measurement dataset for FCaptcha's
Node, Go, and Python detectors. It supports reproducible detector comparisons,
cross-server parity, accessibility false-positive review, and observe-only
research. It is not a population sample and is not a general-purpose identity,
fraud, or accessibility dataset.

## Evidence model

Every row declares three independent fields:

- `provenance`: captured, derived, self-reported, or synthetic;
- `captureMethod`: how a browser or payload was actuated; and
- `labelEvidence`: why the human or agent label is believed.

Only captured `verified-human` and `paired-human-control` families support an
observed false-positive statement. Simulated humans remain structural
regression fixtures. Self-reported hosted traces are exploratory and ephemeral.
Observed agents, simulated agents, and literature-derived payloads remain
separate. Repeated community runs sharing a capture-family ID count once in
independent-human denominators.

## Collection and versions

Committed captures record the FCaptcha client version/hash when the capture
path provides it. Community contributions use permanent-publication schema v1,
coarse browser/OS/tool major versions, a test-only context, declared
limitations, and a machine-readable redaction manifest. Historical samples
predating that schema retain their original provenance rather than being
retroactively described as community contributions.

Current aggregate community coverage is reproducible with:

```bash
cd bench
npm run community:coverage
```

At introduction of schema v1 the community subset contains 0 captures from 0
capture families. The existing corpus is primarily one project's scripted and
manually observed configurations; the command output, not contributor identity,
is the maintained coverage record as contributions arrive.

## Privacy and sanitization

Community source captures stay local. The preparation command removes
operational/session identifiers, screen geometry, and form field names;
replaces stable signal hashes with family-scoped HMAC pseudonyms; rejects
content/secret fields and common URL, email, hostname, IP, key, and token forms;
and emits file hashes plus a redaction manifest for review. Accepted rows
contain no contributor name, contact detail, source timestamp, raw family
nonce, account, or browsing hostname. Aggregate coverage omits sample and
family identifiers.

Automated screening reduces risk but cannot prove that arbitrary input is
anonymous. Reviewers inspect the complete sanitized row and reject ambiguity.

## Known biases and limitations

- The panel is small, opt-in, and clustered by contributors, hardware, language,
  geography, browser versions, and test choreography.
- Repeated sessions are correlated even when signal values differ.
- A tool/version label is operator-declared unless the capture protocol pins a
  binary or commit.
- Test pages cannot reproduce the full distribution of production latency,
  device load, extensions, password managers, or accessibility settings.
- A 0% observed false-positive result means no included evidential family
  crossed the threshold. It does not estimate a 0% population rate.
- The configured 0.3% per-signal budget is a product target, not a confidence
  interval derived from this dataset.

## Intended uses

- regression and cross-language parity tests;
- detector threshold research with provenance attached;
- accessibility and legitimate-input false-positive review;
- aggregate coverage-gap identification; and
- reproducible technical discussion of FCaptcha behavior.

## Prohibited or unsupported claims

- population-level false-positive or true-positive rates;
- representativeness of people with disabilities or assistive-technology users;
- identification of a person, contributor, device, or browsing activity;
- treating accessibility tooling as automation evidence;
- training or evaluating unrelated identity, surveillance, or eligibility
  systems; or
- describing self-reported, simulated, derived, or repeated-family rows as
  independent verified humans.

## Licensing and permanence

The repository is MIT licensed. A community contributor explicitly consents to
permanent public publication of the sanitized capture under that license before
the tool will prepare it. This permits copying and redistribution through Git
history, forks, mirrors, packages, and derivative works. Removal from the
current repository cannot guarantee deletion of existing copies. See
[`COMMUNITY-CONTRIBUTIONS.md`](COMMUNITY-CONTRIBUTIONS.md) for the consent,
review, and removal process.
