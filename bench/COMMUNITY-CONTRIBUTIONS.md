# Community benchmark contributions

This path is for captures that a contributor intentionally publishes in the
repository forever. It is separate from the hosted demo's seven-day research
export. Short-lived research consent never authorizes a corpus contribution and
the preparation command refuses to treat it as one.

The command works locally. It does not upload the source capture, the sanitized
sample, or the manifest.

## Before capturing

Use a fresh browser profile or disposable test device and a test-only FCaptcha
page. Do not sign in to personal accounts or reuse a normal browsing profile.
Remove unrelated extensions, history, saved form values, and password-manager
entries. Type only synthetic fixture content. The source must contain no real
hostnames, URLs, email addresses, IP addresses, tokens, cookies, account IDs, or
stable identifiers from another site.

Assistive technology is welcome and remains human evidence when a person is
operating it. VoiceOver, NVDA, JAWS, TalkBack, Voice Control, and switch input
are recorded as environment context; their presence is never an automation
label. Record only tool/version major numbers and bounded setting slugs, not a
person's accessibility profile or free-form personal details.

Create one random capture-family nonce for one operator/environment cohort and
reuse it for repeated runs in that cohort:

```bash
openssl rand -hex 32
```

Do not reuse that nonce for another dataset or website. The raw nonce is never
published; the preparation command stores a domain-separated SHA-256 digest.
Repeated samples from that family remain useful, but the benchmark counts the
family once in independent-human denominators.

## Source schema

Start from [`community-contribution.example.json`](community-contribution.example.json).
The schema is closed: unknown fields fail instead of being silently retained.

- `publicationConsent` must contain the exact permanent-publication statement,
  `permanentPublic: true`, and `license: "MIT"`.
- Every isolation/accuracy attestation must be `true`.
- `captureFamilyNonce` is the 64-character random value described above.
- `label`, `captureMethod`, and `labelEvidence` remain independent. Human
  contributions use `manual-browser` plus `verified-human` or an actual
  `paired-human-control`; agent captures use observed browser automation plus
  `observed-agent`.
- `limitations` is required. State the cohort's real limits, such as one
  operator, one hardware model, or an unverified browser setting.
- Browser, OS, input, assistive-tool, and agent versions are deliberately
  coarse. Agent captures also require a bounded actor name/version and, when
  available, a full Git commit.
- `signals` is the captured FCaptcha signal object. Never add form values or
  page content to it.

## Prepare and inspect

```bash
cd bench
npm run community:prepare -- \
  --input /path/to/community-capture.json \
  --sample-out /path/to/review/sample.json \
  --manifest-out /path/to/review/redaction-manifest.json
```

The preparation step:

- enforces the closed schema, field bounds, label/evidence combinations, and
  explicit permanent consent;
- removes challenge/session/site identifiers and screen geometry;
- replaces stable signal hash values with family-scoped HMAC pseudonyms so
  equality within a capture family remains testable without publishing the
  original cross-site value;
- replaces form field names with `field_1`, `field_2`, and so on;
- rejects secret/content fields and URL, email, hostname, IP, authorization,
  private-key, and JWT-like values;
- computes a sanitized-sample fingerprint and rejects exact corpus duplicates;
- reports how many committed samples already share the capture family; and
- writes SHA-256 hashes and every redaction into the review manifest.

Both output paths must be new files. The source capture is never copied into the
repository. A contributor submits only the sanitized sample and redaction
manifest for review. The manifest is review evidence; the accepted sample under
`corpus/captured/` is the benchmark input.

Run these before opening a pull request:

```bash
npm test
npm run community:coverage
node run-bench.js --gate
```

`community:coverage` publishes only aggregate capture/family, browser, OS,
input, assistive-tool, label, and scenario counts. It never prints contributor
or family identifiers.

## Reviewer checklist

- Confirm the exact permanent-publication consent and all fresh-context
  attestations are present in the contributor's source-screening record.
- Re-run the preparation command from the submitted source when the contributor
  can share it privately; otherwise verify `sampleSha256` against the proposed
  sample and review every manifest redaction.
- Inspect the entire sanitized sample for content or identifiers the automated
  patterns could miss. Reject ambiguous data rather than editing it in public.
- Confirm label, capture method, label evidence, actor provenance, endpoint,
  scenario, and declared limitations agree with the capture procedure.
- Treat assistive technology operated by a person as human evidence. Never
  re-label it because an accessibility API or tool is present.
- Check exact-duplicate and existing-family results. Multiple runs from one
  family must not be described as independent people or hardware.
- Run the benchmark and coverage commands. Keep observed human, paired control,
  observed agent, simulated, and self-reported cohorts separate in conclusions.
- Do not infer a population false-positive rate from this convenience panel.

## Removal and contact

To request removal, email **hello@webdecoy.com** with `FCaptcha corpus removal`
in the subject and the sample ID. A maintainer will remove the sample from the
current corpus and aggregate reports. Git is a permanent public history and
forks or package mirrors may retain prior copies, so removal cannot guarantee
erasure everywhere; do not contribute data that depends on later deletion.

Report an accidental secret or personal-data publication privately rather than
opening an issue. Use the repository's private security reporting path or the
same email address with `FCaptcha data exposure` in the subject.
