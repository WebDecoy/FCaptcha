# Dynamic browser instrumentation

Status: proposed, observation-only first

## Purpose

FCaptcha commits the submitted signal document into the proof-of-work input. That
prevents a solved proof from being reused with a different document, but it does
not prove that an unmodified FCaptcha client produced the document. A patched
client can fabricate signals and then solve against its fabrication.

This workstream raises the cost of that attack by giving each challenge a small,
fresh browser program whose result is committed alongside the other signals. It
is defense in depth, not proof that a visitor is human. An agent driving an
ordinary browser through operating-system input can run the program correctly.

The design is informed by Cap's per-challenge instrumentation, but deliberately
does not accept executable JavaScript from the challenge endpoint:

- https://trycap.dev/guide/instrumentation
- https://trycap.dev/guide/workings.html

## Security boundary

The server sends data, never code. The widget contains a fixed, reviewed
interpreter with a closed opcode set. The implementation must not use `eval`,
`Function`, dynamic import, inline script insertion, or arbitrary property
access. A compromised or misconfigured challenge endpoint must not gain script
execution in the embedding page.

The program:

- has at most 64 instructions and no unbounded loop or recursion;
- has a small fixed byte limit, with instruction count, operand type, register
  index, and opcode validated before execution;
- operates on 32-bit integers with specified wrapping semantics;
- reads only explicitly allowlisted, privacy-reviewed browser facts;
- never reads field values, key values, page text, cookies, storage, or history;
- performs no network access;
- has a hard wall-clock budget and returns `budget_exceeded` on expiry;
- produces a versioned result that is included in `signalsJson` before PoW.

Malformed programs must produce one bounded `invalid_program` result. They must
not throw into the embedding page, allocate according to attacker-controlled
sizes, or partially execute. Challenge generation must remain constant-bounded
work so the public challenge endpoint does not become a CPU denial-of-service
primitive.

Unknown versions and opcodes fail closed for the instrumentation result, but the
first release only records that failure. They do not withhold a token.

## Threat model

### In scope

- Static clients that submit a canned FCaptcha signal document.
- Simplified solvers that implement the PoW endpoint but not the browser program.
- Browser emulators with incomplete or incoherent JavaScript/DOM behavior.
- Replay of a valid instrumentation result against another challenge.
- Source patches that delete or overwrite individual observations without also
  reproducing the committed program result.

### Out of scope

- A solver that executes the published widget in a real browser.
- Browser-internal agents whose input is delivered as ordinary trusted events.
- A fully patched browser engine or a client that faithfully reimplements the
  interpreter.
- Paid human solving and compromised endpoints.

Obfuscation is not a security boundary and is not part of this proposal.

## Protocol

The existing challenge response gains additive fields:

```json
{
  "protocolVersion": 2,
  "instrumentation": {
    "version": 1,
    "programId": "base64url-128-bit-id",
    "registers": [124950871, 39200152, 77, 0],
    "instructions": [
      ["xor", 0, 1],
      ["rotl", 0, 7],
      ["probe", 2, "wasm_validate"],
      ["mix", 0, 2]
    ]
  }
}
```

The exact wire representation should use compact integer opcode identifiers in
production. Names are shown here for readability.

The widget returns a new environment observation:

```json
{
  "environment": {
    "instrumentation": {
      "version": 1,
      "programId": "base64url-128-bit-id",
      "result": "base64url-256-bit-digest",
      "status": "ok",
      "durationBucket": "under_10ms"
    }
  }
}
```

`signalsJson` already commits this object into the PoW input. The server also
stores the expected digest with the one-use challenge and compares it in
constant time during verification. Consuming the challenge prevents a caller
from probing multiple answers against the same program.

The instrumentation version, program ID, canonical program bytes, and expected
digest are part of the server's signed/stored challenge record. Verification
first validates PoW, then atomically consumes the challenge, then evaluates the
instrumentation result. A valid proof with a wrong instrumentation answer still
consumes the challenge, preventing an answer oracle.

The server never trusts `durationBucket` as elapsed-time evidence. It is an
observation only; the existing server-side challenge clock remains authoritative.

## Versioning and compatibility

- `protocolVersion` is explicit rather than inferred from optional fields.
- Version 1 clients continue to receive and solve the current SHA-256 challenge.
- A version 2 challenge may contain instrumentation, but the initial server must
  accept a missing result and record `instrumentation_missing` only in the
  experimental observation surface.
- The widget reports its supported protocol versions when requesting a
  challenge. The server must never send a program the widget cannot interpret.
- Challenge responses remain `Cache-Control: no-store`; intermediary caching
  must not turn a fresh program into a shared program.
- Downgrade and legacy-client observations are recorded separately from bot
  evidence. Old clients are not suspicious merely because they are old.

## Initial opcode set

Phase one should remain deliberately boring:

- Integer: `add`, `xor`, `imul`, `rotl`, `rotr`, `select`, `mix`.
- Fixed probes: WebAssembly validation, selected property descriptors, typed
  array semantics, canvas readback consistency, DOM geometry consistency, and
  worker/main-thread agreement.
- Finalization: canonical serialization followed by SHA-256.

Every probe returns a normalized small integer or an explicit unavailable/error
code. Raw high-entropy values are not returned to the server. Existing privacy
and false-positive review applies before a probe enters the allowlist.

## Rollout

### Phase 0 — protocol and fixtures

1. Specify canonical integer semantics and serialization.
2. Add cross-language golden fixtures for Node, Python, and Go.
3. Add parser rejection fixtures for excessive instructions, invalid operands,
   unknown opcodes, oversized bodies, and unsupported versions.
4. Add protocol-version negotiation without changing issued challenges.

### Phase 1 — observe-only interpreter

1. Implement the fixed interpreter in the widget.
2. Generate deterministic bounded programs in all three servers.
3. Store the expected digest with the existing one-use challenge.
4. Expose mismatch, missing, unsupported, and budget-exceeded states only under
   `experimental`/observations.

### Phase 2 — paired capture

Capture fresh human and agent pairs across:

- Chrome, Firefox, and Safari on desktop;
- representative iOS and Android devices;
- privacy restrictions and WebAssembly-disabled environments;
- keyboard-only, screen-reader, reduced-motion, and slow-device personas;
- local CDP, hosted computer use, stealth CDP, and browser-internal agents.

Synthetic and self-reported samples remain exploratory and cannot justify a
blocking rule.

### Phase 3 — enforcement decision

Enforcement is a separate change. It requires:

- zero unexplained regression-corpus human failures;
- stable results across repeated real-device sessions;
- meaningful incremental agent coverage after removing signals already caught
  by existing categories;
- an explicit fallback policy for unsupported browsers;
- a security review of the generator, interpreter, and endpoint trust boundary.
- bounded load tests showing challenge generation and invalid-program handling
  cannot amplify attacker-controlled CPU or memory consumption.

If the result only catches solvers that already fail PoW or browser-consistency
checks, it remains an observation and does not consume score.

## Proof-of-work follow-up

Cap also demonstrates two ideas that should be measured separately rather than
coupled to instrumentation:

1. Split the same expected work across several sub-challenges to reduce solve
   time variance and p90/p99 latency.
2. Compare a GPU-resistant work function with SHA-256 on real mobile devices.

FCaptcha's PoW is currently a server-timed liveness gate, not an economic toll.
Changing the primitive therefore needs to show a user-experience or abuse-cost
benefit beyond GPU-resistance alone. The existing measurements and rationale in
`bench/POW-PRIMITIVE.md` remain the baseline.

## Non-goals

- Claiming that instrumentation proves humanity.
- Executing challenge-provided JavaScript in the page's origin.
- Blocking browsers solely for lacking WebAssembly or a new widget version.
- Treating client-reported timing as trusted.
- Shipping a new blocking signal without paired evidence.
