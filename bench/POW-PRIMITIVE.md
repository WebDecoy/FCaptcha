# Proof-of-work primitive: measurements

Prompted by a reasonable criticism — SHA-256 has ASICs and GPUs behind it, so use
a memory-hard function (Argon2id, RandomX, CryptoNight) instead. The premise is
true. The conclusion does not follow, and measuring it showed why.

All figures below were taken in a real Chromium, with CPU throttling standing in
for lower-end hardware. Reproduce with the harness in `bench/`.

## What each primitive costs an honest browser

| | desktop | mid phone (4x) | low-end phone (6x) |
|---|---|---|---|
| SHA-256 | 552,472 hashes/sec | 158,552 | 113,460 |
| Argon2id 8 MiB | 8 ms per hash | 35 ms | 50 ms |
| Argon2id 19 MiB | 19 ms | 73 ms | 118 ms |
| Argon2id 64 MiB | 66 ms | 254 ms | 404 ms |

The shipped difficulty-4 challenge (65,536 expected hashes) costs **0.12s on a
desktop and 0.58s on a low-end phone**.

A difficulty-1 Argon2id search — sixteen attempts, the weakest thing still worth
calling a search — costs:

| memory | desktop | mid phone | low-end phone |
|---|---|---|---|
| 8 MiB | 0.13s | 0.56s | 0.80s |
| 19 MiB | 0.30s | 1.17s | 1.89s |
| 64 MiB | 1.06s | 4.06s | **6.46s** |

Plus a 64 MB allocation and 28 KB of WASM on a widget that is currently 57 KB
minified.

## Why the swap does not help anyway

The constraint that actually binds an attacker is the server-measured gap between
issuing a challenge and receiving its solution — wall clock per identity, which no
choice of hash function changes. The compute cost is not what is holding the line,
so hardening it buys nothing while the honest-client cost above is paid in full.

Argon2id does not change this. Memory-hardness raises the honest client's cost,
not the attacker's ceiling.

## Conclusion

Do not switch. It would cost low-end mobile users 3–11x more wall clock and 64 MB
of RAM to harden a property that is not currently protecting anything — and those
are the same users the accessibility work exists to protect.

The proof of work is a **liveness and timing gate**, not a cost function. Its
load-bearing part is the server-measured gap between issuing a challenge and
receiving its solution, which costs an attacker real wall clock per identity.
That, not the choice of hash, is the lever worth pulling if proof of work should
genuinely raise an attacker's cost — which makes it adaptive-difficulty work, not
primitive-selection work.
