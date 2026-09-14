# Security hardening and upgrade notes

Deploy all three server implementations from the same revision. Run the shared
conformance tests against each deployment before directing production traffic to it.

## Signing keys and token compatibility

Generate the signing key with `openssl rand -hex 32` and store it in your secret
manager. Startup now rejects keys shorter than 32 UTF-8 bytes and obvious
repetition (fewer than eight distinct characters). Those checks cannot establish
entropy: use the generator, not a memorable password. The explicit insecure
development mode binds the bundled server launcher to `127.0.0.1`.

IP binding now uses full HMAC-SHA-256 with a domain-separated key derived from
the signing key and a canonical IP address. IPv4-mapped IPv6 addresses normalize
to IPv4. Tokens issued by an older revision fail `remoteip` validation after this
upgrade. Drain old instances and allow their five-minute tokens to expire before
enabling the new pool; do not mix old and new validators. Validation without
`remoteip` continues to authenticate old token signatures for their normal lifetime.

## Availability limits

Public API admission is checked before scoring and bot-directory discovery:

| Limit | Allowance |
| --- | --- |
| Total API requests | 20,000 per 60-second window |
| API requests per resolved visitor IP | 600 per 60-second window |
| Challenge requests per resolved visitor IP | 60 per 60-second window |
| Challenge reservations per visitor IP | 128 per five-minute lifetime |
| Live challenge storage | 100,000 entries |
| Local spent-token storage | 100,000 entries, retained ten minutes |

Admission windows start with the first request. Exceeding admission returns 429
with `Retry-After: 60`; unavailable/full security state returns 503 or refuses
token verification. Live challenges and spent-token markers are never evicted to
admit new work. Redis quotas are atomic and shared across replicas. Challenge
reservations remain charged until their lifetime expires, including solved
challenges; site-key rotation cannot reset a visitor quota.

Configure `TRUSTED_PROXIES` for the actual ingress. A shared NAT counts as one
source; these conservative defaults may need capacity planning for large shared
egress networks. Apply upstream connection and body limits as well. Account
for backend verification too: calls to `/siteverify` and
`/api/token/verify` share the calling backend's 600-request allowance. Do not
forward an untrusted visitor address to bypass that quota. Redis must
use `maxmemory-policy noeviction`: eviction of spent-token keys can reopen replay.
Reserve enough memory for the configured traffic and retention periods; Redis
write failures deliberately deny verification. Keep Redis private and authenticated.

Node bot discovery retains at most sixteen responses (each capped at 256 KiB),
coalesces identical lookups, limits discovery to eight concurrent jobs, and caches
fetch failures for thirty seconds. Go bounds its dependency's otherwise unbounded
cache with sixteen single-agent verifier entries, 256 KiB responses, and eight concurrent lookups. Both implementations bound their connection pools as well.
Multi-agent Signature-Agent headers receive presence-only treatment in Go.
Neither server treats a timeout or capacity limit as proof of forgery.

`/health` is process liveness. `/ready` checks configured Redis connectivity and
returns 503 when unavailable. Helm readiness uses `/ready`; liveness remains
independent so a Redis outage does not cause a restart loop.
Node Redis commands have a two-second response deadline and a bounded command
queue. Readiness probes coalesce until the underlying ping settles, including
after a timeout, so stalled probes cannot accumulate work.

## Browser integration

An empty `serverUrl` means same origin. Network/HTTP failures reject with
`error.code === 'server_unavailable'`; no local challenge or unsigned token is
created. Automatic form protection clears stale tokens, keeps the form on the
page, dispatches `fcaptcha:error`, and calls an optional `errorCallback(error)`.
Show a retry message or your application's alternate verification flow there.
Always validate a returned token from your backend.

Call `FCaptcha.destroy(widgetId)` when unmounting a widget and `session.destroy()`
for an invisible session. The last teardown releases the shared form analyzer and
restores the form submission method if FCaptcha still owns the wrapper. PoW uses
at most four workers.

The client currently injects styles and creates blob workers. A strict CSP must
permit its script origin, the API origin in `connect-src`, `blob:` in `worker-src`,
and the injected stylesheet (a suitable style hash or `style-src 'unsafe-inline'`).
Do not add `unsafe-inline` to `script-src`. Sites that prohibit injected styles
need to extract and serve the stylesheet under their own CSP before integrating.

## Builds and evidence

Containers pin base-image digests and run as non-root. Node uses `npm ci`; Python
uses `requirements.lock` with mandatory hashes. Refresh the Python lock with:

```sh
uv pip compile --python-version 3.12 --generate-hashes server-python/requirements.txt -o server-python/requirements.lock
```

Go source builds require at least 1.26.8; the Go containers build with 1.27.1.
The Node and Python containers use Node 26 and Python 3.14. CI covers Node
22/24/26, Go 1.26.8/1.27.1, and Python 3.12/3.14, including `govulncheck`.
Dependency-update automation and
Docker provenance/SBOM generation are enabled in the repository workflows.

The fast-JavaScript detector was removed from every scoring implementation and
from benchmark exemptions because it penalized normal fast hardware. The remaining
corpus is still a regression dataset, not a population accuracy measurement.
Derived variants do not count as additional independent users or devices.
Collect independent, consented sessions on real desktop/mobile hardware, with
keyboard, touch, assistive technology, and real network variation before making
accuracy claims. The current one-sample agent classes cannot support a class TPR
estimate; the report continues to display their misses. Such captures cannot be
manufactured by changing the test harness.
