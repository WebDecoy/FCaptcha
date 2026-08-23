# FCaptcha Helm chart

Open source CAPTCHA with proof of work, behavioural biometrics, and AI-agent
detection. Self-hosted, no external dependencies.

```bash
helm install fcaptcha oci://ghcr.io/webdecoy/charts/fcaptcha \
  --namespace fcaptcha --create-namespace \
  --set secret=$(openssl rand -hex 32)
```

Or from a checkout:

```bash
helm install fcaptcha ./charts/fcaptcha \
  --namespace fcaptcha --create-namespace \
  --set secret=$(openssl rand -hex 32)

helm test fcaptcha -n fcaptcha
```

## The chart will not install without a signing key

Deliberately. The server falls back to `dev-secret-change-in-production`, which
is published in its own source, so a deployment that forgets to set one does not
fail — it quietly accepts tokens that anyone can mint. A template error is the
only way to make that impossible to do by accident.

Set `secret`, or point `existingSecret` at a Secret you manage with
sealed-secrets, External Secrets or SOPS.

## Read this before production

**`config.trustedProxies` decides whose `X-Forwarded-For` is believed**, and it
matters more in Kubernetes than anywhere else: traffic arrives through an ingress
controller, which is a proxy. If it is not trusted, every visitor is attributed
to the controller and rate limiting collapses onto one address — silently. The
default covers the usual in-cluster pod CIDRs; narrow it to your controller's
range.

**Run one replica for now.** With the Go image, `redis.url` shares PoW challenges
and their atomic one-time claim. Token replay protection, rate limits,
suspicion, fingerprints, and idempotency are still per-pod; Node and Python do
not yet use Redis. `autoscaling` remains off until those remaining stores land.

The full list of deployment settings with security consequences is in
[SECURITY.md](https://github.com/WebDecoy/FCaptcha/blob/main/SECURITY.md#deployment-notes-that-are-security-relevant).

## Values

| Key | Description | Default |
|---|---|---|
| `secret` | Token signing key. **Required** unless `existingSecret` is set | `""` |
| `existingSecret` | Name of a Secret you manage, instead of one the chart creates | `""` |
| `existingSecretKey` | Key within that Secret | `FCAPTCHA_SECRET` |
| `verifySecret` | Credential a backend presents when verifying a token. Empty means "same as the signing key". Splitting them means a leaked verify credential cannot also mint tokens | `""` |
| `config.trustedProxies` | Peers allowed to set `X-Forwarded-For` / `X-Real-IP` / TLS-fingerprint headers | in-cluster private ranges |
| `config.allowedHostnames` | Comma-separated hostnames permitted to mint tokens. Empty accepts any origin | `""` |
| `config.siteKeys` | Comma-separated allowlist of accepted site keys | `""` |
| `config.logVerdicts` | One privacy-safe JSON line per verification | `false` |
| `config.logVerdictsIncludeRaw` | Also log free-text detection reasons. **Can contain visitor-derived data** | `false` |
| `image.repository` / `image.tag` | Container image; tag defaults to the chart's `appVersion` | `ghcr.io/webdecoy/fcaptcha` |
| `replicaCount` | See the note above before raising this | `1` |
| `redis.url` / `redis.existingSecret` | Go only: shared PoW challenge and atomic claim state; remaining stores are still local | `""` |
| `service.type` / `service.port` | | `ClusterIP` / `80` |
| `ingress.enabled` | | `false` |
| `resources` | | 100m CPU / 128Mi requested |
| `autoscaling.enabled` | Off by default — replicas do not share state | `false` |
| `podDisruptionBudget.enabled` | | `false` |
| `extraEnv` | Anything the chart does not model | `[]` |

Security defaults are on and not parameterised down: non-root (uid 65532),
read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no
service-account token mounted. The image is a single static binary that writes
nothing but `/tmp`.

## What `helm test` checks

More than liveness. `/health` only proves the process is up, and the published
image once returned 404 for `/fcaptcha.js` for three months while health stayed
green. The test checks that the widget is served, that it declares UTF-8 (the
translations are decoded using the document's encoding otherwise), that the
Turnstile-compatible `siteverify` endpoint answers, and that a request carrying
no proof of work is refused a token.
