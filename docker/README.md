# FCaptcha Docker image

The public, prebuilt image is **`ghcr.io/webdecoy/fcaptcha`**:

- [Browse releases and tags on GitHub Container Registry](https://github.com/WebDecoy/FCaptcha/pkgs/container/fcaptcha).
- Platforms: Linux `amd64` and `arm64` (including Docker on Apple Silicon).
- Runtime: the Go server, with the browser widget and demo bundled.
- Tags: `latest` and release versions without the `v` prefix, such as `1.41.0`.
- Pulling the public image does not require a GitHub account or building the source.

## Quick local trial

Requires Docker and OpenSSL. This exposes the service only on your local machine:

```sh
docker pull ghcr.io/webdecoy/fcaptcha:1.41.0
docker run -d --name fcaptcha \
  -p 127.0.0.1:3000:3000 \
  -e FCAPTCHA_SECRET="$(openssl rand -hex 32)" \
  -e FCAPTCHA_VERIFY_SECRET="$(openssl rand -hex 32)" \
  ghcr.io/webdecoy/fcaptcha:1.41.0
```

Open <http://localhost:3000/demo/>. The container also serves:

| Path | Purpose |
| --- | --- |
| `/health` | Health check |
| `/fcaptcha.js` | Self-hosted browser widget |
| `/api/*` | FCaptcha API |
| `/siteverify` | Backend token verification |

```sh
curl --fail http://localhost:3000/health
docker logs fcaptcha
docker stop fcaptcha
```

The random keys above are convenient for a disposable trial. To integrate your
application, supply your own securely stored keys instead: the app backend needs
`FCAPTCHA_VERIFY_SECRET`, while `FCAPTCHA_SECRET` is the signing key. Neither
belongs in browser code. Changing the signing key invalidates existing tokens.

## Compose from this repository

The included Compose file supports pulling the image or building locally:

```sh
export FCAPTCHA_SECRET="$(openssl rand -hex 32)"
docker compose -f docker/docker-compose.yml pull
docker compose -f docker/docker-compose.yml up -d --no-build
```

Unlike the loopback-only trial above, the existing Compose file publishes port
3000 on all host interfaces. Review the port mapping and network exposure before
running it on a reachable server. It uses `latest`; pin `image:` to a version or
digest for reproducibility. Set a separate `FCAPTCHA_VERIFY_SECRET` in the service's
environment when integrating a production app (otherwise it defaults to the signing key).

## Version pinning and upgrades

Use `ghcr.io/webdecoy/fcaptcha:1.41.0` for a fixed release, or pin the multi-platform
digest shown by the registry:

```sh
docker buildx imagetools inspect ghcr.io/webdecoy/fcaptcha:1.41.0
# Use the reported top-level digest as:
# ghcr.io/webdecoy/fcaptcha@sha256:<digest>
```

For upgrades, review the [changelog](../CHANGELOG.md) and
[hardening notes](../HARDENING.md), update the pinned image, pull it, and recreate
the service using the same managed configuration and keys. Configure HTTPS,
allowed hostnames/site keys, trusted proxies and rate limits for your deployment.
Use Redis-backed shared security state when running multiple replicas.

The software is MIT licensed; infrastructure and operations remain your responsibility.

## Build and publication

Build locally from the repository root:

```sh
docker build -f docker/Dockerfile -t fcaptcha-local .
```

The [publication workflow](../.github/workflows/docker-publish.yml) builds both
architectures and pushes to GHCR on `v*` release tags. It also supports manual
workflow dispatch. Release tags publish both `latest` and the versioned tag;
manual dispatch from a branch publishes `latest`. Builds include provenance and
SBOM attestations.
