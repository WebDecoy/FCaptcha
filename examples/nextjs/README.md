# Next.js App Router example

A small contact form that renders the FCaptcha checkbox and verifies its token
in an App Router route handler before accepting the submission. It does not
send or store messages.

## Run locally

Requires Node.js 22+, Docker, and the full FCaptcha checkout. From the
repository root, start a local FCaptcha server with separate signing and
verification credentials:

```sh
export FCAPTCHA_SIGNING_SECRET="$(openssl rand -hex 32)"
export FCAPTCHA_VERIFY_SECRET="$(openssl rand -hex 32)"
docker run --rm -d --name fcaptcha-nextjs -p 127.0.0.1:3000:3000 \
  -e FCAPTCHA_SECRET="$FCAPTCHA_SIGNING_SECRET" \
  -e FCAPTCHA_VERIFY_SECRET="$FCAPTCHA_VERIFY_SECRET" \
  -e FCAPTCHA_SITE_KEYS=nextjs-example \
  -e FCAPTCHA_ALLOWED_HOSTNAMES=127.0.0.1 \
  ghcr.io/webdecoy/fcaptcha:latest
```

In the same shell, run the example:

```sh
cd examples/nextjs
npm ci
npm run dev
```

Open **http://127.0.0.1:3001** (not `localhost`). Check the checkbox, enter
a sample message, and submit. Stop the local server with
`docker stop fcaptcha-nextjs` when finished.

The example defaults to FCaptcha at `http://127.0.0.1:3000` and site key
`nextjs-example`. Set `FCAPTCHA_ORIGIN` for the server-side verification URL,
`NEXT_PUBLIC_FCAPTCHA_ORIGIN` for the browser script and widget API, and
`NEXT_PUBLIC_FCAPTCHA_SITE_KEY` to use other values. Keep
`FCAPTCHA_VERIFY_SECRET` server-side; never give it a `NEXT_PUBLIC_` prefix.
The route rejects missing, replayed, or hostname-mismatched tokens. A verifier
outage also rejects the submission.

## Tests

From the repository root:

```sh
npm ci --prefix server-node
npm ci --prefix examples/nextjs
npm test --prefix examples/nextjs
npm run build --prefix examples/nextjs
```

The tests run against the local Node FCaptcha verifier with temporary test
credentials. They cover a valid token, replay, a missing token, and a token
minted for another hostname. No Docker server is needed for the tests.

This is a local demo. For deployment, use HTTPS, persistent credentials, an
explicit site-key and hostname policy, and the production guidance in
[HARDENING.md](../../HARDENING.md).
