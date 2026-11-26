# FCaptcha contact form with Remix 3

This example runs a self-hosted FCaptcha widget and sends its token to a Remix 3 action. A custom provider for `@sdxc/captcha` calls FCaptcha's Turnstile-compatible verification endpoint. Middleware checks the expected hostname and action before allowing the contact handler to run. The demo sends and stores no messages.

## Run it locally

Requires Node.js 24.3 or later and Docker. From this directory:

```sh
export FCAPTCHA_SECRET="$(openssl rand -hex 32)"
export FCAPTCHA_VERIFY_SECRET="$(openssl rand -hex 32)"

docker run --rm -d --name fcaptcha-remix-demo \
  -p 127.0.0.1:8797:3000 \
  -e FCAPTCHA_SECRET -e FCAPTCHA_VERIFY_SECRET \
  -e FCAPTCHA_ALLOWED_HOSTNAMES=127.0.0.1 \
  -e FCAPTCHA_SITE_KEYS=remix-contact \
  ghcr.io/webdecoy/fcaptcha:1.53.0

npm ci
npm start
```

Open [127.0.0.1:8796](http://127.0.0.1:8796) and try submitting a message. To stop the verifier, run `docker stop fcaptcha-remix-demo`.

The browser receives the widget URL and a public site key. Only the application server gets `FCAPTCHA_VERIFY_SECRET`. The route rejects missing, invalid, expired, and mismatched tokens with HTTP 403. When the verifier is unavailable or its answer is invalid, the route returns HTTP 503.

For production, adapt the route to your application's configured public origin and trusted proxy setup, add request size and rate limits, and follow the [hardening guide](../../HARDENING.md).

## Checks

Run `npm test` for the router and middleware tests. They use a stub verifier on loopback so each outcome can be tested independently. The Docker quickstart uses FCaptcha's actual verifier.
