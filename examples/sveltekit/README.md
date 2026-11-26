# SvelteKit contact form with FCaptcha

This SvelteKit 3 example calls a self-hosted FCaptcha widget from a Svelte form and verifies the token in a native SvelteKit form action. The form action checks the hostname and the `contact` action before accepting the submission. The demo sends no mail and stores no messages.

## Run it locally

Requires Node.js 22.17+ and Docker. From this directory:

```sh
export FCAPTCHA_SECRET="$(openssl rand -hex 32)"
export FCAPTCHA_VERIFY_SECRET="$(openssl rand -hex 32)"

docker run --rm -d --name fcaptcha-sveltekit-demo \
  -p 127.0.0.1:8797:3000 \
  -e FCAPTCHA_SECRET -e FCAPTCHA_VERIFY_SECRET \
  -e FCAPTCHA_ALLOWED_HOSTNAMES=127.0.0.1 \
  -e FCAPTCHA_SITE_KEYS=sveltekit-contact \
  ghcr.io/webdecoy/fcaptcha:1.53.0

npm ci
npm run dev
```

Open [127.0.0.1:5179](http://127.0.0.1:5179), enter a message and select **Verify and submit**. Use `docker stop fcaptcha-sveltekit-demo` to stop the verifier.

## Use the pattern in your application

- `src/routes/+page.svelte` requests a fresh token for the contact action before submitting the form.
- `src/routes/+page.server.js` checks input and verifies the token using a server-only secret. It rejects missing or invalid tokens and returns 503 when the verifier is unavailable.
- `FCAPTCHA_ORIGIN` sets the verifier address the server calls. `FCAPTCHA_PUBLIC_ORIGIN` sets the origin that serves the widget to browsers. Both default to the local Docker port. Keep `FCAPTCHA_VERIFY_SECRET` on the server and use HTTPS in production.
- Behind a reverse proxy, set the Node adapter's `ORIGIN` to your public application URL so the form action compares the verified hostname with the intended host. Set the FCaptcha hostname allowlist and review the project's [hardening guide](../../HARDENING.md) before production use.

## Checks

Run `npm run build && npm test`. The action tests use the built Node adapter with a local stub verifier to check the response handling independently of browser classification. Try the Docker quickstart above to exercise the actual widget.
