# Use FCaptcha with Better Auth

Run a local email sign-up form that uses the Better Auth CAPTCHA plugin
with FCaptcha's Turnstile-compatible verification endpoint.

## Run locally

From this directory, use Docker, OpenSSL, and Node.js 22 or later.

```sh
npm ci
export FCAPTCHA_VERIFY_SECRET="$(openssl rand -hex 32)"
FCAPTCHA_SECRET="$(openssl rand -hex 32)" docker run -d --rm \
  --name fcaptcha-better-auth-demo \
  -p 127.0.0.1:8797:3000 \
  -e FCAPTCHA_SECRET -e FCAPTCHA_VERIFY_SECRET \
  -e FCAPTCHA_ALLOWED_HOSTNAMES=127.0.0.1 \
  -e FCAPTCHA_SITE_KEYS=better-auth-demo \
  ghcr.io/webdecoy/fcaptcha:1.53.0
npm start
```

Open **http://127.0.0.1:8796**. Enter a sample password of at least eight
characters and select **Create demo account**. The expected result is
**Demo account created.** Use a different sample email to try it again.
Accounts are stored in memory and disappear on restart.

Press Ctrl+C to stop the demo, then run `docker stop fcaptcha-better-auth-demo`.

## How verification works

The browser sends a fresh FCaptcha token in the `x-captcha-response`
header. Better Auth's `siteVerifyURLOverride` points the CAPTCHA plugin
at FCaptcha instead of the default provider URL. Before creating an
account, the plugin verifies the token and checks its hostname and
action. Missing tokens return HTTP 400 and invalid tokens return 403.

[demo.mjs](demo.mjs) keeps the verification secret on the application
server. The FCaptcha container has the separate signing secret. The
browser receives only the public site key. There are no Cloudflare
credentials involved in this configuration.

Use HTTPS, your own database, persistent server secrets, and explicit
allowed hostnames when adapting the demo. Give each attempt a new token.
Use the same action for every endpoint guarded by this plugin instance.

- [Better Auth CAPTCHA plugin](https://better-auth.com/docs/plugins/captcha)
- [FCaptcha Docker setup](../../docker/README.md)
