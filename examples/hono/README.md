# Detecting bots and AI agents in a Hono application

A small FCaptcha integration with a browser demo and Hono middleware. FCaptcha
assesses browser automation indicators and interaction/timing signals, including
signals from AI agents operating browsers. This example shows how your server
verifies its token before accepting a request. MIT licensed, with no paid account
or external CAPTCHA service required.

## Run locally

Requires Node.js 22+. From the FCaptcha repository root:

```sh
npm ci --prefix server-node
cd examples/hono
npm ci
npm start
```

Open **http://127.0.0.1:8794**, using that exact hostname rather than `localhost`.
Write sample text, then choose **Verify and submit**. This uses invisible mode,
so there is no image puzzle. Messages are neither stored nor sent.

The launcher starts the Hono app on port 8794 and the real FCaptcha Node server
on 8795, both bound to loopback. It generates separate ephemeral signing and
verification secrets, restricts the site key and hostname, and trusts no forwarded
headers. Ctrl+C stops both services. Restarting invalidates old tokens.
Use sample text, not personal information, and leave both ports free before starting.

The page and browser script are shared with the FastAPI example to keep their
verification flow consistent. The launcher changes the visible framework name.
Keep the full repository checkout so those shared assets are available.

## Middleware before the protected operation

The browser calls `FCaptcha.execute(siteKey, { action: 'contact' })`, then submits
the returned token with its message. The public site key identifies this demo;
it is not a secret or an authentication credential.

[app.mjs](app.mjs) creates a Hono app with three steps on `/contact`:

1. Check the HTTP method, browser Origin, and JSON content type.
2. Apply Hono's `bodyLimit` middleware and validate message/token lengths.
3. Verify the token with FCaptcha before invoking the route handler.

The verification middleware sends a form-encoded POST to `/siteverify` with a
server-only secret, a five-second timeout, and redirects disabled. After checking
that the verifier returned a valid response, it requires all three bindings:

```js
if (result.success !== true ||
    result.hostname !== hostname ||
    result.action !== 'contact') {
  return c.json({ error: 'captcha_rejected' }, 403);
}
c.set('message', body.message.trim());
await next();
```

The route runs after verification:

```js
app.post('/contact', verifyVisitor, c => {
  // Send/save/enqueue c.get('message') here.
  return c.json({ accepted: true, demoOnly: true });
});
```

A browser success flag isn't enough. The server verifies the token separately,
and a token issued for another hostname or action is rejected. Tokens are
single-use, so every retry starts with a fresh `FCaptcha.execute` call.
Business-operation idempotency is separate: plan how a visitor can find out
whether an operation completed before a connection was interrupted.

Invalid tokens return **403**. Verifier outages or malformed replies return
**503**; they do not let a request through unchecked. The public `/config`
response contains only the FCaptcha origin and public site key. Neither the
signing key nor the verification secret is sent to the browser.

## Tests

```sh
npm test
```

The tests use Hono's `app.request`/`app.fetch` and a real local FCaptcha
`/siteverify` endpoint. Signed fixtures use fresh test-only credentials.
They cover successful verification, replay, expiry, forged tokens, wrong
hostname/action, incorrect verification credentials, invalid inputs, streamed
body limits, verifier failures, and the public configuration.

**11 tests pass** with Hono 4.13.12, `@hono/node-server` 2.1.3, and FCaptcha 1.42.0.
The local browser demo loads, and a live forged-token request returns 403.
These are integration checks, not a bot-detection accuracy measurement or a human
accessibility study. Other Hono runtime adapters have not been tested here.

## Adapting the example

Use managed services with HTTPS, persistent secrets, explicit site-key/hostname
configuration, and proxy trust appropriate to your deployment. For FCaptcha
replicas, configure shared replay state. Add rate limits and monitoring.
See [HARDENING.md](../../HARDENING.md).

The middleware uses web-standard Request/Response APIs through Hono; the local
launcher uses Node.js APIs. Adapt the launcher and secret configuration for your
runtime rather than copying it into production unchanged.

CAPTCHA does not authenticate users or replace authorization or CSRF controls.
The Origin check is a browser cross-origin check, not caller identity. This demo
has no accounts, database, or real side effects. Add protected operations only
after verification, plus the authentication your application requires.

This is also not a site-wide crawler log. Bots requesting unrelated pages without
running the widget are outside this example's visibility. Invisible mode still
processes interaction signals. Test real mobile, keyboard, and assistive-technology
workflows, and provide a recovery path for visitors who get rejected.
