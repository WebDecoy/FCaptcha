# @webdecoy/fcaptcha-client

The browser widget for [FCaptcha](https://github.com/WebDecoy/FCaptcha): a
self-hosted, open-source CAPTCHA with no image puzzles. It works as a single
checkbox or invisibly, and it detects bots, headless browsers and AI agents
driving real browsers.

**The widget needs a running FCaptcha server**, which scores the submission and
issues the token. Start one in a minute with Docker:

```bash
docker run -d -p 3000:3000 -e FCAPTCHA_SECRET="$(openssl rand -hex 32)" ghcr.io/webdecoy/fcaptcha
```

Every FCaptcha server also serves this widget at `/fcaptcha.js`, so you may not
need this package at all. Use it when you want the widget from npm or a CDN.

## Install

```bash
npm install @webdecoy/fcaptcha-client
```

Or from a CDN. Pin the version and use the integrity hash, which is published
in each [release's notes](https://github.com/WebDecoy/FCaptcha/releases) and in
`dist/integrity.json`:

```html
<script
  src="https://cdn.jsdelivr.net/npm/@webdecoy/fcaptcha-client@VERSION/dist/fcaptcha.min.js"
  integrity="sha384-…"
  crossorigin="anonymous"></script>
```

## Checkbox

```html
<form method="post" action="/signup">
  <div data-fcaptcha="your-site-key" data-endpoint="https://your-fcaptcha-server.com"></div>
  <button>Sign up</button>
</form>
```

When the visitor passes, the token is posted with the form as `fcaptcha_token`.
To render it yourself:

```js
import FCaptcha from '@webdecoy/fcaptcha-client';

FCaptcha.configure({ serverUrl: 'https://your-fcaptcha-server.com' });
const widgetId = FCaptcha.render('captcha', {
  siteKey: 'your-site-key',
  callback: (token) => { /* optional */ },
});
```

## Invisible

```js
const result = await FCaptcha.execute('your-site-key', { action: 'login' });
if (result.success) {
  // Send result.token to your backend.
}
```

## Verify on your backend

Verify the token server-side. The server speaks the same `siteverify` API as
Turnstile, reCAPTCHA and hCaptcha, so an existing verification call only needs
a new base URL:

```bash
curl -X POST https://your-fcaptcha-server.com/turnstile/v0/siteverify \
  -d "secret=$FCAPTCHA_VERIFY_SECRET" -d "response=$TOKEN"
```

## More

Languages, options, the full API, framework examples and how the scoring works
are in the [FCaptcha README](https://github.com/WebDecoy/FCaptcha#readme).
Try it on the [live demo](https://webdecoy.com/product/fcaptcha-demo/).

MIT licensed.
