# FCaptcha for Nuxt 4

A client-only `<FCaptcha>` component with public runtime configuration, self-hosted script loading, and cleanup when a route or component changes.

Install the official module from npm:

```sh
npm install @webdecoy/fcaptcha-nuxt
```

## Configure it

Add the module and public widget settings to `nuxt.config.ts`:

```ts
// nuxt.config.ts
export default defineNuxtConfig({
  modules: ['@webdecoy/fcaptcha-nuxt'],
  fcaptcha: {
    siteKey: 'contact-form',
    serverUrl: 'https://captcha.example.com',
    scriptSrc: 'https://captcha.example.com/fcaptcha.js',
  },
})
```

Install your self-hosted FCaptcha verifier first using the [main quickstart](../../README.md#try-it-in-60-seconds). Public configuration contains only the site key, endpoint and script URL. Keep the verification secret in **server-only** runtime config or environment variables.

```vue
<script setup>
const token = ref('')
const message = ref('')
function failed() {
  token.value = ''
  message.value = 'Verification failed. Please try again.'
}
</script>

<template>
  <form method="post" action="/api/contact">
    <label>Email <input type="email" name="email" required></label>
    <FCaptcha
      @verify="value => { token = value; message = '' }"
      @expire="token = ''"
      @error="failed"
    />
    <p role="status">{{ message }}</p>
    <button type="submit" :disabled="!token">Send</button>
  </form>
</template>
```

The widget adds a hidden `fcaptcha_token` field. Your own `/api/contact` server handler must verify it with FCaptcha's `/siteverify` endpoint **before** doing the protected action. Reject failed, expired, replayed, malformed or unavailable verification, and check the expected hostname/action using server-controlled values. The example does not implement your contact handler or send email.

Props can override `site-key`, `server-url`, `script-src`, `theme` (`light`/`dark`) and `lang`. All widgets on the same page must use the same verifier endpoint because the checkbox widget uses a browser-global configuration. Conflicting endpoints emit an error rather than silently rerouting existing widgets.

This is the checkbox widget integration. Invisible-mode composables are not part of this initial module. Configure HTTPS, CSP and reverse-proxy settings for your own deployment.

## Development

```sh
npm ci
npm test
npm run test:build
```

Tests cover public defaults, token/error/expiry events, endpoint conflicts, script load failure/retry/timeout, remount cleanup, and late callbacks. The Nuxt fixture builds with SSR enabled and a server-only marker to check that secrets do not enter client assets. These are integration/lifecycle checks, not a detection-accuracy benchmark.
