# Angular and Next.js contact forms with FCaptcha

Runnable local examples for Angular reactive forms + Express and Next.js App Router.
Both validate on the server, verify with the real FCaptcha `/siteverify` endpoint,
require the expected hostname and `contact` action, and fail closed on verifier errors.
No message is stored or sent. Add your business action only after verification.

## Run

Use a current Node release supported by Angular 22 and Next 16 (tested with Node 26.5).
From the repository root:

```sh
npm --prefix server-node install --ignore-scripts --package-lock=false
cd examples/framework-forms
npm ci
npm --prefix angular ci
npm --prefix nextjs ci
npm test
npm run angular
```

Open **http://127.0.0.1:4200** (not localhost). Stop with Ctrl-C.
Run `npm run next` instead for **http://127.0.0.1:3000**. Run one at a time.
The launcher also runs FCaptcha on loopback port 8788 and, for Angular, Express on 4201.
Angular proxies `/api` to Express; Next handles it in `app/api/contact/route.js`.
The server-node install command avoids an existing upstream lockfile mismatch.

The launcher generates separate random signing and verification secrets on every
start. They are passed only to server processes. Restarting invalidates old tokens.
The browser receives only a public site key and FCaptcha URL. Never expose either
secret in client code or `NEXT_PUBLIC_*` variables.

## Files

- `angular/src/main.ts`: standalone reactive form with pending/error state.
- `angular/api.mjs`: Express adapter for the server handler.
- `nextjs/app/page.js`: client form with a synchronous double-submit guard.
- `nextjs/app/api/contact/route.js`: Node route handler and server-only configuration.
- `shared/browser.js`: lazy widget loader, new token on each attempt, submission.
- `shared/contact.mjs`: bounded JSON parsing and server verification.
- `test.mjs`: 17 integration checks using signed fixtures against real `/siteverify`.

```sh
npm --prefix angular run build
npm --prefix nextjs run build
```

Tests cover successful verification, replay, forged/expired tokens, hostname/action
mismatch, missing fields, size limits, origin checks and verification outages.
Signed fixtures use ephemeral keys. These are integration tests, not evidence of
human acceptance rates or browser bot-detection accuracy. Automated tests do not
solve the browser challenge.

## Production adaptation

The launcher and hardcoded loopback browser URL are for local development only.
Configure HTTPS origins and your public site key for deployment; configure stable,
separate secrets through your server environment. Use your actual allowed hostname.
Place the Angular API behind your application origin or configure an explicit
cross-origin policy. `Origin` checking is defense in depth, not authentication:
non-browser clients can set it themselves.

Keep authentication/authorization where needed, rate-limit submissions and FCaptcha,
and bound request sizes at your proxy too. Use a shared FCaptcha state backend when
running multiple replicas. Design protected side effects for idempotency: a token
is consumed during verification, and a later email/database failure needs a fresh
token on retry. Provide a usable recovery path when a visitor cannot pass verification.
Do not log submitted tokens or secrets. This example is not a complete spam defense.
