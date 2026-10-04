# Detecting bots and AI agents before a Supabase Edge Function accepts a request

FCaptcha assesses browser automation and interaction signals, including signals
from AI agents operating browsers. This example obtains an invisible-mode token
in a browser and verifies it in a Supabase Edge Function before accepting a
sample message. Free and MIT licensed; no paid FCaptcha account is needed.

**This protects a custom function.** Supabase Auth's built-in CAPTCHA providers
are [hCaptcha and Turnstile](https://supabase.com/docs/guides/auth/auth-captcha).
This example does not replace that provider setting or protect direct calls to
Supabase Auth, database, or Storage APIs.

## Run locally

Requires Node.js 22+, Docker Desktop, and the Supabase CLI. The commands below
use `npx supabase` so a global CLI install is unnecessary. Use an isolated checkout
and leave ports 8792, 8793 and the default Supabase local ports free.

From the repository root, terminal 1:

```sh
npm ci --prefix server-node
cd examples/supabase
node local.mjs
```

This starts FCaptcha at `http://127.0.0.1:8793` and the demo page at
`http://127.0.0.1:8792`. It generates fresh, separate signing and verification
secrets and writes the verification settings to the ignored `.env.local` file.
The public HTML contains neither secret. The local launcher uses loopback,
an explicit site key and hostname, and no trusted forwarding headers.

From `examples/supabase`, terminal 2:

```sh
npx supabase start --exclude gotrue,realtime,storage-api,imgproxy,mailpit,postgrest,postgres-meta,studio,logflare,vector,supavisor
npx supabase functions serve fcaptcha-contact --env-file .env.local
```

The reduced local stack includes the Edge Runtime, gateway, and database;
the example itself does not use the database. Initial startup downloads images.
Docker Desktop resolves `host.docker.internal` from the function to FCaptcha on
your host. A native Linux Docker setup may need different host networking; these
local commands were tested on macOS with Docker Desktop.

Open **http://127.0.0.1:8792** (not `localhost`), enter sample text, and choose
**Verify and submit**. The page gets a new token for each attempt and calls
`http://127.0.0.1:54321/functions/v1/fcaptcha-contact`.
No message is stored or sent. Use sample text, not personal information.

Stop the two foreground commands with Ctrl+C. Then run `npx supabase stop` from
this example directory. Restarting `local.mjs` rotates its credentials, so restart
`supabase functions serve` too to load the new `.env.local`.

## What the function checks

The function in [handler.ts](supabase/functions/fcaptcha-contact/handler.ts):

1. Handles browser preflight with an explicit allowed origin, including the
   `authorization`, `apikey`, `x-client-info`, and `content-type` headers used
   by Supabase clients. Error replies retain the CORS headers too.
2. Accepts JSON POST requests, caps streamed request bodies at 16 KiB, and bounds
   message/token lengths before calling the verifier.
3. Calls FCaptcha's `/siteverify` with the server-only verification secret and a
   five-second timeout. Redirects are not followed.
4. Requires `success === true`, the expected browser-page hostname, and
   `action === 'contact'` before reaching the protected operation.

```ts
const response = await fetch(`${config.captchaOrigin}/siteverify`, {
  method: 'POST',
  redirect: 'error',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ secret: config.verifySecret, response: body.token }),
  signal: AbortSignal.timeout(5000),
});
```

A failed token or binding check returns **403**. Verifier outages, unsuccessful
HTTP responses, or malformed results return **503**, without accepting the request.
Tokens are single-use; do not cache them or retry the same token automatically.
For real side effects, design business-operation idempotency separately.

The supplied `verify_jwt = false` applies only to this new, deliberately public
demo function. It has no database or service-role access. CAPTCHA is an abuse
check, not user authentication, and CORS does not stop non-browser callers from
forging an Origin header. Do not copy this public-function setting onto private
endpoints. For protected user data, add the appropriate Supabase user validation
and authorization/RLS as well.

## Adapt for a hosted project

Copy `supabase/functions/fcaptcha-contact` into your project's functions folder.
Host FCaptcha on HTTPS with persistent secrets and configure its site-key and
hostname allowlists. Set these **function secrets**, using your own values:

- `APP_ORIGIN`: the exact HTTPS origin of your frontend, without a trailing slash.
- `FCAPTCHA_ORIGIN`: your HTTPS FCaptcha server origin, reachable from Supabase.
- `FCAPTCHA_VERIFY_SECRET`: that server's verification credential, separate from
  its signing key. Never put either secret in browser code.

Set secrets through Supabase's dashboard or an ignored local env file with
`supabase secrets set --env-file <your-private-file> --project-ref <your-project>`.
Use the public-function configuration only if your new endpoint intentionally
allows unauthenticated visitors, then deploy with
`supabase functions deploy fcaptcha-contact --project-ref <your-project>`.

Update the browser demo's `captchaOrigin`, `functionUrl`, and public site key for
your deployment. Keep the `contact` action consistent with the server check.
Add the real protected operation only after verification. Do not leave a direct
unauthenticated database/API route that bypasses this check. Add rate limits,
monitoring, and a recovery path for legitimate visitors who get rejected.
See FCaptcha's [hardening guide](../../HARDENING.md), including shared replay state
when running replicas. No hosted Supabase project is deployed by this example.

## Tests and limits

Verified locally with Supabase CLI 2.118.0, Edge Runtime 1.76.2 (Deno 2.1.4),
Deno 2.9.6 for tests, and FCaptcha 1.42.0. The local gateway answered preflight
and the served function returned 403 for a forged token. The Chrome demo loads
the local widget. A human browser verification was not measured.

The local Kong gateway answers preflight itself and may replace the handler's
`Access-Control-Allow-Origin` with `*`. The handler still rejects mismatched
Origin values on POST. Check the headers at your deployed gateway; do not infer
caller authentication from a successful preflight or from CORS headers.

Install the Node server dependencies first, then from this directory:

```sh
npx deno task test
npx deno task check
npx deno lint supabase/functions tests
```

Seven test groups cover CORS, input limits, verifier response shapes, timeouts,
server errors, and the form-encoded verification call. The integration group
starts the **real Node FCaptcha verifier** and uses signed fixtures with ephemeral
test-only credentials: acceptance, replay rejection, expiry, forgery, and wrong
hostname/action are checked. No production credentials are used.

These tests validate the integration contract, not detection accuracy. The
widget needs JavaScript and interaction signals; this isn't a site-wide crawler
log and does not identify bots fetching unrelated pages. Invisible mode still
processes interaction signals. Test real mobile, keyboard, and assistive-technology
workflows, and plan how visitors recover from rejection or a service outage.
