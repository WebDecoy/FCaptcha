# FCaptcha contact form / お問い合わせフォーム

A small, runnable integration example: a Japanese/English form, the real Node.js
FCaptcha server, and backend `/siteverify` validation. MIT licensed like this repository.
The demo **does not send email or store messages**.

## Run locally

Requires Node.js 22+ and npm. From the repository root:

```sh
cd server-node
npm ci
cd ../examples/contact-form
npm start
```

Open **http://127.0.0.1:8787** (use this exact host, not `localhost`). Type a test
message, then select **検証して送信 / Verify and submit**. The page starts in Japanese;
use **English** to switch. The form uses invisible mode, so there is no puzzle widget.

The launcher binds both servers to loopback (form: 8787, FCaptcha: 8788), generates
separate ephemeral signing and verification secrets, and starts the actual FCaptcha
Express app. Ctrl+C stops both. Restarting invalidates existing tokens.

Do not enter real personal information. This is a local example, not a production
contact service. Close other processes using ports 8787/8788 before starting it.

## What to read

- `public/app.js`: requests a fresh token with `action: 'contact'`, submits the
  message and token, and displays the backend result. Each retry obtains a new token.
- `server.mjs`: limits request size, checks browser Origin, validates input, calls
  `/siteverify` with a server-only secret and a five-second timeout, then checks
  `success`, `hostname`, and `action` before accepting the demo submission.
- `start.mjs`: starts the local application and FCaptcha without a CDN or paid account.

No secret is included in `/config` or browser JavaScript. FCaptcha tokens are single-use.
CAPTCHA does not replace authentication, authorization, CSRF protection or rate limiting.
The Origin check here is a browser cross-origin check, not a way to identify a user.

## Test

```sh
npm test
```

Tests use the real FCaptcha `/siteverify` endpoint and signed fixtures created with an
ephemeral test-only key. They cover acceptance, replay, expiry, wrong hostname/action,
forged and missing tokens, invalid input, cross-origin submissions, request limits,
verification outages, and the public configuration. They **do not** measure bot
classification accuracy or constitute a human browser accessibility test.

## Before production

Run FCaptcha and the app as managed services with HTTPS, persistent secrets from a
secret manager, explicit hostname/site-key configuration, appropriate proxy trust,
rate limits, monitoring, and shared security state when using replicas. Keep verification
credentials separate from signing keys. Decide how users can recover from rejection
or an outage, and test real mobile, keyboard and assistive-technology workflows.
Add your actual protected operation only after verification succeeds. Do not use this
local launcher in production. See the repository's `HARDENING.md` for deployment details.

## 日本語

Node.js 22以上で上記コマンドを実行し、`http://127.0.0.1:8787` を開いてください。
メッセージを入力して「検証して送信」を押すと、不可視モードでトークンを取得し、
バックエンドが検証します。この例ではメール送信・データ保存は行いません。
本番導入前に、秘密鍵の管理、HTTPS、レート制限、障害時の再試行、誤検知と操作性を
確認してください。
