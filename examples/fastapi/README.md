# Detecting bots and AI agents in a FastAPI application

A runnable FCaptcha integration with a browser form, an async verification
client, and a FastAPI dependency that protects a route. Free and MIT licensed.
No paid account, CDN, or external CAPTCHA service is needed.

FCaptcha assesses browser and interaction signals for automation, including
headless browsers and AI agents that drive browsers. This example shows how to
consume its verdict in your own FastAPI app. It does not add new detectors.
The demo accepts sample messages but **does not store them or send email**.

## Run it

Requires Python 3.12+. From the FCaptcha repository root:

```sh
cd examples/fastapi
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python run.py
```

On Windows, activate with `.venv\Scripts\activate` instead.
Open **http://127.0.0.1:8790**, using this exact hostname rather than `localhost`.
Type a sample message and click **Verify and submit**. No image puzzle is shown.
Use test text, not personal information.

The launcher starts two Uvicorn processes, both bound to loopback:

- **8790:** your FastAPI application, defined in `main.py`.
- **8791:** FCaptcha's existing Python/FastAPI detection server.

It generates separate ephemeral signing and verification secrets, restricts the
site key and hostname, and disables forwarded-header trust. Ctrl+C stops both
services. Restarting invalidates old tokens. Leave both ports free before starting.
This launcher is for local testing, not production deployment.

## How it works

1. The page loads the widget from your local FCaptcha server.
2. `FCaptcha.execute(siteKey, { action: 'contact' })` collects signals and asks
   FCaptcha to assess them. A successful result includes a signed token.
3. The browser sends that token and the sample message to your `/contact` route.
4. A FastAPI dependency sends the token to FCaptcha's `/siteverify` endpoint,
   using a verification secret that stays on the server.
5. The dependency requires `success: true`, the expected `hostname`, and the
   expected `action`. Only then does the route run its protected operation.

The important boundary is server-side verification. Disabling a submit button
or trusting a browser's `success` field cannot protect an API endpoint.

### The verification call

The complete implementation is in [main.py](main.py). Its async HTTPX client is
created once per worker in FastAPI's lifespan context and closed on shutdown:

```python
response = await request.app.state.verifier.post(
    "/siteverify",
    data={"secret": settings.verify_secret, "response": submission.token},
)
response.raise_for_status()
result = response.json()
```

After validating the response shape, the dependency checks the signed bindings:

```python
if (result["success"] is not True
        or result.get("hostname") != urlsplit(settings.origin).hostname
        or result.get("action") != "contact"):
    raise HTTPException(403, "captcha_rejected")
```

`/contact` depends on that check:

```python
@app.post("/contact")
async def contact(submission: Annotated[Submission, Depends(verified_submission)]):
    # Send, save, or enqueue only after verification succeeds.
    return {"accepted": True, "demoOnly": True}
```

Invalid tokens and binding mismatches return **403**. Verification timeouts,
server errors, or malformed responses return **503**, so a verifier outage does
not silently turn protection off. There is a five-second HTTPX timeout and an
eight-second browser timeout for the application request. The app does not
follow verifier redirects or automatically retry token verification.

Tokens are single-use. Every browser retry calls `FCaptcha.execute` again.
For a real application, business-operation idempotency needs its own design:
a token alone does not tell a visitor whether a message was saved before a
network interruption.

The demo also checks the browser's Origin, accepts only JSON, limits the body to
16 KiB, and bounds the message and token lengths. Its input-validation errors do
not echo the message or token. `/config` exposes only the public site key and
FCaptcha origin. No signing or verification secret is sent to the browser.

## What is being detected?

The underlying FCaptcha server combines browser automation indicators with
interaction signals, including pointer, keyboard, form, and timing patterns.
It also validates proof of work. The intent is to assess automation even when an
agent operates a browser, rather than relying on a claimed User-Agent alone.
Read the repository [README](../../README.md) for individual detectors and
current limitations.

This is **not a site-wide crawler log**. Bots fetching unrelated pages without
running the widget are outside this example's visibility. Calling `/contact`
without a valid token is rejected, but that does not identify every crawler on
your site. CAPTCHA also does not replace authentication, authorization, rate
limits, or the CSRF controls your real application requires.

The implementations have documented differences. In particular, the Python
server identifies Web Bot Auth headers by presence; it does not cryptographically
verify those agent identities as the Go and Node implementations do. Do not use
that signal as proof of a caller's identity.

## Tests

From this directory:

```sh
python -m pytest test_main.py -q
```

The integration tests call the actual Python FCaptcha `/siteverify` endpoint
through HTTPX's ASGI transport. Positive cases use signed fixtures generated with
an ephemeral test key. They cover successful verification, replay, expiry,
forged tokens, incorrect verification credentials, wrong/missing hostname and
action, input/body limits, cross-origin submissions, and keeping secrets out of
public responses. Mock transports exercise verifier outages and malformed replies.

Tested with Python 3.12.12, FastAPI 0.142.1, HTTPX 0.28.1, and FCaptcha 1.42.0:
**25 tests pass**. Starlette 1.7.0 currently emits a deprecation warning for its
HTTPX-based TestClient. The pinned environment remains functional.

These are integration tests, **not bot-detection accuracy or accessibility
benchmarks**. The demo page was also checked loading in Chrome. No human pass
rate is inferred from automated tests or from the browser loading successfully.

## Adapting it for production

Use managed HTTPS services and persistent secrets, configure explicit site keys
and allowed hostnames, and set proxy trust for your actual network. If running
FCaptcha replicas, configure shared security state so replay protection works
across instances. Add rate limits and request-size limits at the ingress too.
See [HARDENING.md](../../HARDENING.md).

Replace the demo response with your operation after verification succeeds.
For cookie-authenticated routes, use the CSRF protection appropriate to your
application. The Origin check here is a browser cross-origin check, not caller
authentication. The example deliberately omits optional `remoteip` verification
rather than trusting arbitrary forwarded IP headers.

Plan a recovery path for legitimate visitors who are rejected, and test actual
keyboard, mobile, and assistive-technology workflows. Invisible mode still
collects interaction signals; self-hosting does not mean no data is processed.
