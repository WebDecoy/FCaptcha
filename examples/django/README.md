# Detecting bots and AI agents in a Django form

A small Django 5.2 LTS application that renders FCaptcha in a normal form and
verifies the submitted token before running the protected action. It keeps the
verification credential server-side, fails closed, and checks the signed
hostname and action. The sample does not store the message or send email.

## Run it

Start an FCaptcha server first. Configure it to allow the `django-demo` site key
and `127.0.0.1`, then export the same backend verification credential here:

```sh
cd examples/django
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
export FCAPTCHA_VERIFY_SECRET='replace-with-your-verification-secret'
python manage.py runserver 127.0.0.1:8000
```

Open **http://127.0.0.1:8000**. Override `FCAPTCHA_ORIGIN`,
`FCAPTCHA_SITE_KEY`, or `APP_ORIGIN` if your local verifier or application uses
another origin. Never put `FCAPTCHA_VERIFY_SECRET` in a template or client-side
runtime configuration.

The widget adds `fcaptcha_token` to the form. `contact/verifier.py` posts it to
`/turnstile/v0/siteverify` with a five-second timeout and no redirect following.
The view accepts only `success: true` for the expected hostname and `contact`
action. Verifier errors return 503; rejected and replayed tokens return 403.

Keep Django's CSRF middleware enabled. FCaptcha complements CSRF, authentication,
authorization, rate limits, and abuse controls; it does not replace them.

## Test it

```sh
python manage.py test
```

The tests cover accepted, replayed, missing, and incorrectly bound tokens,
verifier failure, and keeping the secret out of the page. The HTTP verifier is
faked in these application tests; FCaptcha's own suites test token issuance and
single-use enforcement.

Tested with Python 3.14.2, Django 5.2.19, and HTTPX 0.29.0: **6 tests pass**.
