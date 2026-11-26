# Use FCaptcha with Authentik, Gitea, Django and Flask-WTF

FCaptcha is a self-hosted CAPTCHA designed to detect bots and AI agents
operating browsers. Its reCAPTCHA-compatible endpoints let applications
that expose both URLs use their existing widget and server verification
flow.

[Try the browser demo](https://webdecoy.com/product/fcaptcha-demo/) or
[deploy a verifier](INSTALLATION.md) before configuring your application.
These recipes are maintained by WebDecoy; they are not upstream project
endorsements.

## Before you start

Deploy FCaptcha behind HTTPS at a hostname your browser and application
server can reach, such as `https://captcha.example.com`. Use a reviewed
release; the contract checks below used **FCaptcha 1.50.1**.

The relevant endpoints are:

| Purpose | URL |
| --- | --- |
| Browser widget | `https://captcha.example.com/recaptcha/api.js` |
| Backend verification | `https://captcha.example.com/recaptcha/api/siteverify` |
| Widget form field | `g-recaptcha-response` |

Configure a server-side `FCAPTCHA_VERIFY_SECRET` and give that verification
credential to your application. Keep the signing key `FCAPTCHA_SECRET`
on the FCaptcha server; never put either secret in browser markup. If you
have configured `FCAPTCHA_SITE_KEYS`, use an allowed public site key.

Changing only a script URL is insufficient: token verification must also
reach your own verifier. Keep application CSRF protection and rate limits.
If your application sends `remoteip`, it must agree with the client IP
used to issue the token. Configure trusted reverse proxies rather than
removing IP binding to work around a mismatch.

## Gitea

Gitea exposes a reCAPTCHA base URL. In `app.ini`:

```ini
[service]
ENABLE_CAPTCHA = true
CAPTCHA_TYPE = recaptcha
RECAPTCHA_URL = https://captcha.example.com/recaptcha/
RECAPTCHA_SITEKEY = your-public-site-key
RECAPTCHA_SECRET = your-private-verification-secret
```

Use your actual public site key and FCaptcha verification credential.
Retain the `/recaptcha/` path: Gitea appends `api.js` for the widget and
`api/siteverify` for verification. Apply the configuration through your
normal Gitea deployment/restart procedure.

`ENABLE_CAPTCHA` enables registration verification. Login and external
registration settings are separate; review the
[Gitea configuration guide](https://docs.gitea.com/administration/config-cheat-sheet/)
for the flows you intend to protect.

**Checked:** current Gitea source constructs the expected script and
verification paths. An equivalent backend form request accepted a signed
local fixture and rejected a forged token against FCaptcha 1.50.1. This
check did not run a full Gitea registration UI.

## Authentik

Authentik's CAPTCHA stage accepts custom JavaScript and verification URLs, so
it can use FCaptcha through the Turnstile-compatible endpoints. In the
Authentik admin interface, create or edit a **Captcha Stage** and set:

| Authentik field | Value |
| --- | --- |
| Public key | your FCaptcha site key |
| Private key | your `FCAPTCHA_VERIFY_SECRET` |
| JS URL | `https://captcha.example.com/turnstile/v0/api.js` |
| API URL | `https://captcha.example.com/turnstile/v0/siteverify` |
| Interactive | enabled |
| Score minimum threshold | `0` |
| Score maximum threshold | `1` |
| Request content type | `application/x-www-form-urlencoded` |

Add the stage to the flow you want to protect. Both the visitor's browser and
the Authentik server must be able to reach the FCaptcha hostname. Configure
that hostname in Authentik's Content Security Policy if your deployment has
customized its default CSP.

Use interactive mode. Authentik defaults the minimum score to `0.5`, following
reCAPTCHA's convention that a higher score is more human. FCaptcha's native
Turnstile-compatible `score` is the opposite: **lower is more human**. Set the
range to `0`–`1`, so Authentik accepts the full score range and FCaptcha's
`success` verdict remains the gate. Leaving Authentik's `0.5` minimum in place
rejects a valid low-risk FCaptcha response.

Authentik includes `remoteip` in its verification request. FCaptcha must derive
the same visitor address when it issues the token, so configure trusted proxies
correctly on both services. Do not solve a mismatch by trusting arbitrary
forwarding headers or disabling IP binding.

The private key is a backend verification credential, not FCaptcha's signing
key. Keep `FCAPTCHA_SECRET` only on the FCaptcha server. A successful stage
does not replace Authentik's other authentication, rate-limit, or recovery
controls.

**Checked:** Authentik **2026.8.7** loaded FCaptcha **1.52.0** through the
configured Turnstile script path in a real browser flow. Its backend stage
accepted a signed, low-risk token, advanced the flow, and rejected the same
token in a new flow session as a replay. The test also confirmed that the
default `0.5` minimum is incompatible with FCaptcha's score direction; the
documented `0`–`1` range passed. The headless browser used to inspect the flow
was independently blocked by FCaptcha's normal WebDriver/headless signals, as
expected, so the accepted fixture was signed with the same ephemeral test key
and visitor-IP binding rather than weakening detection.

## Django with django-recaptcha

Install and configure
[django-recaptcha](https://github.com/django-recaptcha/django-recaptcha)
according to its installation guide. Then configure the host in Django
settings:

```python
import os

RECAPTCHA_DOMAIN = "captcha.example.com"  # Host only, no scheme or path.
RECAPTCHA_PUBLIC_KEY = "your-public-site-key"
RECAPTCHA_PRIVATE_KEY = os.environ["FCAPTCHA_VERIFY_SECRET"]
```

The package adds `https://` and `/recaptcha/api.js` or
`/recaptcha/api/siteverify` itself. Do not set `RECAPTCHA_DOMAIN` to a
complete URL. Use a trusted HTTPS certificate for that hostname.

Start with the checkbox widget:

```python
from django import forms
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox

class ContactForm(forms.Form):
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox)
```

Render the bound form normally and require `form.is_valid()` before
processing its protected action. A successful frontend callback alone
must not authorize a submission.

**Checked:** django-recaptcha **4.1.0** with Django **6.1.3** rendered the
custom HTTPS widget URL. The package's actual verification client
accepted a signed local fixture and rejected replayed and forged tokens
against FCaptcha 1.50.1. The local test used a temporary trusted TLS
proxy; it did not test a production deployment or complete Django browser
form submission.

## Flask-WTF

Install and configure
[Flask-WTF](https://flask-wtf.readthedocs.io/en/latest/quickstart/), including
a Flask application secret and CSRF protection. Configure the script and
verification URL together:

```python
import os

app.config.update(
    RECAPTCHA_PUBLIC_KEY="your-public-site-key",
    RECAPTCHA_PRIVATE_KEY=os.environ["FCAPTCHA_VERIFY_SECRET"],
    RECAPTCHA_SCRIPT="https://captcha.example.com/recaptcha/api.js",
    RECAPTCHA_VERIFY_SERVER="https://captcha.example.com/recaptcha/api/siteverify",
)
```

Use the existing field in a Flask-WTF form:

```python
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import RecaptchaField

class ContactForm(FlaskForm):
    captcha = RecaptchaField()
```

Render the form's CSRF token and CAPTCHA field. Require
`form.validate_on_submit()` before performing the protected action.

For a meaningful verification test, set **`app.testing = False`**.
Flask-WTF intentionally bypasses its CAPTCHA validator in testing mode.
Do not disable CAPTCHA verification or CSRF protection to make an
integration test pass.

**Checked:** Flask-WTF **1.3.0** with Flask **3.1.3** rendered the configured
script URL. Its actual validator, with testing disabled and verification
enabled, accepted a signed local fixture and rejected replayed and forged
tokens against FCaptcha 1.50.1. This did not test a full browser form flow.

## Validate your deployment

On a staging installation, complete the widget in a real browser and
confirm the protected action succeeds only after backend verification.
Then confirm missing, forged and replayed tokens are rejected. Test
keyboard-only navigation, expiry/reset and the legitimate browsers your
users rely on. Check reverse-proxy IP handling and your CSP without
weakening either to hide errors.

The 11 local contract checks described above used signed fixtures minted
with an ephemeral test key. They verify protocol handling, **not human
classification, AI-agent detection accuracy or complete application
compatibility**. Browser challenge completion, multi-widget behavior,
production TLS and the full application request lifecycle remain separate
checks.

These recipes begin with checkbox verification. Do not assume invisible
or score-based modes work identically across applications and releases.
See the [provider compatibility table](README.md#apps-that-support-turnstile-hcaptcha-or-recaptcha)
for endpoint-specific score semantics.
