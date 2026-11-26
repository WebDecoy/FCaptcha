# Detecting bots and AI agents in a Laravel form

A runnable Laravel 13 application with a Blade form, a custom validation rule,
and server-side FCaptcha verification. It fails closed, checks the signed
hostname and action, and keeps the verification credential out of the browser.
The sample does not store the message or send email.

## Run it

Start an FCaptcha server first. Configure it to allow the `laravel-demo` site
key and `127.0.0.1`, then:

```sh
cd examples/laravel
composer install
cp .env.example .env
php artisan key:generate
```

Set `FCAPTCHA_VERIFY_SECRET` in `.env` to the backend verification credential
configured on your FCaptcha server, then run:

```sh
php artisan serve --host=127.0.0.1 --port=8000
```

Open **http://127.0.0.1:8000**. Override `FCAPTCHA_ORIGIN`,
`FCAPTCHA_SITE_KEY`, or `FCAPTCHA_EXPECTED_HOSTNAME` if your deployment differs.

The widget adds `fcaptcha_token` to the form. `App\Rules\ValidFCaptcha` posts
it to `/turnstile/v0/siteverify` through Laravel's HTTP client with a five-second
timeout and redirect following disabled. It accepts only `success: true` for
the expected hostname and `contact` action. An unavailable or malformed
verifier returns 503; rejected and replayed tokens return a validation error.

Keep Laravel's CSRF middleware enabled. FCaptcha complements CSRF,
authentication, authorization, rate limits, and abuse controls; it does not
replace them.

## Test it

```sh
php artisan test
```

The feature tests use `Http::fake()` to cover accepted, replayed, missing, and
incorrectly bound tokens, verifier failure, the exact endpoint/credential
contract, and keeping the verification secret out of the page. FCaptcha's own
suites test token issuance and single-use enforcement.

Tested with PHP 8.5.10 and Laravel Framework 13.44.1: **6 tests and 25
assertions pass**. Laravel Pint also passes.
