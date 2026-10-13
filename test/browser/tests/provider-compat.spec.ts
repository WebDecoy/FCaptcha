import { test, expect, Page } from '../fixtures';

/**
 * The widget served on Turnstile, hCaptcha and reCAPTCHA script paths.
 *
 * Apps that support one of those providers and let an admin change its script
 * and siteverify URLs call the provider's global (turnstile.render,
 * hcaptcha.getResponse, grecaptcha.reset) and read the provider's form field.
 * Served on that provider's path, the widget answers to both.
 */

async function load(page: Page, script: string, body: string, head = '') {
  await page.route('http://localhost:3000/__provider_compat__', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><html><head>${head}</head><body>${body}
        <script src="http://localhost:3000${script}"></script>
      </body></html>`,
    })
  );
  await page.goto('http://localhost:3000/__provider_compat__');
}

/** Drive the first widget into its verified state without a real verification. */
const verify = (page: Page) =>
  page.evaluate(() => {
    const F = (window as any).FCaptcha;
    F.widgets.get(Array.from(F.widgets.keys())[0] as string)._showSuccess('synthetic-token');
  });

const fields = (page: Page) =>
  page.evaluate(() => Object.fromEntries(new FormData(document.querySelector('form')!)));

test('Turnstile: auto-renders .cf-turnstile and fills cf-turnstile-response', async ({ page }) => {
  await load(page, '/turnstile/v0/api.js', `<form>
    <div class="cf-turnstile" data-sitekey="compat-test" data-callback="onToken"></div>
  </form><script>window.onToken = (t) => { window.__token = t; };</script>`);
  await page.waitForSelector('.fcaptcha-checkbox');

  expect(await page.evaluate(() => (window as any).FCaptcha.serverUrl)).toBe('http://localhost:3000');
  await verify(page);
  expect(await fields(page)).toEqual({ 'cf-turnstile-response': 'synthetic-token' });
  expect(await page.evaluate(() => (window as any).__token)).toBe('synthetic-token');
  expect(await page.evaluate(() => (window as any).turnstile.getResponse())).toBe('synthetic-token');

  await page.evaluate(() => (window as any).turnstile.reset());
  expect(await fields(page)).toEqual({ 'cf-turnstile-response': '' });
});

test('hCaptcha: explicit render from onload fills both response fields', async ({ page }) => {
  await load(page, '/1/api.js?render=explicit&onload=init', `<form><div id="box"></div></form>
    <script>
      window.init = () => { window.__id = hcaptcha.render('box', { sitekey: 'compat-test' }); };
    </script>`);
  await page.waitForSelector('.fcaptcha-checkbox');

  await verify(page);
  expect(await fields(page)).toEqual({
    'h-captcha-response': 'synthetic-token',
    'g-recaptcha-response': 'synthetic-token',
  });
  expect(await page.evaluate(() => (window as any).hcaptcha.getResponse((window as any).__id)))
    .toBe('synthetic-token');

  await page.evaluate(() => (window as any).hcaptcha.reset((window as any).__id));
  expect(await fields(page)).toEqual({ 'h-captcha-response': '', 'g-recaptcha-response': '' });
});

test('reCAPTCHA: auto-renders .g-recaptcha with numeric widget ids', async ({ page }) => {
  await load(page, '/recaptcha/api.js', `<form>
    <div class="g-recaptcha" data-sitekey="compat-test"></div>
  </form>`);
  await page.waitForSelector('.fcaptcha-checkbox');

  await verify(page);
  expect(await fields(page)).toEqual({ 'g-recaptcha-response': 'synthetic-token' });
  expect(await page.evaluate(() => (window as any).grecaptcha.getResponse(0))).toBe('synthetic-token');
  expect(await page.evaluate(() => (window as any).grecaptcha.getResponse())).toBe('synthetic-token');
});

test('served as /fcaptcha.js it installs no provider globals', async ({ page }) => {
  await load(page, '/fcaptcha.js', `<form><div data-fcaptcha="compat-test"></div></form>`);
  await page.waitForSelector('.fcaptcha-checkbox');

  expect(await page.evaluate(() => ({
    turnstile: typeof (window as any).turnstile,
    hcaptcha: typeof (window as any).hcaptcha,
    grecaptcha: typeof (window as any).grecaptcha,
  }))).toEqual({ turnstile: 'undefined', hcaptcha: 'undefined', grecaptcha: 'undefined' });
});

test('an existing provider global is left alone', async ({ page }) => {
  await load(page, '/turnstile/v0/api.js', `<form></form>`,
    `<script>window.turnstile = { real: true };</script>`);
  await page.waitForFunction(() => (window as any).FCaptcha);

  expect(await page.evaluate(() => (window as any).turnstile.real)).toBe(true);
});
