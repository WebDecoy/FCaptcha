import { test, expect, Page } from '../fixtures';

/**
 * The hidden input that carries the token in the enclosing form.
 *
 * Before it existed, a checkbox widget inside a <form> submitted nothing: every
 * integration needed a hidden field and a callback to copy the token into it,
 * which Turnstile, reCAPTCHA and hCaptcha all do for you.
 */

async function load(page: Page, body: string) {
  await page.route('http://localhost:3000/__response_field__', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><html><body>${body}
        <script src="http://localhost:3000/fcaptcha.js"></script>
      </body></html>`,
    })
  );
  await page.goto('http://localhost:3000/__response_field__');
  await page.waitForSelector('.fcaptcha-checkbox');
}

/** Drive the first widget into, and out of, its verified state. */
const widget = (page: Page, call: string) =>
  page.evaluate((call) => {
    const F = (window as any).FCaptcha;
    const w = F.widgets.get(Array.from(F.widgets.keys())[0] as string);
    if (call === 'verify') w._showSuccess('synthetic-token');
    if (call === 'reset') w.reset();
  }, call);

const posted = (page: Page) =>
  page.evaluate(() => {
    const data = new FormData(document.querySelector('form')!);
    return data.getAll('fcaptcha_token');
  });

test('a widget inside a form submits its token with it, and reset clears it', async ({ page }) => {
  await load(page, `<form><div data-fcaptcha="response-field-test"></div></form>`);

  expect(await posted(page)).toEqual(['']);
  await widget(page, 'verify');
  expect(await posted(page)).toEqual(['synthetic-token']);
  await widget(page, 'reset');
  expect(await posted(page)).toEqual(['']);
});

test('a form that already has the field gets no duplicate', async ({ page }) => {
  await load(page, `<form>
    <input type="hidden" name="fcaptcha_token" id="mine">
    <div data-fcaptcha="response-field-test"></div>
  </form>`);

  await widget(page, 'verify');
  // Only the integrator's own field, which their callback is responsible for.
  expect(await posted(page)).toEqual(['']);
});

test('data-response-field="false" turns it off', async ({ page }) => {
  await load(page, `<form><div data-fcaptcha="response-field-test" data-response-field="false"></div></form>`);

  await widget(page, 'verify');
  expect(await posted(page)).toEqual([]);
});

test('data-response-field-name renames it', async ({ page }) => {
  await load(page, `<form><div data-fcaptcha="response-field-test" data-response-field-name="captcha"></div></form>`);

  await widget(page, 'verify');
  const value = await page.evaluate(() =>
    new FormData(document.querySelector('form')!).get('captcha'));
  expect(value).toBe('synthetic-token');
  expect(await posted(page)).toEqual([]);
});
