import { test, expect, Page } from '@playwright/test';

test.setTimeout(60_000);

/**
 * Renders the widget in a real browser and reads back what a user would see.
 *
 * The point of doing this in a browser rather than unit-testing the resolver is
 * that most of what can go wrong here is DOM-shaped: whether `<html lang>` is
 * actually consulted, whether `dir="rtl"` reaches the element, whether the
 * accessible name resolves. None of that is observable from the string table.
 *
 * Served through a route interception at a real http://localhost path rather
 * than page.setContent(), for the reason pow.spec.ts documents: about:blank has
 * no crypto.subtle, which the widget's SHA-256 helper needs.
 */
async function renderWidget(
  page: Page,
  opts: { htmlLang?: string; dataLang?: string; renderOptions?: string } = {}
) {
  const htmlLang = opts.htmlLang ? ` lang="${opts.htmlLang}"` : '';
  const dataLang = opts.dataLang ? ` data-lang="${opts.dataLang}"` : '';
  const renderOptions = opts.renderOptions ?? '{ siteKey: "test" }';

  await page.route('http://localhost:3000/__fcaptcha_i18n__', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><html${htmlLang}><head><title>i18n</title></head>
        <body>
          <div id="captcha"${dataLang}></div>
          <script src="http://localhost:3000/fcaptcha.js"></script>
          <script>
            window.__ready = false;
            FCaptcha.configure({ serverUrl: 'http://localhost:3000' });
            FCaptcha.render('captcha', ${renderOptions});
            window.__ready = true;
          </script>
        </body></html>`,
    });
  });

  await page.goto('http://localhost:3000/__fcaptcha_i18n__');
  await page.waitForFunction(() => (window as any).__ready === true);
  await page.waitForSelector('.fcaptcha-label');
}

const label = (page: Page) => page.locator('.fcaptcha-label').innerText();
const widget = (page: Page) => page.locator('.fcaptcha-widget');

test('an explicit lang option wins over everything else', async ({ page }) => {
  await renderWidget(page, {
    htmlLang: 'de',
    dataLang: 'es',
    renderOptions: '{ siteKey: "test", lang: "fr" }',
  });
  expect(await label(page)).toBe('Je ne suis pas un robot');
});

test('data-lang is used when no option is given', async ({ page }) => {
  await renderWidget(page, { htmlLang: 'de', dataLang: 'ja' });
  expect(await label(page)).toBe('私はロボットではありません');
});

test('<html lang> is used when nothing more specific is set', async ({ page }) => {
  // The page outranks the browser deliberately: a widget should match the form
  // around it rather than the reader's locale.
  await renderWidget(page, { htmlLang: 'pl' });
  expect(await label(page)).toBe('Nie jestem robotem');
});

test('a region tag falls back to its base language', async ({ page }) => {
  await renderWidget(page, { htmlLang: 'de-AT' });
  expect(await label(page)).toBe('Ich bin kein Roboter');
});

test('a region tag with its own entry is preferred over the base', async ({ page }) => {
  await renderWidget(page, { htmlLang: 'pt-BR' });
  expect(await label(page)).toBe('Não sou um robô');
  // pt-BR and pt share the resting label but differ elsewhere; assert the tag
  // actually resolved rather than that the shared string happens to match.
  await expect(widget(page)).toHaveAttribute('lang', 'pt-br');
});

test('an unknown language falls back to English rather than rendering empty', async ({ page }) => {
  await renderWidget(page, { htmlLang: 'tlh' });
  expect(await label(page)).toBe("I'm not a robot");
});

test('the strings option overrides individual keys', async ({ page }) => {
  await renderWidget(page, {
    renderOptions: '{ siteKey: "test", lang: "en", strings: { label: "Prove you are human" } }',
  });
  expect(await label(page)).toBe('Prove you are human');
});

test('the strings option can supply a language we do not ship', async ({ page }) => {
  await renderWidget(page, {
    renderOptions: '{ siteKey: "test", lang: "is", strings: { label: "Ég er ekki vélmenni" } }',
  });
  expect(await label(page)).toBe('Ég er ekki vélmenni');
});

test('caller-supplied strings are escaped, not injected', async ({ page }) => {
  // strings may come from a CMS or locale file; interpolating it raw would make
  // the widget an XSS vector on the form it protects.
  await renderWidget(page, {
    renderOptions:
      '{ siteKey: "test", lang: "en", strings: { label: "<img src=x onerror=window.__xss=1>" } }',
  });
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
  expect(await page.locator('.fcaptcha-label img').count()).toBe(0);
  expect(await label(page)).toContain('<img');
});

test('RTL languages set dir on the widget root', async ({ page }) => {
  await renderWidget(page, { htmlLang: 'ar' });
  expect(await label(page)).toBe('لست روبوتًا');
  await expect(widget(page)).toHaveAttribute('dir', 'rtl');
  // The row has to flip too, or the checkbox sits on the wrong side.
  const direction = await widget(page).evaluate(
    (el) => getComputedStyle(el).flexDirection
  );
  expect(direction).toBe('row-reverse');
});

test('LTR languages do not set dir', async ({ page }) => {
  await renderWidget(page, { htmlLang: 'fr' });
  expect(await widget(page).getAttribute('dir')).toBeNull();
});

test('the widget root carries its resolved lang, for pronunciation', async ({ page }) => {
  await renderWidget(page, { htmlLang: 'ru' });
  await expect(widget(page)).toHaveAttribute('lang', 'ru');
});

test('the checkbox has an accessible name', async ({ page }) => {
  // It previously had none: the label is a sibling span rather than a wrapping
  // <label>, so the control announced as "checkbox, not checked" with no name.
  await renderWidget(page, { htmlLang: 'it' });
  const checkbox = page.getByRole('checkbox');
  await expect(checkbox).toHaveAccessibleName('Non sono un robot');
});

test('the label is a live region so state changes are announced', async ({ page }) => {
  await renderWidget(page);
  await expect(page.locator('.fcaptcha-label')).toHaveAttribute('aria-live', 'polite');
});

test('the widget is served declaring UTF-8', async ({ page }) => {
  // Without a charset a classic script is decoded using the *document's*
  // encoding, so every non-ASCII translation renders as mojibake on any page
  // that is not already UTF-8. Node got this right via Express; Go and Python
  // both served a bare application/javascript until the translations made it
  // matter.
  const res = await page.request.get('http://localhost:3000/fcaptcha.js');
  expect((res.headers()['content-type'] || '').toLowerCase()).toContain('charset=utf-8');
});

test('every shipped language renders a non-empty label', async ({ page }) => {
  await renderWidget(page);
  const langs: string[] = await page.evaluate(() => (window as any).FCaptcha.languages());
  expect(langs.length).toBeGreaterThan(30);

  const empties = await page.evaluate((all: string[]) => {
    const bad: string[] = [];
    for (const lang of all) {
      const el = document.createElement('div');
      document.body.appendChild(el);
      (window as any).FCaptcha.render(el, { siteKey: 'test', lang });
      const text = (el.querySelector('.fcaptcha-label') as HTMLElement | null)?.innerText ?? '';
      if (!text.trim()) bad.push(lang);
      el.remove();
    }
    return bad;
  }, langs);

  expect(empties).toEqual([]);
});
