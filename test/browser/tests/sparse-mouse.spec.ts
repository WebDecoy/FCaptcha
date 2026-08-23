import { test, expect, Page } from '@playwright/test';

test.setTimeout(60_000);

async function loadWidget(page: Page) {
  await page.route('http://localhost:3000/__sparse_mouse__', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><html><body>
        <div id="captcha"></div>
        <script src="http://localhost:3000/fcaptcha.js"></script>
        <script>
          FCaptcha.configure({serverUrl: 'http://localhost:3000'});
          FCaptcha.render('captcha', {siteKey: 'sparse-mouse-test'});
        </script>
      </body></html>`,
    })
  );

  await page.goto('http://localhost:3000/__sparse_mouse__');
  await page.waitForSelector('.fcaptcha-checkbox');
}

test('preserves observed counts for a sub-threshold mouse trace', async ({ page }) => {
  await loadWidget(page);

  const verifyRequest = page.waitForRequest((request) =>
    request.method() === 'POST' && request.url().endsWith('/api/verify')
  );

  await page.evaluate(() => {
    // These synthetic events test serialization only. Their verdict says
    // nothing about human false positives: Playwright should be detected.
    for (let i = 0; i < 9; i++) {
      document.dispatchEvent(new MouseEvent('mousemove', {
        bubbles: true,
        clientX: 40 + i * 3,
        clientY: 80 + i * 2,
      }));
    }

    const checkbox = document.querySelector('.fcaptcha-checkbox');
    checkbox?.dispatchEvent(new MouseEvent('click', {
      bubbles: true,
      clientX: 64,
      clientY: 96,
    }));
  });

  const body = (await verifyRequest).postDataJSON();
  expect(body.signals.behavioral.totalPoints).toBe(9);
  expect(body.signals.behavioral.approachPoints).toBe(9);
});
