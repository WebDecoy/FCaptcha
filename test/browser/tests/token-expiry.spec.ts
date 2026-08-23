import { test, expect, Page } from '@playwright/test';

test.setTimeout(60_000);

/**
 * Token expiry, and the expiredCallback that goes with it.
 *
 * All three servers reject a token older than 300s. Until now the widget kept
 * showing "verified" past that point and never called expiredCallback — an
 * option present in the public options object since the first release but
 * invoked nowhere. A form left open for five minutes therefore failed on
 * submit with nothing for the integrator to react to.
 *
 * Clock is virtualised: waiting out the real interval would put five minutes
 * into the suite for one assertion.
 */

async function loadWidget(page: Page) {
  await page.route('http://localhost:3000/__token_expiry__', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><html><body>
        <div id="captcha"></div>
        <script src="http://localhost:3000/fcaptcha.js"></script>
        <script>
          window.__expired = 0;
          window.__expiredEvents = 0;
          FCaptcha.configure({serverUrl: 'http://localhost:3000'});
          FCaptcha.render('captcha', {
            siteKey: 'token-expiry-test',
            expiredCallback: function () { window.__expired++; }
          });
          document.getElementById('captcha')
            .addEventListener('fcaptcha:expired', function () { window.__expiredEvents++; });
        </script>
      </body></html>`,
    })
  );
  await page.goto('http://localhost:3000/__token_expiry__');
  await page.waitForSelector('.fcaptcha-checkbox');
}

/** Drive the widget into its verified state without a real verification. */
const markVerified = (page: Page) =>
  page.evaluate(() => {
    const F = (window as any).FCaptcha;
    const w = F.widgets.get(Array.from(F.widgets.keys())[0] as string);
    w._showSuccess('synthetic-token-for-expiry-test');
  });

const state = (page: Page) =>
  page.evaluate(() => {
    const F = (window as any).FCaptcha;
    const w = F.widgets.get(Array.from(F.widgets.keys())[0] as string);
    return {
      verified: w.verified,
      token: w.token,
      expiredCalls: (window as any).__expired,
      expiredEvents: (window as any).__expiredEvents,
    };
  });

test.describe('token expiry', () => {
  test('expires the token, resets the widget and fires expiredCallback', async ({ page }) => {
    await page.clock.install();
    await loadWidget(page);
    await markVerified(page);

    const held = await state(page);
    expect(held.verified).toBe(true);
    expect(held.token).toBe('synthetic-token-for-expiry-test');
    expect(held.expiredCalls).toBe(0);

    // Just short of the widget's expiry (300s less a 15s margin): still valid.
    await page.clock.runFor(280_000);
    const before = await state(page);
    expect(before.verified, 'must not expire early').toBe(true);
    expect(before.expiredCalls).toBe(0);

    // Past it.
    await page.clock.runFor(10_000);
    const after = await state(page);
    expect(after.verified, 'widget must reset itself').toBe(false);
    expect(after.token, 'the stale token must be dropped').toBeNull();
    expect(after.expiredCalls, 'expiredCallback must fire exactly once').toBe(1);
    expect(after.expiredEvents, 'fcaptcha:expired must be dispatched').toBe(1);
  });

  test('a manual reset cancels the pending expiry', async ({ page }) => {
    await page.clock.install();
    await loadWidget(page);
    await markVerified(page);

    await page.evaluate(() => {
      const F = (window as any).FCaptcha;
      F.widgets.get(Array.from(F.widgets.keys())[0] as string).reset();
    });

    await page.clock.runFor(400_000);
    const s = await state(page);
    // The widget was already reset by hand; firing expiredCallback afterwards
    // would report an expiry the integrator had already handled.
    expect(s.expiredCalls, 'no expiry callback after a manual reset').toBe(0);
  });
});
