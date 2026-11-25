import { test, expect, Page } from '../fixtures';

test.setTimeout(60_000);

/**
 * Network change between challenge and submit.
 *
 * The widget fetches its proof-of-work challenge when it renders, and the
 * server binds that challenge to the visitor's network (an IPv4 /24 or an
 * IPv6 /56). A visitor who submits from a different network, because a phone
 * moved from wifi to cellular or a dual-stack browser opened its next
 * connection over the other address family, was refused with
 * `challenge_network_mismatch` and shown "Verification failed".
 *
 * The widget now retries once with a fresh challenge, which the server issues
 * to the network the visitor is on now. It retries only when the proof of
 * work was withheld, and only once.
 */

// Documentation ranges, one per simulated network.
const HOME = '203.0.113.7';
const CELLULAR = '198.51.100.9';

/** Send each request from the network `pick` names; record what was sent. */
async function routeNetworks(page: Page, pick: (kind: 'challenge' | 'submit', n: number) => string) {
  const seen = { challenge: 0, submit: 0 };
  const submits: any[] = [];
  const forward = (kind: 'challenge' | 'submit') => async (route: any) => {
    const ip = pick(kind, seen[kind]++);
    const response = await route.fetch({ headers: { ...route.request().headers(), 'x-forwarded-for': ip } });
    if (kind === 'submit') submits.push(await response.json());
    await route.fulfill({ response });
  };
  await page.route('**/api/pow/challenge*', forward('challenge'));
  await page.route('**/api/verify', forward('submit'));
  await page.route('**/api/score', forward('submit'));
  return { seen, submits };
}

const mismatched = (result: any) =>
  (result.detections || []).some((d: any) => d.reason === 'PoW verification failed: challenge_network_mismatch');

async function loadWidget(page: Page) {
  await page.route('http://localhost:3000/__network_change__', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><html><body>
        <div id="captcha"></div>
        <script src="http://localhost:3000/fcaptcha.js"></script>
        <script>
          FCaptcha.configure({serverUrl: 'http://localhost:3000'});
          FCaptcha.render('captcha', {siteKey: 'network-change-test'});
          window.__widget = function () {
            var F = window.FCaptcha;
            return F.widgets.get(Array.from(F.widgets.keys())[0]);
          };
        </script>
      </body></html>`,
    })
  );
  await page.goto('http://localhost:3000/__network_change__');
  await page.waitForSelector('.fcaptcha-checkbox');
  await page.waitForFunction(() => !!(window as any).__widget().powManager.challenge);
}

const settled = (page: Page) =>
  page.waitForFunction(() => !(window as any).__widget().checkbox.classList.contains('loading'));

test.describe('network change between challenge and submit', () => {
  test('the widget retries once with a challenge from the new network', async ({ page }) => {
    // Loaded at home, clicked after switching to cellular.
    const net = await routeNetworks(page, (kind, n) => (kind === 'challenge' && n === 0 ? HOME : CELLULAR));
    await loadWidget(page);
    await page.click('.fcaptcha-checkbox');
    await settled(page);

    expect(net.submits.length, 'submitted twice').toBe(2);
    expect(mismatched(net.submits[0]), 'the first submit hit the mismatch').toBe(true);
    expect(mismatched(net.submits[1]), 'the retry did not').toBe(false);
  });

  test('a persistent mismatch is retried once, not looped', async ({ page }) => {
    const net = await routeNetworks(page, (kind) => (kind === 'challenge' ? HOME : CELLULAR));
    await loadWidget(page);
    await page.click('.fcaptcha-checkbox');
    await settled(page);

    expect(net.submits.length).toBe(2);
    expect(net.submits.every(mismatched)).toBe(true);
    expect(await page.evaluate(() => (window as any).__widget().verified)).toBe(false);
  });

  test('invisible scoring retries the same way', async ({ page }) => {
    const net = await routeNetworks(page, (kind, n) => (kind === 'challenge' && n === 0 ? HOME : CELLULAR));
    await page.goto('/health');
    await page.addScriptTag({ url: '/fcaptcha.js' });
    await page.evaluate(async () => {
      const session = (window as any).FCaptcha.invisible({ autoScore: false, minCollectionTime: 0 });
      // Hold a challenge issued on the first network, as a prefetch would.
      await session.powManager.ensureChallenge('network-change-test');
      try { await session.execute('submit'); } finally { session.destroy(); }
    });

    // /api/score returns no detections, so the reason is all there is to see.
    expect(net.submits.length).toBe(2);
    expect(net.submits[0].reason).toBe('pow_not_satisfied');
    expect(net.submits[1].reason).not.toBe('pow_not_satisfied');
  });

  test('a refusal that is not about the proof of work is not retried', async ({ page }) => {
    let submits = 0;
    await page.route('**/api/verify', (route) => {
      submits++;
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: false, score: 0.1, recommendation: 'allow', reason: 'hostname_not_allowed' }),
      });
    });
    await loadWidget(page);
    await page.click('.fcaptcha-checkbox');
    await settled(page);
    expect(submits).toBe(1);
  });
});
