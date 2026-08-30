import { test, expect, Page } from '@playwright/test';

test.setTimeout(60_000);

/**
 * Challenge refresh.
 *
 * The widget fetches a PoW challenge when it loads, and the server only holds
 * that challenge for five minutes. Nothing re-fetched it: `_solve` asked for a
 * challenge only when it had none at all, so a page open longer than the expiry
 * — a contact form filled in slowly, a tab restored hours later — submitted a
 * solution to a challenge the server no longer had. The server refused it, the
 * widget showed "Verification failed", and because the failure path left the
 * spent challenge in place, every retry failed the same way until a reload.
 *
 * Neither half is a scoring decision: the visitor is a person and scores like
 * one. The server said so — `recommendation: allow` on the very request whose
 * token it withheld.
 */

async function loadWidget(page: Page) {
  await page.route('http://localhost:3000/__challenge_refresh__', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><html><body>
        <div id="captcha"></div>
        <script src="http://localhost:3000/fcaptcha.js"></script>
        <script>
          FCaptcha.configure({serverUrl: 'http://localhost:3000'});
          FCaptcha.render('captcha', {siteKey: 'challenge-refresh-test'});
          window.__widget = function () {
            var F = window.FCaptcha;
            return F.widgets.get(Array.from(F.widgets.keys())[0]);
          };
        </script>
      </body></html>`,
    })
  );
  await page.goto('http://localhost:3000/__challenge_refresh__');
  await page.waitForSelector('.fcaptcha-checkbox');
  // The first challenge is fetched in the background when the widget renders.
  await page.waitForFunction(() => !!(window as any).__widget().powManager.challenge);
}

const challengeId = (page: Page) =>
  page.evaluate(() => (window as any).__widget().powManager.challenge?.challengeId ?? null);

/** Every /api/pow/challenge the page asks for, in order. */
function recordChallengeFetches(page: Page): string[] {
  const fetched: string[] = [];
  page.on('request', (req) => {
    if (req.url().includes('/api/pow/challenge')) fetched.push(req.url());
  });
  return fetched;
}

test.describe('PoW challenge refresh', () => {
  test('replaces a challenge that expired while the page sat open', async ({ page }) => {
    const fetched = recordChallengeFetches(page);
    await loadWidget(page);

    const first = await challengeId(page);
    expect(fetched.length, 'one challenge fetched on load').toBe(1);

    // What a page left open past the server's five-minute window looks like
    // from the client: the challenge it holds is no longer one the server has.
    await page.evaluate(() => {
      (window as any).__widget().powManager.challenge.expiresAt = Date.now() - 60_000;
    });
    expect(await page.evaluate(() => (window as any).__widget().powManager.challengeExpired())).toBe(true);

    const solved = await page.evaluate(async () => {
      const solution = await (window as any)
        .__widget()
        .powManager.solveWithSignalsHash('challenge-refresh-test', 'deadbeef');
      return solution.challengeId;
    });

    expect(fetched.length, 'the stale challenge must be replaced').toBe(2);
    expect(solved, 'the solution must be for the new challenge').not.toBe(first);
    expect(solved).toBe(await challengeId(page));
    expect(
      await page.evaluate(() => !!(window as any).__widget().powManager.challenge.local),
      'the replacement must come from the server, not the local fallback'
    ).toBe(false);
  });

  test('keeps a challenge that still has expiry to spare', async ({ page }) => {
    const fetched = recordChallengeFetches(page);
    await loadWidget(page);

    const first = await challengeId(page);
    expect(await page.evaluate(() => (window as any).__widget().powManager.challengeExpired())).toBe(false);

    await page.evaluate(() =>
      (window as any).__widget().powManager.solveWithSignalsHash('challenge-refresh-test', 'deadbeef')
    );

    expect(fetched.length, 'a live challenge must not be thrown away').toBe(1);
    expect(await challengeId(page)).toBe(first);
  });

  test('a failed attempt leaves a fresh challenge ready for the retry', async ({ page }) => {
    await loadWidget(page);
    const first = await challengeId(page);

    // The no-message path is the one the servers actually take: they answer
    // success:false with no reason attached.
    await page.evaluate(() => (window as any).__widget()._showFailure(undefined));

    await page.waitForFunction(
      (before) => {
        const challenge = (window as any).__widget().powManager.challenge;
        return !!challenge && challenge.challengeId !== before;
      },
      first
    );

    expect(
      await page.evaluate(() => (window as any).__widget().powManager.solution),
      'the spent solution must not survive into the retry'
    ).toBeNull();
  });
});
