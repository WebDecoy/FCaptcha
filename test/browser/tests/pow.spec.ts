import { test, expect, Page } from '@playwright/test';

test.setTimeout(60_000);

test.beforeEach(async ({ page }, testInfo) => {
  page.on('console', (msg) => {
    // eslint-disable-next-line no-console
    console.log(`  [page:${msg.type()}] ${msg.text()}`);
  });
  page.on('pageerror', (err) => {
    // eslint-disable-next-line no-console
    console.log(`  [page:error] ${err.message}`);
  });
  page.on('request', (req) => {
    if (req.url().includes('/api/')) {
      // eslint-disable-next-line no-console
      console.log(`  [page:req ] ${req.method()} ${req.url()}`);
    }
  });
  page.on('response', (resp) => {
    if (resp.url().includes('/api/')) {
      // eslint-disable-next-line no-console
      console.log(`  [page:resp] ${resp.status()} ${resp.url()}`);
    }
  });
});

// Loads a minimal page that pulls fcaptcha.js from the local server. We
// instrument window.Worker before the script runs so the test can assert how
// many PoW workers were spawned.
//
// The page is served via a Playwright route interception at a real
// http://localhost path — page.setContent() leaves the document at
// about:blank where Chromium does not expose crypto.subtle, which the
// widget's SHA-256 helper depends on. Localhost is treated as a secure
// context so subtle works there.
async function loadWidgetPage(page: Page, overrides: { hardwareConcurrency?: number } = {}) {
  await page.route('http://localhost:3000/__fcaptcha_test__', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: `<!doctype html><html><head><title>fcaptcha browser test</title></head>
        <body>
          <div id="captcha"></div>
          <script src="http://localhost:3000/fcaptcha.js"></script>
        </body></html>`,
    });
  });

  await page.addInitScript((opts: { hardwareConcurrency?: number }) => {
    (window as any).__workerStats = { created: 0, terminated: 0 };
    const RealWorker = window.Worker;
    (window as any).Worker = class extends RealWorker {
      constructor(...args: any[]) {
        // @ts-expect-error spread
        super(...args);
        (window as any).__workerStats.created++;
        const realTerminate = this.terminate.bind(this);
        this.terminate = function () {
          (window as any).__workerStats.terminated++;
          realTerminate();
        };
      }
    };

    if (opts.hardwareConcurrency !== undefined) {
      Object.defineProperty(navigator, 'hardwareConcurrency', {
        value: opts.hardwareConcurrency,
        configurable: true,
      });
    }
  }, overrides);

  await page.goto('http://localhost:3000/__fcaptcha_test__');
  await page.waitForFunction(() => !!(window as any).FCaptcha);

  await page.evaluate(() => {
    (window as any).FCaptcha.configure({ serverUrl: 'http://localhost:3000' });
  });
}

test.describe('parallel PoW solver', () => {
  test('produces a solution the server accepts', async ({ page }) => {
    await loadWidgetPage(page);

    const result = await page.evaluate(async () => {
      const r = await (window as any).FCaptcha.execute('test-site-key', { action: 'login' });
      return { token: r?.token, score: r?.score, success: r?.success, reason: r?.reason };
    });

    // What this test is for is the solver, so that is what it asserts.
    //
    // It used to assert a token came back, which quietly asked the captcha to
    // fail at its job: this is a Playwright-driven Chromium, so
    // navigator.webdriver is true, and that detection is Dispositive — the score
    // floors at 0.9 and the token is correctly withheld. The assertion passed
    // only until the floor shipped, and nothing noticed because these tests run
    // nowhere in CI.
    //
    // A withheld token therefore proves nothing either way. What does is that
    // the server never rejected the proof of work: the solution the parallel
    // solver produced verified against the challenge it was issued.
    expect(result.reason, 'server rejected the solver output').not.toBe('pow_not_satisfied');
    expect(typeof result.score, 'no score returned — the request did not complete').toBe('number');
  });

  test('spawns multiple workers under default hardwareConcurrency', async ({ page }) => {
    await loadWidgetPage(page);

    await page.evaluate(async () => {
      await (window as any).FCaptcha.execute('test-site-key', { action: 'multi' });
    });

    const stats = await page.evaluate(() => (window as any).__workerStats);
    const cores = await page.evaluate(() => navigator.hardwareConcurrency);
    const expectedThreads = Math.max(1, Math.floor(cores / 2));

    // PoW spawns one worker per thread. There may be other workers in the
    // widget too (e.g. fingerprint consistency check), so use >=.
    expect(stats.created).toBeGreaterThanOrEqual(expectedThreads);
    if (cores >= 4) {
      expect(stats.created).toBeGreaterThan(1);
    }
  });

  test('falls back to a single worker when hardwareConcurrency=1', async ({ page }) => {
    await loadWidgetPage(page, { hardwareConcurrency: 1 });

    const beforeStats = await page.evaluate(() => ({ ...(window as any).__workerStats }));

    await page.evaluate(async () => {
      await (window as any).FCaptcha.execute('test-site-key', { action: 'single' });
    });

    const afterStats = await page.evaluate(() => (window as any).__workerStats);
    const powWorkersCreated = afterStats.created - beforeStats.created;

    // Exactly one PoW worker (no parallel fan-out at hardwareConcurrency=1).
    // Allow a small upper bound to absorb any non-PoW worker the widget
    // might also spin up during execute().
    expect(powWorkersCreated).toBeGreaterThanOrEqual(1);
    expect(powWorkersCreated).toBeLessThanOrEqual(2);
  });

  test('terminates all workers after solve completes', async ({ page }) => {
    await loadWidgetPage(page);

    await page.evaluate(async () => {
      await (window as any).FCaptcha.execute('test-site-key', { action: 'cleanup' });
    });

    // Give the runtime a tick to flush termination.
    await page.waitForTimeout(50);

    const stats = await page.evaluate(() => (window as any).__workerStats);
    expect(stats.terminated).toBeGreaterThanOrEqual(stats.created - 1); // -1 tolerates one transient worker
  });
});
