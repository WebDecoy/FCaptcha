import { test, expect } from '../fixtures';

const TEST_URL = 'http://localhost:3000/__canvas_stability__';

const PAGE = `<!doctype html><html><body>
  <script src="http://localhost:3000/fcaptcha.js"></script>
</body></html>`;

test('canvas readback is stable in stock Chromium', async ({ page }) => {
  await page.route(TEST_URL, (route) => route.fulfill({
    status: 200,
    contentType: 'text/html; charset=utf-8',
    body: PAGE,
  }));
  await page.goto(TEST_URL);
  await page.waitForFunction(() => (window as any).FCaptcha !== undefined);

  const canvas = await page.evaluate(() =>
    (window as any).FCaptcha.getSignals().environmental.canvasHash
  );
  expect(canvas.supported).toBe(true);
  expect(canvas.canvasStable).toBe(true);
});

test('per-read privacy noise is reported but remains content-free', async ({ page }) => {
  await page.addInitScript(() => {
    const original = HTMLCanvasElement.prototype.toDataURL;
    let reads = 0;
    HTMLCanvasElement.prototype.toDataURL = function (...args) {
      const value = original.apply(this, args as Parameters<typeof original>);
      reads++;
      return reads % 2 === 0 ? `${value}#privacy-noise-${reads}` : value;
    };
  });
  await page.route(TEST_URL, (route) => route.fulfill({
    status: 200,
    contentType: 'text/html; charset=utf-8',
    body: PAGE,
  }));
  await page.goto(TEST_URL);
  await page.waitForFunction(() => (window as any).FCaptcha !== undefined);

  const canvas = await page.evaluate(() =>
    (window as any).FCaptcha.getSignals().environmental.canvasHash
  );
  expect(canvas.supported).toBe(true);
  expect(canvas.canvasStable).toBe(false);
  expect(canvas).not.toHaveProperty('dataUrl');
  expect(canvas).not.toHaveProperty('repeatedDataUrl');
});
