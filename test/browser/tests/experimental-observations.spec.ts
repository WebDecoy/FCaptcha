import { test, expect } from '../fixtures';

test.beforeEach(async ({ page }) => {
  await page.goto('/health');
  await page.addScriptTag({ url: '/fcaptcha.js' });
});

for (const reducedMotion of ['reduce', 'no-preference'] as const) {
  test(`normal animation measurements stay neutral with reduced motion ${reducedMotion}`, async ({ page }) => {
    await page.emulateMedia({ reducedMotion });
    const result = await page.evaluate(() => {
      const before = document.body.childElementCount;
      const probe = (window as any).FCaptcha.getSignals().environmental.animationConsistency;
      return { probe, remaining: document.body.childElementCount - before,
        animations: document.getAnimations().length };
    });
    const realm = { status: 'ok', specified: [1000, 1000, 1000],
      durations: Array.from({ length: 3 }, () => [1000, 1000, 1000, 1000]) };
    expect(result).toEqual({ probe: { version: 1, main: realm, iframe: realm }, remaining: 0, animations: 0 });
  });
}

test('missing animation APIs are unsupported, with no elements left behind', async ({ page }) => {
  const result = await page.evaluate(() => {
    const session = (window as any).FCaptcha.invisible({ autoScore: false });
    const before = document.body.childElementCount;
    const original = Element.prototype.animate;
    try {
      (Element.prototype as any).animate = undefined;
      const probe = session.environmental._checkAnimationConsistency();
      return { status: probe.main.status, remaining: document.body.childElementCount - before };
    } finally { Element.prototype.animate = original; session.destroy(); }
  });
  expect(result).toEqual({ status: 'unsupported', remaining: 0 });
});

test('an unavailable iframe is unknown data, not a failed verification', async ({ page }) => {
  const result = await page.evaluate(() => {
    const session = (window as any).FCaptcha.invisible({ autoScore: false });
    const original = document.createElement;
    const before = document.body.childElementCount;
    document.createElement = function (tag: string, ...args: any[]) {
      if (tag === 'iframe') throw new Error('frame blocked');
      return original.call(this, tag, ...args);
    } as typeof document.createElement;
    try {
      const probe = session.environmental._checkAnimationConsistency();
      return { main: probe.main.status, frame: probe.iframe.status, remaining: document.body.childElementCount - before };
    } finally { document.createElement = original; session.destroy(); }
  });
  expect(result).toEqual({ main: 'ok', frame: 'error', remaining: 0 });
});

test('timing API errors cancel animations and clean up the probe', async ({ page }) => {
  const result = await page.evaluate(() => {
    const session = (window as any).FCaptcha.invisible({ autoScore: false });
    const original = AnimationEffect.prototype.getComputedTiming;
    const before = document.body.childElementCount;
    AnimationEffect.prototype.getComputedTiming = () => { throw new Error('unavailable'); };
    try {
      const probe = session.environmental._checkAnimationConsistency();
      return { status: probe.main.status, remaining: document.body.childElementCount - before,
        animations: document.getAnimations().length };
    } finally { AnimationEffect.prototype.getComputedTiming = original; session.destroy(); }
  });
  expect(result).toEqual({ status: 'error', remaining: 0, animations: 0 });
});
