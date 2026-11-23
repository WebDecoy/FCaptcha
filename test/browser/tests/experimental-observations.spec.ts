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

test('input collector summarizes repeated move-before-click and global key timing', async ({ page }) => {
  const result = await page.evaluate(() => {
    const session = (window as any).FCaptcha.invisible({ autoScore: false });
    const collector = session.behavioral;
    for (let i = 0; i < 3; i++) {
      collector.recordPointer({
        type: 'pointermove', pointerType: 'mouse', clientX: 100 + i, clientY: 200 + i,
        movementX: 1, movementY: 1, pressure: 0, tiltX: 0, tiltY: 0,
        tangentialPressure: 0, getCoalescedEvents: () => [],
      });
      collector._lastPointerMove.t = performance.now() - 5;
      collector.recordMouseDown({ clientX: 100 + i, clientY: 200 + i, button: 0 });
    }
    for (let i = 0; i < 4; i++) {
      collector.recordKeyEvent({ type: 'keydown', code: `Key${i}`, key: 'a', repeat: false });
      collector._keyDownAt.set(`Key${i}`, performance.now() - 25);
      collector.recordKeyEvent({ type: 'keyup', code: `Key${i}`, key: 'a', repeat: false });
    }
    const forensics = collector.analyze().inputForensics;
    session.destroy();
    return { click: forensics.clickPrelude, key: forensics.keyTiming };
  });
  expect(result.click).toMatchObject({
    version: 1, samples: 3, singleCoalescedRatio: 1,
    delays: { samples: 3 }, distances: { samples: 3, mean: 0, variance: 0, min: 0, max: 0 },
  });
  expect(result.click.delays.mean).toBeGreaterThanOrEqual(5);
  expect(result.click.delays.mean).toBeLessThan(20);
  expect(result.key).toMatchObject({
    version: 1, keydowns: 4,
    intervals: { samples: 3 },
    holds: { samples: 4 },
  });
  expect(result.key.holds.mean).toBeGreaterThanOrEqual(25);
  expect(result.key.holds.mean).toBeLessThan(40);
});
