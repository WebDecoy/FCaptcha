import { test, expect, Page } from '@playwright/test';

async function session(page: Page) {
  await page.goto('/health');
  await page.addScriptTag({ url: '/fcaptcha.js' });
  await page.evaluate(() => {
    const w = window as any;
    w.FCaptcha.configure({ serverUrl: location.origin });
    const s = w.session = w.FCaptcha.invisible({ siteKey: 'lifecycle', autoScore: false, minCollectionTime: 0 });
    // Test the real network/PoW lifecycle without webdriver detection deciding
    // the verdict or asynchronous environmental probes obscuring the failure.
    s.environmental.collect = () => ({ automationFlags: {} });
    s.environmental.collectAsync = async () => ({});
    s.environmental.measureRAFConsistency = async () => ({});
    s.behavioral.analyze = () => ({ totalPoints: 60, trajectoryLength: 400,
      microTremorScore: 0.5, velocityVariance: 0.5, approachPoints: 12,
      approachDirectness: 0.4, explorationRatio: 0.35, overshootCorrections: 2,
      interactionDuration: 4200 });
    s.temporal.collect = () => ({});
  });
  await page.waitForFunction(() => !!(window as any).session.powManager.challenge);
}

test('repeated and concurrent actions each receive a fresh usable challenge', async ({ page }) => {
  await session(page);
  const challengeIds: string[] = [];
  page.on('request', (req) => {
    if (req.url().endsWith('/api/score')) challengeIds.push(req.postDataJSON().powSolution.challengeId);
  });
  const results = await page.evaluate(async () => {
    const s = (window as any).session;
    return [await s.execute('first'), ...await Promise.all([s.execute('second'), s.execute('third')])];
  });
  expect(results.map((r) => r.success)).toEqual([true, true, true]);
  expect(new Set(challengeIds).size).toBe(3);
  expect(new Set(results.map((r) => r.token)).size).toBe(3);
});

test('expiry refresh binds signals to the replacement challenge', async ({ page }) => {
  await session(page);
  const old = await page.evaluate(() => {
    const c = (window as any).session.powManager.challenge;
    c.expiresAt = Date.now() - 1;
    return { id: c.challengeId, nonce: c.nonce };
  });
  const submission = page.waitForRequest((req) => req.url().endsWith('/api/score'));
  const result = await page.evaluate(() => (window as any).session.execute('expired'));
  const body = (await submission).postDataJSON();
  expect(body.powSolution.challengeId).not.toBe(old.id);
  expect(body.signals.meta.challengeNonce).not.toBe(old.nonce);
  expect(result.success).toBe(true);
});

test('a persistent session can retry after its solver fails', async ({ page }) => {
  await session(page);
  const result = await page.evaluate(async () => {
    const s = (window as any).session;
    const create = s.powManager._createWorker;
    s.powManager._createWorker = () => { throw new Error('worker failed'); };
    let rejected = false;
    try { await s.execute('first'); } catch { rejected = true; }
    s.powManager._createWorker = create;
    return { rejected, retry: (await s.execute('retry')).success };
  });
  expect(result).toEqual({ rejected: true, retry: true });
});

test('destroy removes retained sessions, sensors, and form handlers', async ({ page }) => {
  await page.goto('/health');
  await page.addScriptTag({ url: '/fcaptcha.js' });
  const result = await page.evaluate(() => {
    const api = (window as any).FCaptcha;
    const form = document.createElement('form');
    document.body.appendChild(form);
    const sessions = Array.from({ length: 10 }, () => api.invisible({ autoScore: true }));
    for (const s of sessions) s.destroy();
    const event = new Event('submit', { bubbles: true, cancelable: true });
    form.dispatchEvent(event);
    window.dispatchEvent(new Event('devicemotion'));
    window.dispatchEvent(new Event('deviceorientation'));
    return { retained: api.widgets.size, intercepted: event.defaultPrevented,
      samples: sessions.map((s) => s.sensor.motionEvents.length + s.sensor.orientationEvents.length) };
  });
  expect(result).toEqual({ retained: 0, intercepted: false, samples: Array(10).fill(0) });
});

test('public execute cleans up when the worker cannot start', async ({ page }) => {
  await page.goto('/health');
  await page.evaluate(() => {
    const w = window as any;
    w.sensors = new Set();
    const add = window.addEventListener.bind(window);
    const remove = window.removeEventListener.bind(window);
    window.addEventListener = ((name: string, fn: any, options: any) => {
      if (name === 'devicemotion' || name === 'deviceorientation') w.sensors.add(fn);
      add(name, fn, options);
    }) as any;
    window.removeEventListener = ((name: string, fn: any, options: any) => {
      if (name === 'devicemotion' || name === 'deviceorientation') w.sensors.delete(fn);
      remove(name, fn, options);
    }) as any;
    w.Worker = class { constructor() { throw new Error('worker disabled'); } };
  });
  await page.addScriptTag({ url: '/fcaptcha.js' });
  const result = await page.evaluate(async () => {
    const w = window as any;
    let rejected = false;
    try { await w.FCaptcha.execute('cleanup', { minTime: 1 }); } catch { rejected = true; }
    return { rejected, sensors: w.sensors.size };
  });
  expect(result).toEqual({ rejected: true, sensors: 0 });
});

test('destroying one widget leaves another widget usable', async ({ page }) => {
  await page.goto('/health');
  await page.addScriptTag({ url: '/fcaptcha.js' });
  expect(await page.evaluate(() => {
    const api = (window as any).FCaptcha;
    const first = document.createElement('div');
    const second = document.createElement('div');
    document.body.append(first, second);
    const a = api.render(first, { siteKey: 'one' });
    const b = api.render(second, { siteKey: 'two' });
    const separate = api.widgets.get(a).powManager !== api.widgets.get(b).powManager;
    api.destroy(a);
    const result = { separate, retained: api.widgets.size, removed: first.childElementCount,
      remaining: !!second.querySelector('[role=checkbox]') };
    api.destroy(b);
    return result;
  })).toEqual({ separate: true, retained: 1, removed: 0, remaining: true });
});
