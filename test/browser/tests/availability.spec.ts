import { test, expect } from '../fixtures';

test.beforeEach(async ({ page }) => {
  await page.goto('/health');
  await page.addScriptTag({ url: '/fcaptcha.js' });
});

test('same-origin challenges fail closed during an outage', async ({ page }) => {
  await page.route('**/api/pow/challenge*', route => route.fulfill({ status: 503, body: '{}' }));
  const result = await page.evaluate(async () => {
    const api = (window as any).FCaptcha;
    api.configure({ serverUrl: '' });
    const session = api.invisible({ autoScore: false });
    try { await session.powManager.ensureChallenge('outage'); return { rejected: false }; }
    catch (error: any) { return { rejected: true, code: error.code, challenge: session.powManager.challenge }; }
    finally { session.destroy(); }
  });
  expect(result).toEqual({ rejected: true, code: 'server_unavailable', challenge: null });
});

test('scoring never returns a fabricated token when the server fails', async ({ page }) => {
  await page.route('**/api/score', route => route.fulfill({ status: 503, body: '{}' }));
  expect(await page.evaluate(async () => {
    const session = (window as any).FCaptcha.invisible({ autoScore: false });
    try { await session._score({}, 'outage'); return false; }
    catch (error: any) { return error.code === 'server_unavailable' && !session.lastScore; }
    finally { session.destroy(); }
  })).toBe(true);
});

test('automatic forms stay on the page and clear stale tokens on failure', async ({ page }) => {
  const result = await page.evaluate(async () => {
    const form = document.createElement('form');
    form.innerHTML = '<input name="fcaptcha_token" value="stale">';
    document.body.append(form);
    const session = (window as any).FCaptcha.invisible({ autoScore: true });
    session.execute = async () => { throw new Error('offline'); };
    let submitted = false;
    form.submit = () => { submitted = true; };
    form.requestSubmit = () => { submitted = true; };
    const error = new Promise(resolve => document.addEventListener('fcaptcha:error', resolve, { once: true }));
    const event = new Event('submit', { bubbles: true, cancelable: true });
    form.dispatchEvent(event);
    await error;
    session.destroy();
    return { submitted, prevented: event.defaultPrevented, token: (form.elements.namedItem('fcaptcha_token') as HTMLInputElement).value };
  });
  expect(result).toEqual({ submitted: false, prevented: true, token: '' });
});

test('last widget teardown restores form interception and workers stay capped', async ({ page }) => {
  expect(await page.evaluate(() => {
    const original = HTMLFormElement.prototype.submit;
    const api = (window as any).FCaptcha;
    const a = api.invisible({ autoScore: false });
    const b = api.invisible({ autoScore: false });
    Object.defineProperty(navigator, 'hardwareConcurrency', { value: 128, configurable: true });
    const workers = a.powManager._threadCount();
    a.destroy();
    const retained = HTMLFormElement.prototype.submit !== original;
    a.destroy();
    b.destroy();
    return { workers, retained, restored: HTMLFormElement.prototype.submit === original };
  })).toEqual({ workers: 4, retained: true, restored: true });
});
