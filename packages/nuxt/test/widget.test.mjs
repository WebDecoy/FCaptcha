import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import FCaptcha from '../runtime/FCaptcha.mjs';
import { configureServer, loadClient } from '../runtime/load-client.mjs';

let api;
let wrappers;
beforeEach(() => {
  wrappers = [];
  api = { serverUrl: '', configure: vi.fn(options => { api.serverUrl = options.serverUrl; }), render: vi.fn(() => 'test-widget'), destroy: vi.fn() };
  window.FCaptcha = api;
});
afterEach(() => {
  for (const wrapper of wrappers) wrapper.unmount();
  delete window.FCaptcha;
  document.head.querySelectorAll('script').forEach(script => script.remove());
  vi.useRealTimers();
});
const render = props => { const wrapper = mount(FCaptcha, { props }); wrappers.push(wrapper); return wrapper; };

describe('FCaptcha Nuxt component', () => {
  it('renders using public runtime defaults and forwards callbacks', async () => {
    const wrapper = render({});
    await flushPromises();
    expect(api.configure).toHaveBeenCalledWith({ serverUrl: 'https://captcha.example.test' });
    const [element, options] = api.render.mock.calls[0];
    expect(element).toBe(wrapper.element);
    expect(options.siteKey).toBe('test-site');
    options.callback('test-token'); options.expiredCallback(); options.errorCallback('denied');
    expect(wrapper.emitted('verify')).toEqual([['test-token']]);
    expect(wrapper.emitted('expire')).toHaveLength(1);
    expect(wrapper.emitted('error')).toEqual([['denied']]);
  });
  it('destroys the old widget on prop changes and unmount', async () => {
    const wrapper = render({ siteKey: 'first', lang: 'de', theme: 'dark' });
    await flushPromises();
    expect(api.render.mock.calls[0][1]).toMatchObject({ siteKey: 'first', lang: 'de', theme: 'dark' });
    await wrapper.setProps({ siteKey: 'second' }); await flushPromises();
    expect(api.destroy).toHaveBeenCalledTimes(1);
    expect(api.render.mock.calls[1][1].siteKey).toBe('second');
    wrapper.unmount();
    expect(api.destroy).toHaveBeenCalledTimes(2);
  });
  it('ignores callbacks from an old widget', async () => {
    const wrapper = render({}); await flushPromises();
    const old = api.render.mock.calls[0][1];
    await wrapper.setProps({ siteKey: 'new-key' }); await flushPromises();
    old.callback('stale'); old.expiredCallback(); old.errorCallback('stale');
    expect(wrapper.emitted('verify')).toBeUndefined();
    expect(wrapper.emitted('expire')).toBeUndefined();
    expect(wrapper.emitted('error')).toBeUndefined();
  });
  it('does not render after unmount during script load', async () => {
    delete window.FCaptcha;
    const wrapper = render({ scriptSrc: 'https://captcha.example.test/pending.js' });
    const script = document.head.querySelector('script');
    wrapper.unmount();
    window.FCaptcha = api; script.dispatchEvent(new Event('load'));
    await flushPromises();
    expect(api.render).not.toHaveBeenCalled();
  });
  it('rejects conflicting verifier endpoints instead of rerouting existing widgets', async () => {
    api.serverUrl = 'https://first.example.test';
    const wrapper = render({ serverUrl: 'https://second.example.test' }); await flushPromises();
    expect(api.render).not.toHaveBeenCalled();
    expect(wrapper.emitted('error')[0][0].message).toContain('same serverUrl');
    expect(api.serverUrl).toBe('https://first.example.test');
  });
});

describe('self-hosted script loading', () => {
  it('shares one load for simultaneous widgets', async () => {
    delete window.FCaptcha;
    const first = loadClient('/shared.js'); const second = loadClient('/shared.js');
    expect(first).toBe(second);
    expect(document.head.querySelectorAll('script')).toHaveLength(1);
    window.FCaptcha = api; document.head.querySelector('script').dispatchEvent(new Event('load'));
    expect(await first).toBe(api);
  });
  it('rejects a failed script and allows retry', async () => {
    delete window.FCaptcha;
    const first = loadClient('/retry.js');
    const failure = expect(first).rejects.toThrow('could not be loaded');
    document.head.querySelector('script').dispatchEvent(new Event('error')); await failure;
    expect(document.head.querySelector('script')).toBeNull();
    const retry = loadClient('/retry.js'); window.FCaptcha = api;
    document.head.querySelector('script').dispatchEvent(new Event('load'));
    expect(await retry).toBe(api);
  });
  it('rejects a loaded script without an API', async () => {
    delete window.FCaptcha;
    const load = loadClient('/missing-api.js');
    const failure = expect(load).rejects.toThrow('no browser API');
    document.head.querySelector('script').dispatchEvent(new Event('load')); await failure;
  });
  it('times out and removes an unavailable script', async () => {
    vi.useFakeTimers(); delete window.FCaptcha;
    const load = loadClient('/timeout.js');
    const failure = expect(load).rejects.toThrow('timed out');
    await vi.advanceTimersByTimeAsync(15000); await failure;
    expect(document.head.querySelector('script')).toBeNull();
  });
  it('rejects unsafe or credential-bearing endpoints', () => {
    for (const endpoint of ['javascript:alert(1)', 'https://user:password@example.test', 'https://example.test/?key=x']) {
      expect(() => configureServer(api, endpoint)).toThrow('HTTP(S)');
    }
    expect(api.configure).not.toHaveBeenCalled();
  });
});
