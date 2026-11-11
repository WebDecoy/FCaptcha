import { StrictMode } from 'react';
import { act, cleanup, render, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FCaptcha } from './index.js';

let sequence = 0;
const uniqueScript = () => `/fcaptcha-test-${sequence++}.js`;

function fakeApi() {
  const api = {
    serverUrl: '',
    configure: vi.fn(({ serverUrl }) => { api.serverUrl = serverUrl; }),
    render: vi.fn(() => `widget-${api.render.mock.calls.length}`),
    destroy: vi.fn(),
  };
  return api;
}

afterEach(() => {
  cleanup();
  delete window.FCaptcha;
  document.head.replaceChildren();
  document.body.replaceChildren();
});

describe('FCaptcha', () => {
  it('mounts, verifies, and destroys the widget', async () => {
    const api = fakeApi();
    const onVerify = vi.fn();
    window.FCaptcha = api;

    const view = render(<FCaptcha siteKey="site" onVerify={onVerify} />);
    await waitFor(() => expect(api.render).toHaveBeenCalledOnce());

    api.render.mock.calls[0][1].callback('token');
    expect(onVerify).toHaveBeenCalledWith('token');
    view.unmount();
    expect(api.destroy).toHaveBeenCalledWith('widget-1');
  });

  it('renders only once across the StrictMode cleanup and remount cycle', async () => {
    const api = fakeApi();
    window.FCaptcha = api;

    const view = render(<StrictMode><FCaptcha siteKey="site" /></StrictMode>);
    await waitFor(() => expect(api.render).toHaveBeenCalledOnce());
    view.unmount();
    expect(api.destroy).toHaveBeenCalledTimes(1);
  });

  it('shares one resolved script URL across simultaneous instances', async () => {
    const source = uniqueScript();
    const absoluteSource = new URL(source, document.baseURI).href;
    const api = fakeApi();

    const view = render(<>
      <FCaptcha siteKey="one" scriptSrc={source} />
      <FCaptcha siteKey="two" scriptSrc={absoluteSource} />
    </>);

    expect(document.querySelectorAll(`script[src="${absoluteSource}"]`)).toHaveLength(1);
    window.FCaptcha = api;
    await act(async () => document.querySelector(`script[src="${absoluteSource}"]`).dispatchEvent(new Event('load')));
    await waitFor(() => expect(api.render).toHaveBeenCalledTimes(2));
    view.unmount();
    expect(api.destroy).toHaveBeenCalledTimes(2);
  });

  it('does not render or report an error after unmounting before load', async () => {
    const source = uniqueScript();
    const api = fakeApi();
    const onError = vi.fn();
    const view = render(<FCaptcha siteKey="site" scriptSrc={source} onError={onError} />);
    const script = document.querySelector('script');

    view.unmount();
    window.FCaptcha = api;
    await act(async () => script.dispatchEvent(new Event('load')));
    expect(api.render).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();
  });

  it('removes a failed load from the cache so the same URL can retry', async () => {
    const source = uniqueScript();
    const firstError = vi.fn();
    const first = render(<FCaptcha siteKey="site" scriptSrc={source} onError={firstError} />);
    const failedScript = document.querySelector('script');

    await act(async () => failedScript.dispatchEvent(new Event('load')));
    await waitFor(() => expect(firstError).toHaveBeenCalledOnce());
    expect(failedScript.isConnected).toBe(false);
    first.unmount();

    const api = fakeApi();
    const second = render(<FCaptcha siteKey="site" scriptSrc={source} />);
    const retryScript = document.querySelector('script');
    expect(retryScript).not.toBe(failedScript);
    window.FCaptcha = api;
    await act(async () => retryScript.dispatchEvent(new Event('load')));
    await waitFor(() => expect(api.render).toHaveBeenCalledOnce());
    second.unmount();
  });

  it('uses updated callbacks without recreating the widget', async () => {
    const api = fakeApi();
    const firstCallback = vi.fn();
    const secondCallback = vi.fn();
    window.FCaptcha = api;

    const view = render(<FCaptcha siteKey="site" onVerify={firstCallback} />);
    await waitFor(() => expect(api.render).toHaveBeenCalledOnce());
    view.rerender(<FCaptcha siteKey="site" onVerify={secondCallback} />);

    api.render.mock.calls[0][1].callback('token');
    expect(firstCallback).not.toHaveBeenCalled();
    expect(secondCallback).toHaveBeenCalledWith('token');
    expect(api.render).toHaveBeenCalledOnce();
  });

  it('rejects a conflicting global server URL', async () => {
    const api = fakeApi();
    const onConflict = vi.fn();
    window.FCaptcha = api;

    render(<>
      <FCaptcha siteKey="one" serverUrl="https://one.example/" />
      <FCaptcha siteKey="two" serverUrl="https://two.example" onError={onConflict} />
    </>);

    await waitFor(() => expect(onConflict).toHaveBeenCalledOnce());
    expect(api.configure).toHaveBeenCalledOnce();
    expect(api.configure).toHaveBeenCalledWith({ serverUrl: 'https://one.example' });
    expect(api.render).toHaveBeenCalledOnce();
  });
});
