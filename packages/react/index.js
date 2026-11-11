import { createElement, useEffect, useRef } from 'react';

const scriptLoads = new Map();

function resolvedUrl(value) {
  return new URL(value, document.baseURI).href;
}

function loadScript(source) {
  if (window.FCaptcha) return Promise.resolve(window.FCaptcha);

  const url = resolvedUrl(source);
  const pending = scriptLoads.get(url);
  if (pending) return pending;

  const script = document.createElement('script');
  script.src = url;
  script.async = true;

  const load = new Promise((resolve, reject) => {
    const fail = (message) => {
      scriptLoads.delete(url);
      script.remove();
      reject(new Error(message));
    };

    script.addEventListener('load', () => {
      if (window.FCaptcha) resolve(window.FCaptcha);
      else fail('FCaptcha script loaded without exposing window.FCaptcha');
    }, { once: true });
    script.addEventListener('error', () => fail(`Failed to load FCaptcha from ${url}`), { once: true });
  });

  scriptLoads.set(url, load);
  document.head.appendChild(script);
  return load;
}

function normalizedServerUrl(value) {
  if (!value) return '';
  return resolvedUrl(value).replace(/\/+$/, '');
}

function configureServer(api, serverUrl) {
  const requested = normalizedServerUrl(serverUrl);
  if (!requested) return;

  const current = normalizedServerUrl(api.serverUrl);
  if (current && current !== requested) {
    throw new Error(`FCaptcha is already configured for ${current}; refusing conflicting serverUrl ${requested}`);
  }

  if (!current) {
    if (typeof api.configure !== 'function') {
      throw new Error('Loaded FCaptcha API does not support configure({ serverUrl })');
    }
    api.configure({ serverUrl: requested });
  }
}

export function FCaptcha({
  siteKey,
  onVerify,
  onExpire,
  onError,
  scriptSrc = '/fcaptcha.js',
  serverUrl,
  theme,
  size,
  lang,
  className,
  style,
}) {
  const containerRef = useRef(null);
  const callbacks = useRef({ onVerify, onExpire, onError });
  callbacks.current = { onVerify, onExpire, onError };

  useEffect(() => {
    let active = true;
    let api;
    let widgetId;

    loadScript(scriptSrc).then((loadedApi) => {
      if (!active || !containerRef.current) return;

      api = loadedApi;
      configureServer(api, serverUrl);
      widgetId = api.render(containerRef.current, {
        siteKey,
        ...(theme === undefined ? {} : { theme }),
        ...(size === undefined ? {} : { size }),
        ...(lang === undefined ? {} : { lang }),
        callback: (token) => callbacks.current.onVerify?.(token),
        expiredCallback: () => callbacks.current.onExpire?.(),
        errorCallback: (error) => callbacks.current.onError?.(error),
      });
    }).catch((error) => {
      if (active) callbacks.current.onError?.(error);
    });

    return () => {
      active = false;
      if (api && widgetId !== undefined) api.destroy(widgetId);
    };
  }, [siteKey, scriptSrc, serverUrl, theme, size, lang]);

  return createElement('div', { ref: containerRef, className, style });
}
