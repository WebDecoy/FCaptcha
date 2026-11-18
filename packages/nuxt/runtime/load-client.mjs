const pending = new Map();

export function loadClient(source) {
  if (window.FCaptcha) return Promise.resolve(window.FCaptcha);
  const parsed = new URL(source, document.baseURI);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error('FCaptcha scriptSrc must be a credential-free HTTP(S) URL');
  }
  const url = parsed.href;
  if (pending.has(url)) return pending.get(url);
  const script = document.createElement('script');
  script.src = url;
  script.async = true;
  const load = new Promise((resolve, reject) => {
    const fail = (message) => {
      clearTimeout(timer);
      pending.delete(url);
      script.remove();
      reject(new Error(message));
    };
    const timer = setTimeout(() => fail('FCaptcha script timed out'), 15000);
    script.onload = () => {
      if (!window.FCaptcha) return fail('FCaptcha script exposed no browser API');
      clearTimeout(timer);
      resolve(window.FCaptcha);
    };
    script.onerror = () => fail('FCaptcha script could not be loaded');
    document.head.appendChild(script);
  });
  pending.set(url, load);
  return load;
}

export function configureServer(api, serverUrl) {
  if (!serverUrl) throw new Error('FCaptcha requires a public serverUrl');
  const requested = new URL(serverUrl, document.baseURI);
  if (!['http:', 'https:'].includes(requested.protocol) || requested.username || requested.password || requested.search || requested.hash) {
    throw new Error('FCaptcha serverUrl must be an HTTP(S) base URL without credentials, query or fragment');
  }
  const normalized = requested.href.replace(/\/+$/, '');
  const current = api.serverUrl ? new URL(api.serverUrl, document.baseURI).href.replace(/\/+$/, '') : '';
  if (current && current !== normalized) throw new Error('FCaptcha widgets on one page must use the same serverUrl');
  api.configure({ serverUrl: normalized });
}
