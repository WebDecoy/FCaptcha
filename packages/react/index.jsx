import { useEffect, useRef } from 'react';
const scripts = new Map();
const load = (src) => {
  if (window.FCaptcha) return Promise.resolve(window.FCaptcha);
  if (!scripts.has(src)) scripts.set(src, new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src; s.async = true;
    s.onload = () => window.FCaptcha ? resolve(window.FCaptcha) : reject(new Error('FCaptcha missing'));
    s.onerror = () => { scripts.delete(src); reject(new Error('Failed to load FCaptcha')); };
    document.head.appendChild(s);
  }));
  return scripts.get(src);
};
export function FCaptcha({ siteKey, onVerify, onExpire, onError, scriptSrc = '/fcaptcha.js', serverUrl, ...options }) {
  const el = useRef(null), cb = useRef({ onVerify, onExpire, onError });
  cb.current = { onVerify, onExpire, onError };
  useEffect(() => {
    let cancelled = false, api, widget;
    load(scriptSrc).then((a) => {
      api = a;
      if (cancelled || !el.current) return;
      if (serverUrl) api.configure?.({ serverUrl });
      widget = api.render(el.current, {
        ...options, siteKey,
        callback: (token) => cb.current.onVerify?.(token),
        expiredCallback: () => cb.current.onExpire?.(),
        errorCallback: (err) => cb.current.onError?.(err),
      });
    }).catch((err) => cb.current.onError?.(err));
    return () => {
      cancelled = true;
      if (api) api.destroy(widget ?? el.current);
    };
  }, [siteKey, scriptSrc, serverUrl]);
  return <div ref={el} />;
}
