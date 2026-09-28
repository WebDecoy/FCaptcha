// Public configuration only. All secrets stay in the server process.
let loading;
export function loadCaptcha() {
  if (window.FCaptcha) return Promise.resolve();
  if (!loading) loading = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'http://127.0.0.1:8788/fcaptcha.js';
    script.onload = () => { window.FCaptcha.configure({ serverUrl: 'http://127.0.0.1:8788' }); resolve(); };
    script.onerror = () => { script.remove(); loading = undefined; reject(new Error('Widget unavailable')); };
    document.head.append(script);
  });
  return loading;
}
export async function submitContact(message) {
  await loadCaptcha();
  // A fresh token for every attempt: successful verification consumes it.
  const result = await window.FCaptcha.execute('framework-contact', { action: 'contact', lang: 'en' });
  if (!result.success || !result.token) throw new Error('Verification did not pass. Please try again.');
  const response = await fetch('/api/contact', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, token: result.token }), signal: AbortSignal.timeout(8000)
  });
  const data = await response.json();
  if (!response.ok || data.accepted !== true) throw new Error(
    response.status >= 500 ? 'Verification service unavailable. Please try later.' : 'Submission rejected. Please try again.');
  return 'Server verification passed. Demo only: no message was sent.';
}
