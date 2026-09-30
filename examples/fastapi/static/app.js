const form = document.getElementById('contact');
const button = document.getElementById('submit');
const status = document.getElementById('status');
let config;
try {
  const response = await fetch('/config');
  if (!response.ok) throw new Error('Configuration unavailable');
  config = await response.json();
  await new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = `${config.captchaOrigin}/fcaptcha.js`;
    script.onload = resolve;
    script.onerror = reject;
    document.head.append(script);
  });
  FCaptcha.configure({ serverUrl: config.captchaOrigin });
  button.disabled = false;
  button.textContent = 'Verify and submit';
} catch {
  status.textContent = 'Could not load FCaptcha. Check that both local servers are running, then reload.';
}
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = 'Checking…';
  status.textContent = '';
  try {
    // Start a new verification on every attempt. Tokens are single-use.
    const result = await FCaptcha.execute(config.siteKey, { action: 'contact' });
    if (!result.success || !result.token) {
      status.textContent = 'Verification did not pass. You can wait a moment and try again.';
      return;
    }
    const response = await fetch('/contact', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: document.getElementById('message').value, token: result.token }),
      signal: AbortSignal.timeout(8000)
    });
    const body = await response.json();
    status.textContent = response.ok && body.accepted === true
      ? 'FastAPI verified the token. Demo accepted; no message was sent or stored.'
      : response.status >= 500
        ? 'Verification service unavailable. Try again when it is back online.'
        : 'The server rejected this submission. Check your message and try again.';
  } catch {
    status.textContent = 'Verification could not finish. Check your local servers and try again.';
  } finally {
    button.disabled = false;
    button.textContent = 'Verify and submit';
  }
});
