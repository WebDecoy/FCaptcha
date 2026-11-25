<script>
  import { tick } from 'svelte';

  let { data, form } = $props();
  let token = $state('');
  let pending = $state(false);
  let status = $state('');

  async function verify(event) {
    if (token) return;
    event.preventDefault();
    if (pending) return;

    const element = event.currentTarget;
    pending = true;
    status = 'Verifying…';

    try {
      const captcha = window.FCaptcha;
      if (!captcha) {
        status = 'Start the local FCaptcha server and reload this page.';
        return;
      }
      captcha.configure({ serverUrl: data.captchaOrigin });
      const result = await captcha.execute('sveltekit-contact', { action: 'contact' });
      if (!result.success || !result.token) {
        status = 'Verification failed. Please try again.';
        return;
      }
      token = result.token;
      await tick();
      element.requestSubmit();
    } catch {
      token = '';
      status = 'Verification is unavailable. Please try again.';
    } finally {
      pending = false;
    }
  }
</script>

<svelte:head>
  <title>SvelteKit contact form with FCaptcha</title>
  <script src={data.captchaOrigin + '/fcaptcha.js'} defer></script>
</svelte:head>

<main>
  <h1>Contact form with FCaptcha</h1>
  <p>Try a local verification. This demo does not send or store your message.</p>
  <form method="POST" onsubmit={verify}>
    <label for="message">Message</label>
    <textarea id="message" name="message" required maxlength="2000" rows="5"></textarea>
    <input type="hidden" name="fcaptcha_token" value={token} />
    <button disabled={pending}>Verify and submit</button>
  </form>
  <p role="status">{status || form?.error || (form?.accepted ? 'Demo submission accepted.' : '')}</p>
</main>

<style>
  main { max-width: 36rem; margin: 3rem auto; padding: 0 1rem; font: 1rem/1.6 system-ui; }
  form { display: grid; gap: .75rem; }
  textarea, button { font: inherit; }
  button { justify-self: start; padding: .35rem .75rem; }
</style>
