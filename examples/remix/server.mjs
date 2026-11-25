import { readFile } from 'node:fs/promises';
import { CaptchaError } from '@sdxc/captcha';
import { captcha } from '@sdxc/captcha/middleware';
import { failure, success } from '@sdxc/result';
import { createRouter } from 'remix/router';

const template = await readFile(new URL('./contact.html', import.meta.url), 'utf8');

export function createContactRouter({ appOrigin, verifierOrigin, secret }) {
  const { hostname } = new URL(appOrigin);
  const browserOrigin = new URL(verifierOrigin).origin;
  const endpoint = new URL('/turnstile/v0/siteverify', browserOrigin);
  if (endpoint.protocol !== 'http:' && endpoint.protocol !== 'https:') {
    throw new Error('Use an HTTP or HTTPS verifier origin.');
  }
  const htmlOrigin = browserOrigin.replaceAll('&', '&amp;').replaceAll('"', '&quot;');

  const provider = {
    field: 'fcaptcha_token',
    async verify(token) {
      if (token.length > 8192) return failure(new CaptchaError('rejected'));

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          body: new URLSearchParams({ secret, response: token }),
          redirect: 'error',
          signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) return failure(new CaptchaError('unavailable'));

        const result = await response.json();
        if (result?.success === true) {
          return success({ hostname: result.hostname, action: result.action });
        }
        const codes = result?.['error-codes'];
        if (Array.isArray(codes) && codes.includes('timeout-or-duplicate')) {
          return failure(new CaptchaError('expired'));
        }
        if (Array.isArray(codes) && codes.includes('invalid-input-response')) {
          return failure(new CaptchaError('rejected'));
        }
      } catch {
        return failure(new CaptchaError('unavailable'));
      }
      return failure(new CaptchaError('unavailable'));
    },
  };

  const router = createRouter();
  router.get('/', () => new Response(template.replaceAll('DEMO_VERIFIER_ORIGIN', () => htmlOrigin), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  }));

  router.post('/contact', {
    middleware: [
      (ctx, next) => ctx.request.headers.get('origin') === appOrigin
        ? next()
        : new Response('Request origin refused.', { status: 403 }),
      captcha(provider, {
        hostname,
        action: 'contact',
        onFailure(error) {
          return error.code === 'unavailable'
            ? new Response('Verification is unavailable. Try again later.', { status: 503 })
            : new Response('Verification was rejected. Try again.', { status: 403 });
        },
      }),
    ],
    async handler({ request }) {
      const message = (await request.formData()).get('message');
      if (typeof message !== 'string' || !message.trim() || message.length > 2000) {
        return new Response('Enter a message of up to 2,000 characters.', { status: 400 });
      }
      return new Response('Demo submission accepted. No message was sent or stored.');
    },
  });
  return router;
}
