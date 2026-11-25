import { FCAPTCHA_ORIGIN, FCAPTCHA_PUBLIC_ORIGIN, FCAPTCHA_VERIFY_SECRET } from '$app/env/private';
import { fail } from '@sveltejs/kit';

const localCaptchaOrigin = 'http://127.0.0.1:8797';

export function load() {
  return { captchaOrigin: new URL(FCAPTCHA_PUBLIC_ORIGIN || localCaptchaOrigin).origin };
}

export const actions = {
  default: async ({ request, url }) => {
    const data = await request.formData();
    const message = data.get('message');
    const token = data.get('fcaptcha_token');

    if (typeof message !== 'string' || !message.trim() || message.length > 2000 ||
        typeof token !== 'string' || !token.trim() || token.length > 8192) {
      return fail(400, { error: 'Enter a message and complete verification.' });
    }

    const secret = FCAPTCHA_VERIFY_SECRET;
    const unavailable = 'Verification is unavailable. Please try again.';
    if (!secret) return fail(503, { error: unavailable });

    let result;
    try {
      const response = await fetch(new URL('/siteverify', FCAPTCHA_ORIGIN || localCaptchaOrigin), {
        method: 'POST',
        body: new URLSearchParams({ secret, response: token }),
        signal: AbortSignal.timeout(5000),
        redirect: 'error',
      });
      if (!response.ok) return fail(503, { error: unavailable });

      result = await response.json();
      if (typeof result?.success !== 'boolean') return fail(503, { error: unavailable });
    } catch {
      return fail(503, { error: unavailable });
    }

    if (!result.success || result.hostname !== url.hostname || result.action !== 'contact') {
      return fail(403, { error: 'Verification was rejected. Please try again.' });
    }

    // Perform your protected action here. This demo does not send or store messages.
    return { accepted: true };
  },
};
