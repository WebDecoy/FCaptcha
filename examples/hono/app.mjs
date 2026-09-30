import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';

export function createApp({ origin, captchaOrigin, verifySecret, page, script, fetchImpl = fetch }) {
  for (const value of [origin, captchaOrigin]) {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== value || url.username || url.password) {
      throw new Error('Use explicit http(s) origins without paths or credentials');
    }
  }
  if (!verifySecret) throw new Error('A server-only verification secret is required');
  const hostname = new URL(origin).hostname;
  const app = new Hono();
  app.use('*', async (c, next) => {
    c.header('Cache-Control', 'no-store');
    c.header('X-Content-Type-Options', 'nosniff');
    await next();
  });
  app.get('/', c => c.html(page));
  app.get('/app.js', c => c.body(script, 200, { 'Content-Type': 'text/javascript' }));
  app.get('/config', c => c.json({ captchaOrigin, siteKey: 'hono-demo' }));

  // Validate before calling the verifier. Origin is a browser check, not caller identity.
  app.use('/contact', async (c, next) => {
    if (c.req.method !== 'POST') return c.json({ error: 'method_not_allowed' }, 405);
    if (c.req.header('origin') !== origin) return c.json({ error: 'origin_not_allowed' }, 403);
    if (c.req.header('content-type')?.split(';')[0].trim() !== 'application/json') {
      return c.json({ error: 'json_required' }, 415);
    }
    await next();
  });
  app.use('/contact', bodyLimit({
    maxSize: 16 * 1024,
    onError: c => c.json({ error: 'body_too_large' }, 413),
  }));

  const verifyVisitor = async (c, next) => {
    let body;
    try { body = await c.req.json(); }
    catch { return c.json({ error: 'invalid_json' }, 400); }
    if (!body || typeof body.message !== 'string' || !body.message.trim() || body.message.length > 2000 ||
        typeof body.token !== 'string' || !body.token.trim() || body.token.length > 8192) {
      return c.json({ error: 'invalid_input' }, 400);
    }
    let result;
    try {
      const response = await fetchImpl(`${captchaOrigin}/siteverify`, {
        method: 'POST', redirect: 'error',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ secret: verifySecret, response: body.token }),
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error('Verifier unavailable');
      result = await response.json();
      if (!result || typeof result.success !== 'boolean') throw new Error('Invalid response');
    } catch { return c.json({ error: 'verification_unavailable' }, 503); }
    if (result.success !== true || result.hostname !== hostname || result.action !== 'contact') {
      return c.json({ error: 'captcha_rejected' }, 403);
    }
    // Downstream handlers get validated input, not the token or verification secret.
    c.set('message', body.message.trim());
    await next();
  };

  app.post('/contact', verifyVisitor, c => {
    // Send/save/enqueue c.get('message') here, only after middleware passes.
    return c.json({ accepted: true, demoOnly: true });
  });
  return app;
}
