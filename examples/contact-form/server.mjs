import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

export function createContactServer({ origin, captchaOrigin, verifySecret, fetchImpl = fetch }) {
  if (!origin || !captchaOrigin || !verifySecret) throw new Error('Missing configuration');
  const hostname = new URL(origin).hostname;
  const files = new Map([
    ['/', ['index.html', 'text/html; charset=utf-8']],
    ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
    ['/style.css', ['style.css', 'text/css; charset=utf-8']]
  ]);
  return createServer(async (req, res) => {
    const reply = (status, data) => {
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(data));
    };
    res.setHeader('X-Content-Type-Options', 'nosniff');
    try {
      const path = new URL(req.url, origin).pathname;
      if (req.method === 'GET' && files.has(path)) {
        const [file, type] = files.get(path);
        res.writeHead(200, { 'Content-Type': type });
        res.end(await readFile(new URL(`public/${file}`, import.meta.url)));
        return;
      }
      if (req.method === 'GET' && path === '/config') {
        reply(200, { captchaOrigin, siteKey: 'contact-form' });
        return;
      }
      if (req.method !== 'POST' || path !== '/contact') return reply(404, { error: 'not_found' });
      // Reject browser cross-origin form submissions. This is not authentication.
      if (req.headers.origin !== origin) return reply(403, { error: 'origin_not_allowed' });
      if (req.headers['content-type']?.split(';')[0] !== 'application/json') {
        return reply(415, { error: 'json_required' });
      }
      let size = 0;
      const chunks = [];
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 16 * 1024) return reply(413, { error: 'body_too_large' });
        chunks.push(chunk);
      }
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString()); }
      catch { return reply(400, { error: 'invalid_json' }); }
      if (!body || typeof body.message !== 'string' || !body.message.trim() ||
          body.message.length > 2000 || typeof body.token !== 'string' || !body.token.trim()) {
        return reply(400, { error: 'invalid_input' });
      }
      let result;
      try {
        const verification = await fetchImpl(new URL('/siteverify', captchaOrigin), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ secret: verifySecret, response: body.token }),
          signal: AbortSignal.timeout(5000)
        });
        if (!verification.ok) throw new Error('Verification unavailable');
        result = await verification.json();
      } catch {
        return reply(503, { error: 'verification_unavailable' });
      }
      if (result?.success !== true || result.hostname !== hostname || result.action !== 'contact') {
        return reply(403, { error: 'captcha_rejected' });
      }
      // A real application performs its protected action here, after verification.
      // This example deliberately does not persist or send the message.
      return reply(200, { accepted: true, demoOnly: true });
    } catch {
      if (!res.headersSent) reply(500, { error: 'internal_error' });
      else res.end();
    }
  });
}
