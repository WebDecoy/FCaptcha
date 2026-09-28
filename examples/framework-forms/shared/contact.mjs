// Server-only: never import this module into a browser component.
export function contactHandler({ origin, captchaOrigin, verifySecret, fetchImpl = fetch }) {
  if (!origin || !captchaOrigin || !verifySecret) throw new Error('Missing server configuration');
  const hostname = new URL(origin).hostname;
  const reply = (status, error) => Response.json(error, { status, headers: { 'Cache-Control': 'no-store' } });
  return async function POST(request) {
    // Browser-origin check is defense in depth, not authentication.
    if (request.headers.get('origin') !== origin) return reply(403, { error: 'origin_not_allowed' });
    if (request.headers.get('content-type')?.split(';')[0] !== 'application/json') return reply(415, { error: 'json_required' });
    let body;
    try {
      const reader = request.body?.getReader();
      if (!reader) return reply(400, { error: 'invalid_json' });
      const chunks = []; let size = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 16384) { await reader.cancel(); return reply(413, { error: 'body_too_large' }); }
        chunks.push(Buffer.from(value));
      }
      body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch { return reply(400, { error: 'invalid_json' }); }
    if (!body || typeof body.message !== 'string' || !body.message.trim() || body.message.length > 2000 ||
        typeof body.token !== 'string' || !body.token.trim() || body.token.length > 12000) {
      return reply(400, { error: 'invalid_input' });
    }
    let result;
    try {
      const verification = await fetchImpl(new URL('/siteverify', captchaOrigin), {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ secret: verifySecret, response: body.token }),
        signal: AbortSignal.timeout(5000), cache: 'no-store'
      });
      if (!verification.ok) throw new Error('Verification unavailable');
      result = await verification.json();
    } catch { return reply(503, { error: 'verification_unavailable' }); }
    if (result?.success !== true || result.hostname !== hostname || result.action !== 'contact') {
      return reply(403, { error: 'captcha_rejected' });
    }
    // Put your protected side effect HERE, never before verification.
    // Demo only: no email is sent and no message is stored.
    return reply(200, { accepted: true, demoOnly: true });
  };
}
