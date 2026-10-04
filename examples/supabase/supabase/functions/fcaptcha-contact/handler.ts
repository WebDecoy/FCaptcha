export interface Config {
  appOrigin: string;
  captchaOrigin: string;
  verifySecret: string;
}

export function createHandler(config: Config, fetcher: typeof fetch = fetch) {
  for (const origin of [config.appOrigin, config.captchaOrigin]) {
    const url = new URL(origin);
    if (
      !['http:', 'https:'].includes(url.protocol) || url.origin !== origin ||
      url.username || url.password
    ) {
      throw new Error(
        'Configure explicit http(s) origins without paths or credentials',
      );
    }
  }
  if (!config.verifySecret) throw new Error('Missing verification secret');
  const hostname = new URL(config.appOrigin).hostname;
  const headers = {
    'Access-Control-Allow-Origin': config.appOrigin,
    'Access-Control-Allow-Headers':
      'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Vary': 'Origin',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };
  const reply = (status: number, body: unknown) =>
    Response.json(body, { status, headers });
  return async (request: Request): Promise<Response> => {
    // CORS is a browser policy, not authentication. Non-browser clients can forge Origin.
    if (request.headers.get('origin') !== config.appOrigin) {
      return reply(403, { error: 'origin_not_allowed' });
    }
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }
    if (request.method !== 'POST') {
      return reply(405, { error: 'method_not_allowed' });
    }
    if (
      request.headers.get('content-type')?.split(';')[0].trim() !==
        'application/json'
    ) {
      return reply(415, { error: 'json_required' });
    }
    // Bound streamed bytes before JSON parsing; Content-Length alone is not sufficient.
    let raw = '';
    const reader = request.body?.getReader();
    if (!reader) return reply(400, { error: 'invalid_input' });
    const decoder = new TextDecoder();
    let bytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > 16 * 1024) {
          await reader.cancel();
          return reply(413, { error: 'body_too_large' });
        }
        raw += decoder.decode(value, { stream: true });
      }
      raw += decoder.decode();
    } catch {
      return reply(400, { error: 'invalid_input' });
    } finally {
      reader.releaseLock();
    }
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return reply(400, { error: 'invalid_json' });
    }
    if (
      !body || typeof body.message !== 'string' || !body.message.trim() ||
      body.message.length > 2000 ||
      typeof body.token !== 'string' || !body.token.trim() ||
      body.token.length > 8192
    ) {
      return reply(400, { error: 'invalid_input' });
    }
    let result;
    try {
      const response = await fetcher(`${config.captchaOrigin}/siteverify`, {
        method: 'POST',
        redirect: 'error',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret: config.verifySecret,
          response: body.token,
        }),
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error('Verifier unavailable');
      result = await response.json();
      if (!result || typeof result.success !== 'boolean') {
        throw new Error('Invalid verifier response');
      }
    } catch {
      return reply(503, { error: 'verification_unavailable' });
    }
    if (
      result.success !== true || result.hostname !== hostname ||
      result.action !== 'contact'
    ) {
      return reply(403, { error: 'captcha_rejected' });
    }
    // Put the protected operation here. This example does not write to a database or send email.
    return reply(200, { accepted: true, demoOnly: true });
  };
}
