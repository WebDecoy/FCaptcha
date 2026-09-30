import { createHandler } from '../supabase/functions/fcaptcha-contact/handler.ts';

function equal(actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    );
  }
}
const appOrigin = 'http://127.0.0.1:8792';
const config = {
  appOrigin,
  captchaOrigin: 'http://127.0.0.1:8793',
  verifySecret: 'unit-test-only',
};
function request(
  body: unknown = { message: 'sample', token: 'fixture' },
  origin = appOrigin,
) {
  return new Request('http://127.0.0.1/functions/v1/fcaptcha-contact', {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
const mock = (value: unknown, status = 200): typeof fetch => () =>
  Promise.resolve(Response.json(value, { status }));

Deno.test('browser preflight and rejection responses retain explicit CORS headers', async () => {
  const handler = createHandler(config, mock({ success: false }));
  const preflight = await handler(
    new Request('http://127.0.0.1', {
      method: 'OPTIONS',
      headers: { Origin: appOrigin },
    }),
  );
  equal(preflight.status, 204);
  equal(preflight.headers.get('access-control-allow-origin'), appOrigin);
  equal(
    preflight.headers.get('access-control-allow-headers'),
    'authorization, x-client-info, apikey, content-type',
  );
  const rejected = await handler(request());
  equal(rejected.status, 403);
  equal(rejected.headers.get('access-control-allow-origin'), appOrigin);
});

Deno.test('bad origin and method never reach verification', async () => {
  const handler = createHandler(config, () => {
    throw new Error('must not call');
  });
  equal(
    (await handler(request(undefined, 'https://other.example'))).status,
    403,
  );
  equal((await handler(new Request('http://127.0.0.1'))).status, 403);
  equal(
    (await handler(
      new Request('http://127.0.0.1', { headers: { Origin: appOrigin } }),
    )).status,
    405,
  );
});

Deno.test('valid result requires matching hostname and action', async () => {
  for (
    const [value, code] of [
      [{ success: true, hostname: '127.0.0.1', action: 'contact' }, 200],
      [{ success: true, hostname: 'other.example', action: 'contact' }, 403],
      [{ success: true, hostname: '127.0.0.1', action: 'login' }, 403],
      [{ success: true }, 403],
      [{ success: false }, 403],
      [{ success: 'true' }, 503],
      [null, 503],
      [[], 503],
    ] as const
  ) {
    equal((await createHandler(config, mock(value))(request())).status, code);
  }
});

Deno.test('form-encoded secret stays on verification request, with timeout and redirect protection', async () => {
  const fetcher: typeof fetch = (url, options) => {
    equal(url, `${config.captchaOrigin}/siteverify`);
    equal(options?.method, 'POST');
    equal(options?.redirect, 'error');
    if (!options?.signal) throw new Error('Missing timeout signal');
    const data = options.body as URLSearchParams;
    equal(data.get('secret'), config.verifySecret);
    equal(data.get('response'), 'fixture');
    return Promise.resolve(
      Response.json({
        success: true,
        hostname: '127.0.0.1',
        action: 'contact',
      }),
    );
  };
  const response = await createHandler(config, fetcher)(request());
  equal(await response.json(), { accepted: true, demoOnly: true });
});

Deno.test('outages, non-JSON, and unsuccessful HTTP status fail closed', async () => {
  const failures: typeof fetch[] = [
    () => Promise.reject(new DOMException('timed out', 'TimeoutError')),
    () => Promise.resolve(new Response('not json')),
    mock({ success: true }, 500),
    mock({}, 302),
  ];
  for (const failure of failures) {
    equal((await createHandler(config, failure)(request())).status, 503);
  }
});

Deno.test('input validation and streamed size limit', async () => {
  const handler = createHandler(config, () => {
    throw new Error('must not call');
  });
  for (
    const body of [null, {}, { message: 'x' }, { message: '', token: 'x' }, {
      message: 'x'.repeat(2001),
      token: 'x',
    }, { message: 'x', token: 'x'.repeat(8193) }]
  ) {
    equal((await handler(request(body))).status, 400);
  }
  equal(
    (await handler(
      new Request('http://127.0.0.1', {
        method: 'POST',
        headers: { Origin: appOrigin },
        body: 'test',
      }),
    )).status,
    415,
  );
  equal(
    (await handler(
      new Request('http://127.0.0.1', {
        method: 'POST',
        headers: { Origin: appOrigin, 'Content-Type': 'application/json' },
        body: '{',
      }),
    )).status,
    400,
  );
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(9000));
      controller.enqueue(new Uint8Array(9000));
      controller.close();
    },
  });
  equal(
    (await handler(
      new Request('http://127.0.0.1', {
        method: 'POST',
        headers: { Origin: appOrigin, 'Content-Type': 'application/json' },
        body: stream,
      }),
    )).status,
    413,
  );
});

Deno.test('real FCaptcha verifier: accept once, reject replay, expiry, forgery and incorrect bindings', async () => {
  const secret = crypto.randomUUID() + crypto.randomUUID();
  const verifySecret = crypto.randomUUID();
  const child = new Deno.Command('node', {
    args: ['tests/verifier.mjs'],
    stdin: 'piped',
    stdout: 'piped',
    stderr: 'inherit',
    clearEnv: true,
    env: {
      PATH: Deno.env.get('PATH') ?? '',
      FCAPTCHA_SECRET: secret,
      FCAPTCHA_VERIFY_SECRET: verifySecret,
      FCAPTCHA_SITE_KEYS: 'supabase-demo',
      FCAPTCHA_ALLOWED_HOSTNAMES: '127.0.0.1',
      TRUSTED_PROXIES: 'none',
      REDIS_URL: '',
    },
  }).spawn();
  const reader = child.stdout.getReader();
  let output = '';
  const timer = setTimeout(() => {
    try {
      child.kill('SIGTERM');
    } catch { /* already exited */ }
  }, 20000);
  try {
    while (!output.includes('TEST_PORT=')) {
      const { value, done } = await reader.read();
      if (done) throw new Error('Verifier exited before ready');
      output += new TextDecoder().decode(value);
    }
    const port = output.match(/TEST_PORT=(\d+)/)?.[1];
    if (!port) throw new Error('Missing test port');
    const handler = createHandler({
      appOrigin,
      captchaOrigin: `http://127.0.0.1:${port}`,
      verifySecret,
    });
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const token = async (overrides: Record<string, unknown> = {}) => {
      const data = {
        site_key: 'supabase-demo',
        jti: crypto.randomUUID(),
        timestamp: Math.floor(Date.now() / 1000),
        score: 0.05,
        ip_hash: '',
        hostname: '127.0.0.1',
        action: 'contact',
        cdata: '',
        ...overrides,
      };
      const payload = JSON.stringify(data, Object.keys(data).sort());
      const sig = [
        ...new Uint8Array(
          await crypto.subtle.sign('HMAC', key, encoder.encode(payload)),
        ),
      ]
        .map((byte) => byte.toString(16).padStart(2, '0')).join('');
      return btoa(JSON.stringify({ ...data, sig })).replaceAll('+', '-')
        .replaceAll('/', '_').replace(/=+$/, '');
    };
    const valid = await token();
    equal(
      (await handler(request({ message: 'sample', token: valid }))).status,
      200,
    );
    equal(
      (await handler(request({ message: 'sample', token: valid }))).status,
      403,
    );
    for (
      const overrides of [{ timestamp: 1 }, { hostname: 'other.example' }, {
        action: 'login',
      }]
    ) {
      equal(
        (await handler(
          request({ message: 'sample', token: await token(overrides) }),
        )).status,
        403,
      );
    }
    equal(
      (await handler(request({ message: 'sample', token: 'forged' }))).status,
      403,
    );
  } finally {
    clearTimeout(timer);
    await child.stdin.close();
    await reader.cancel();
    reader.releaseLock();
    await child.status;
  }
});
