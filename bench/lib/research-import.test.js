'use strict';

const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const test = require('node:test');

const {
  fetchExport,
  parseExport,
  readExportStream,
  toCorpusSample,
  validateRecord,
} = require('./research-import');

function record(overrides = {}) {
  return {
    schemaVersion: 1,
    id: 'a'.repeat(32),
    capturedAt: '2026-11-09T12:00:00Z',
    expiresAt: '2026-11-16T12:00:00Z',
    endpoint: 'verify',
    label: 'human',
    labelSource: 'self_report',
    inputMethod: 'trackpad',
    subjectId: 'b'.repeat(24),
    browser: 'chrome',
    os: 'macos',
    signals: {
      meta: {
        challengeNonce: 'private-challenge',
        userAgent: 'private-user-agent',
        stable: true,
      },
      environmental: {
        screen: { width: 1920, height: 1080 },
        webdriver: false,
      },
      formAnalysis: {
        textareaKeyboard: {
          email: { keyEvents: 4 },
          message: { keyEvents: 12 },
        },
      },
    },
    verdict: { success: true, score: 0.02 },
    ...overrides,
  };
}

test('converts consented records without retaining linkable or operational metadata', () => {
  const source = record();
  const sample = toCorpusSample(source);
  const serialized = JSON.stringify(sample);

  assert.equal(sample.label, 'human');
  assert.equal(sample.provenance, 'self-reported');
  assert.equal(sample.group, 'self-reported-chrome-macos-trackpad');
  assert.equal(sample.scenario, 'hosted-demo-chrome-macos-trackpad');
  assert.equal(sample.id, 'human/hosted-demo-chrome-macos-trackpad/research-0000');
  assert.equal(sample.signals.meta.challengeNonce, undefined);
  assert.equal(sample.signals.meta.userAgent, undefined);
  assert.equal(sample.signals.meta.stable, true);
  assert.equal(sample.signals.environmental.screen, undefined);
  assert.deepEqual(Object.keys(sample.signals.formAnalysis.textareaKeyboard), ['field_1', 'field_2']);
  assert.equal(serialized.includes(source.id), false);
  assert.equal(serialized.includes(source.subjectId), false);
  assert.equal(serialized.includes(source.capturedAt), false);
  assert.equal(serialized.includes(source.expiresAt), false);
  assert.equal(serialized.includes('verdict'), false);
});

test('strictly rejects schema drift, untrusted labels, and unsafe objects', () => {
  assert.throws(() => validateRecord(record({ schemaVersion: 2 })), /schemaVersion/);
  assert.throws(() => validateRecord(record({ labelSource: 'verified' })), /self-reported human label/);
  assert.throws(() => validateRecord({ ...record(), unexpected: true }), /unknown field unexpected/);
  assert.throws(
    () => validateRecord(record({ signals: JSON.parse('{"__proto__":{"polluted":true}}') })),
    /forbidden key __proto__/
  );
});

test('parses NDJSON deterministically and refuses duplicate or empty exports', () => {
  const line = JSON.stringify(record());
  const first = parseExport(Buffer.from(`${line}\n`));
  const second = parseExport(Buffer.from(`${line}\n`));

  assert.equal(first.length, 1);
  assert.equal(first[0].id, second[0].id);
  assert.throws(() => parseExport(Buffer.from(`${line}\n${line}\n`)), /duplicate record/);
  assert.throws(() => parseExport(Buffer.from('\n')), /contains no records/);
  assert.throws(() => parseExport(Buffer.from('{nope}\n')), /not valid JSON/);
  assert.throws(
    () => parseExport(Buffer.from(`${line}\n`), { maxBytes: 8 }),
    /exceeds 8 bytes/
  );
});

test('reads bounded NDJSON streams without writing an intermediate file', async () => {
  const payload = Buffer.from(`${JSON.stringify(record())}\n`);
  const bytes = await readExportStream(Readable.from([payload.subarray(0, 17), payload.subarray(17)]));
  assert.deepEqual(bytes, payload);
  await assert.rejects(
    readExportStream(Readable.from([payload]), { maxBytes: 8 }),
    /exceeds 8 bytes/
  );
});

test('fetches with an environment-style bearer token and refuses redirects', async () => {
  const token = 't'.repeat(32);
  const payload = Buffer.from(`${JSON.stringify(record())}\n`);
  let request;
  const bytes = await fetchExport(
    'https://fcaptcha.webdecoy.com/api/research/captures',
    token,
    {
      fetchImpl: async (url, options) => {
        request = { url: String(url), options };
        return new Response(payload, {
          status: 200,
          headers: { 'content-type': 'application/x-ndjson; charset=utf-8' },
        });
      },
    }
  );

  assert.equal(request.url, 'https://fcaptcha.webdecoy.com/api/research/captures');
  assert.equal(request.options.redirect, 'manual');
  assert.equal(request.options.headers.Authorization, `Bearer ${token}`);
  assert.deepEqual(bytes, payload);

  await assert.rejects(
    fetchExport('https://fcaptcha.webdecoy.com/api/research/captures', token, {
      fetchImpl: async () => new Response(null, {
        status: 302,
        headers: { location: 'https://example.com/steal' },
      }),
    }),
    /refused a redirect/
  );
  await assert.rejects(
    fetchExport('http://fcaptcha.webdecoy.com/api/research/captures', token),
    /must be HTTPS/
  );
  await assert.rejects(
    fetchExport('https://fcaptcha.webdecoy.com/api/research/captures?copy=1', token),
    /without credentials, a query, or a fragment/
  );
  await assert.rejects(
    fetchExport('https://fcaptcha.webdecoy.com/api/research/captures', token, {
      maxBytes: 8,
      fetchImpl: async () => new Response(payload, {
        status: 200,
        headers: {
          'content-length': String(payload.length),
          'content-type': 'application/x-ndjson',
        },
      }),
    }),
    /exceeds 8 bytes/
  );
});
