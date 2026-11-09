'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { toCorpusSample } = require('./manual-import');

function report(overrides = {}) {
  return {
    samples: [{
      browser: 'Chrome 155, macOS',
      label: 'human',
      inputSource: 'operator-declared manual input',
      provenance: 'captured',
      normalization: 'none',
      mode: 'widget',
      capture: {
        endpoint: '/api/verify',
        headers: {
          Host: '127.0.0.1:1234',
          'User-Agent': 'captured browser',
          'Accept-Language': 'en-US',
          Origin: 'http://127.0.0.1:1234',
        },
        request: {
          signals: { meta: { challengeNonce: 'dead', userAgent: 'captured browser' } },
        },
      },
      ...overrides,
    }],
  };
}

const options = {
  group: 'real-trackpad',
  scenario: 'chrome-macos-trackpad',
  input: 'built-in trackpad',
  index: 0,
};

test('imports manual signals without stale challenge state or transport litter', () => {
  const sample = toCorpusSample(report(), options, Buffer.from('report'));

  assert.equal(sample.id, 'human/chrome-macos-trackpad/0000');
  assert.equal(sample.signals.meta.challengeNonce, undefined);
  assert.equal(sample.headers['User-Agent'], 'captured browser');
  assert.equal(sample.headers.Host, undefined);
  assert.equal(sample.headers.Origin, undefined);
  assert.match(sample.capture.reportSha256, /^[a-f0-9]{64}$/);
});

test('rejects automated and normalized samples', () => {
  assert.throws(
    () => toCorpusSample(report({ inputSource: 'playwright' }), options),
    /not recorded as manual input/
  );
  assert.throws(
    () => toCorpusSample(report({ normalization: 'environment-normalized' }), options),
    /must not be normalized/
  );
});
