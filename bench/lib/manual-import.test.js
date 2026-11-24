'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { toCorpusSample, toBrowserInternalSample } = require('./manual-import');

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
  assert.equal(sample.capture.endpoint, '/api/verify');
  assert.match(sample.capture.reportSha256, /^[a-f0-9]{64}$/);
});

test('pins released-client provenance and requires the new neutral telemetry', () => {
  const released = report();
  const capture = released.samples[0].capture;
  capture.clientVersion = '1.51.4';
  capture.clientSha256 = 'a'.repeat(64);
  capture.request.signals.behavioral = {
    inputForensics: { clickPrelude: { version: 1 }, keyTiming: { version: 1 } },
  };
  const pinned = { ...options, expectedClientVersion: '1.51.4' };
  const sample = toCorpusSample(released, pinned, Buffer.from('released-report'));

  assert.equal(sample.capture.clientVersion, '1.51.4');
  assert.equal(sample.capture.clientSha256, 'a'.repeat(64));

  capture.clientVersion = '1.51.3';
  assert.throws(() => toCorpusSample(released, pinned), /expected FCaptcha client 1\.51\.4/);
  capture.clientVersion = '1.51.4';
  delete capture.request.signals.behavioral.inputForensics.keyTiming;
  assert.throws(() => toCorpusSample(released, pinned), /input telemetry is missing/);
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

function browserInternalReport(overrides = {}) {
  return report({
    label: 'agent',
    agent: 'Chrome Auto Browse (Gemini)',
    inputSource: 'operator-declared browser-internal automation',
    operatorOutcome: 'completed',
    ...overrides,
  });
}

const browserInternalOptions = {
  scenario: 'chrome-auto-browse-widget',
  input: 'browser-internal pointer and keyboard',
  index: 0,
};

test('imports a driver-free browser-internal capture as an agent', () => {
  const sample = toBrowserInternalSample(
    browserInternalReport(), browserInternalOptions, Buffer.from('agent-report')
  );

  assert.equal(sample.id, 'agent/chrome-auto-browse-widget/0000');
  assert.equal(sample.label, 'agent');
  assert.equal(sample.group, 'browser-internal');
  assert.equal(sample.capture.agent, 'Chrome Auto Browse (Gemini)');
  assert.equal(sample.capture.endpoint, '/api/verify');
  assert.equal(sample.signals.meta.challengeNonce, undefined);
  assert.equal(sample.headers.Host, undefined);
  assert.match(sample.capture.reportSha256, /^[a-f0-9]{64}$/);
});

test('browser-internal importer rejects human, driven, and normalized reports', () => {
  assert.throws(
    () => toBrowserInternalSample(report(), browserInternalOptions),
    /label must be agent/
  );
  assert.throws(
    () => toBrowserInternalSample(
      browserInternalReport({ inputSource: 'playwright' }), browserInternalOptions
    ),
    /not recorded in external browser-internal mode/
  );
  assert.throws(
    () => toBrowserInternalSample(
      browserInternalReport({ normalization: 'environment-normalized' }), browserInternalOptions
    ),
    /must not be normalized/
  );
  assert.throws(
    () => toBrowserInternalSample(
      browserInternalReport({ operatorOutcome: 'takeover' }), browserInternalOptions
    ),
    /did not confirm completion without takeover/
  );
  assert.throws(
    () => toBrowserInternalSample(
      browserInternalReport({ operatorOutcome: undefined }), browserInternalOptions
    ),
    /did not confirm completion without takeover/
  );
});
