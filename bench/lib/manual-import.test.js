'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  toBrowserInternalSample,
  toCorpusSample,
  toExternalDriverSample,
} = require('./manual-import');

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

test('imports pinned accessibility workflow provenance', () => {
  const manualWorkflow = {
    id: 'screen-reader-keyboard-selection',
    fixture: 'basic',
    tool: {
      name: 'VoiceOver',
      version: 'macOS 26.1 built-in',
      settings: 'Quick Nav off; keyboard selection',
    },
    consent: 'operator-confirmed',
    isolation: 'fresh-test-context-no-personal-data',
    unrelatedProfileData: 'must not survive import',
  };
  const sample = toCorpusSample(
    report({ manualWorkflow }),
    { ...options, expectedWorkflow: manualWorkflow.id }
  );

  assert.deepEqual(sample.capture.workflow, {
    id: manualWorkflow.id,
    fixture: manualWorkflow.fixture,
    tool: manualWorkflow.tool,
    consent: manualWorkflow.consent,
    isolation: manualWorkflow.isolation,
  });
  assert.equal(sample.capture.workflow.unrelatedProfileData, undefined);
  assert.notEqual(sample.capture.workflow, manualWorkflow);
});

test('rejects unpinned or unconfirmed accessibility workflow provenance', () => {
  const manualWorkflow = {
    id: 'voice-control-form-entry',
    fixture: 'basic',
    tool: { name: 'Voice Control', version: 'macOS 26.1 built-in', settings: 'default' },
    consent: 'operator-confirmed',
    isolation: 'fresh-test-context-no-personal-data',
  };
  assert.throws(
    () => toCorpusSample(report({ manualWorkflow }), options),
    /requires --expected-workflow/
  );
  assert.throws(
    () => toCorpusSample(
      report({ manualWorkflow }),
      { ...options, expectedWorkflow: 'screen-reader-keyboard-selection' }
    ),
    /expected workflow screen-reader-keyboard-selection, captured voice-control-form-entry/
  );
  assert.throws(
    () => toCorpusSample(
      report({ manualWorkflow: { ...manualWorkflow, consent: 'unknown' } }),
      { ...options, expectedWorkflow: manualWorkflow.id }
    ),
    /consent was not confirmed/
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

const DRIVER_COMMIT = 'c24e5072ee66f8499bacd663f4f4bcb089bc4492';

function externalDriverReport(overrides = {}) {
  const value = report({
    label: 'agent',
    inputSource: 'operator-declared external browser automation',
    operatorOutcome: 'completed',
    driver: {
      name: 'browser-harness',
      version: '0.1.13',
      commit: DRIVER_COMMIT,
    },
    ...overrides,
  });
  const capture = value.samples[0].capture;
  capture.clientVersion = '1.51.4';
  capture.clientSha256 = 'b'.repeat(64);
  capture.request.signals.behavioral = {
    inputForensics: { clickPrelude: { version: 1 }, keyTiming: { version: 1 } },
  };
  return value;
}

const externalDriverOptions = {
  scenario: 'browser-harness-real-chrome-form',
  input: 'Browser Harness over loopback CDP',
  index: 2,
  expectedClientVersion: '1.51.4',
  expectedDriverName: 'browser-harness',
  expectedDriverVersion: '0.1.13',
  expectedDriverCommit: DRIVER_COMMIT,
};

test('imports a pinned external CDP driver capture into its own cohort', () => {
  const sample = toExternalDriverSample(
    externalDriverReport(), externalDriverOptions, Buffer.from('external-driver-report')
  );

  assert.equal(sample.id, 'agent/browser-harness-real-chrome-form/0002');
  assert.equal(sample.group, 'browser-harness-cdp-agent');
  assert.equal(sample.capture.driver.name, 'browser-harness');
  assert.equal(sample.capture.driver.version, '0.1.13');
  assert.equal(sample.capture.driver.commit, DRIVER_COMMIT);
  assert.equal(sample.capture.endpoint, '/api/verify');
  assert.equal(sample.signals.meta.challengeNonce, undefined);
  assert.match(sample.capture.reportSha256, /^[a-f0-9]{64}$/);
});

test('imports an independent external-driver cohort into a distinct group', () => {
  const sample = toExternalDriverSample(
    externalDriverReport(),
    { ...externalDriverOptions, group: 'browser-harness-macbook-cdp-agent' }
  );

  assert.equal(sample.group, 'browser-harness-macbook-cdp-agent');
});

test('external-driver importer rejects takeover and provenance mismatches', () => {
  assert.throws(
    () => toExternalDriverSample(report(), externalDriverOptions),
    /label must be agent/
  );
  assert.throws(
    () => toExternalDriverSample(
      externalDriverReport({ inputSource: 'operator-declared browser-internal automation' }),
      externalDriverOptions
    ),
    /not recorded in external-driver mode/
  );
  assert.throws(
    () => toExternalDriverSample(
      externalDriverReport({ operatorOutcome: 'takeover' }), externalDriverOptions
    ),
    /did not confirm completion without takeover/
  );
  assert.throws(
    () => toExternalDriverSample(
      externalDriverReport({ normalization: 'environment-normalized' }), externalDriverOptions
    ),
    /must not be normalized/
  );
  assert.throws(
    () => toExternalDriverSample(
      externalDriverReport({
        driver: { name: 'browser-harness', version: '0.1.14', commit: DRIVER_COMMIT },
      }),
      externalDriverOptions
    ),
    /expected external driver version 0\.1\.13, captured 0\.1\.14/
  );
  assert.throws(
    () => toExternalDriverSample(
      externalDriverReport({
        driver: { name: 'browser-harness', version: '0.1.13', commit: 'short' },
      }),
      externalDriverOptions
    ),
    /full lowercase Git SHA/
  );
  assert.throws(
    () => toExternalDriverSample(
      externalDriverReport({
        driver: { name: 'browser-harness', version: 'latest', commit: DRIVER_COMMIT },
      }),
      { ...externalDriverOptions, expectedDriverVersion: 'latest' }
    ),
    /version must be semantic/
  );
  assert.throws(
    () => toExternalDriverSample(
      externalDriverReport({
        driver: { name: '../browser-harness', version: '0.1.13', commit: DRIVER_COMMIT },
      }),
      { ...externalDriverOptions, expectedDriverName: '../browser-harness' }
    ),
    /name must be a lowercase hyphenated slug/
  );
});
