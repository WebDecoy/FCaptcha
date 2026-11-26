'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  CONSENT_STATEMENT,
  prepareContribution,
  summarizeCommunityCoverage,
} = require('./community-contribution');

function contribution(overrides = {}) {
  const base = {
    schemaVersion: 1,
    publicationConsent: {
      permanentPublic: true,
      license: 'MIT',
      statement: CONSENT_STATEMENT,
    },
    attestations: {
      freshTestContext: true,
      noPersonalAccounts: true,
      noUnrelatedExtensions: true,
      noPersonalHistory: true,
      noPersonalFormContent: true,
      noOperationalIdentifiers: true,
      familyNonceScopedToThisDataset: true,
      labelAccurate: true,
    },
    captureFamilyNonce: 'a'.repeat(64),
    sample: {
      label: 'human',
      scenario: 'safari-macos-voiceover-keyboard',
      captureMethod: 'manual-browser',
      labelEvidence: 'verified-human',
      limitations: ['One operator and one hardware configuration.'],
      environment: {
        browser: { name: 'safari', versionMajor: 26 },
        os: { name: 'macos', versionMajor: 26 },
        inputMethods: ['keyboard'],
        assistiveTechnology: [
          { name: 'voiceover', versionMajor: 26, settings: ['quick-nav-on'] },
        ],
      },
      endpoint: '/api/verify',
      mode: 'widget',
      signals: {
        meta: { challengeNonce: 'must-not-survive', stable: true },
        environmental: {
          canvasHash: { hash: '0123456789abcdef', supported: true },
          screen: { width: 1920, height: 1080 },
        },
        formAnalysis: {
          textareaKeyboard: {
            message: { contentLength: 18, keyCount: 18 },
          },
        },
      },
    },
  };
  return {
    ...base,
    ...overrides,
    publicationConsent: { ...base.publicationConsent, ...(overrides.publicationConsent || {}) },
    attestations: { ...base.attestations, ...(overrides.attestations || {}) },
    sample: { ...base.sample, ...(overrides.sample || {}) },
  };
}

test('prepares a permanent-publication sample and machine-readable redaction manifest', () => {
  const { sample, manifest } = prepareContribution(contribution());

  assert.match(sample.id, /^human\/safari-macos-voiceover-keyboard\/community-[a-f0-9]{16}$/);
  assert.equal(sample.provenance, 'captured');
  assert.equal(sample.labelEvidence, 'verified-human');
  assert.deepEqual(sample.headers, {});
  assert.equal(sample.signals.meta.challengeNonce, undefined);
  assert.equal(sample.signals.environmental.screen, undefined);
  assert.match(sample.signals.environmental.canvasHash.hash, /^[a-f0-9]{64}$/);
  assert.notEqual(sample.signals.environmental.canvasHash.hash, '0123456789abcdef');
  assert.deepEqual(Object.keys(sample.signals.formAnalysis.textareaKeyboard), ['field_1']);
  assert.equal(sample.capture.community.publicationConsent, 'permanent-publication-mit-v1');
  assert.equal(sample.capture.assistiveTechnology[0].name, 'voiceover');
  assert.ok(manifest.redactions.some((entry) => entry.action === 'removed-private-field'));
  assert.ok(manifest.redactions.some((entry) => entry.action === 'removed-screen-geometry'));
  assert.ok(manifest.redactions.some((entry) => entry.action === 'anonymized-field-name'));
  assert.ok(manifest.redactions.some((entry) => entry.action === 'pseudonymized-stable-hash'));
  assert.equal(manifest.checks.secretUrlEmailHostnameTokenLeaks, 'none-found');
});

test('stable signal hashes are family-scoped pseudonyms', () => {
  const first = prepareContribution(contribution()).sample;
  const repeated = contribution();
  repeated.sample.signals.behavioral = { totalPoints: 42 };
  const second = prepareContribution(repeated).sample;
  const otherFamily = prepareContribution(contribution({
    captureFamilyNonce: 'b'.repeat(64),
  })).sample;

  assert.equal(
    first.signals.environmental.canvasHash.hash,
    second.signals.environmental.canvasHash.hash
  );
  assert.notEqual(
    first.signals.environmental.canvasHash.hash,
    otherFamily.signals.environmental.canvasHash.hash
  );
});

test('seven-day research consent cannot be repurposed for permanent publication', () => {
  assert.throws(
    () => prepareContribution(contribution({
      publicationConsent: {
        permanentPublic: false,
        statement: 'I agreed to short-lived research use.',
      },
    })),
    /permanent public publication consent is required/
  );
});

test('requires every isolation attestation and declared limitation', () => {
  assert.throws(
    () => prepareContribution(contribution({ attestations: { noPersonalAccounts: false } })),
    /noPersonalAccounts must be true/
  );
  assert.throws(
    () => prepareContribution(contribution({ sample: { limitations: [] } })),
    /limitations must contain/
  );
});

test('rejects schema drift and bounded-field violations', () => {
  assert.throws(
    () => prepareContribution({ ...contribution(), contributorName: 'not accepted' }),
    /unknown field contributorName/
  );
  assert.throws(
    () => prepareContribution(contribution({
      sample: { limitations: ['x'.repeat(241)] },
    })),
    /1 to 240 characters/
  );
  let deep = { valueAtLimit: true };
  for (let index = 0; index < 26; index++) deep = { nested: deep };
  assert.throws(
    () => prepareContribution(contribution({ sample: { signals: deep } })),
    /nesting limit/
  );
});

test('rejects URL, email, hostname, IP, token, and content-field leaks', () => {
  const cases = [
    ['URL', { note: 'https://private.example/path' }],
    ['URL', { canvasHash: { hash: 'https://private.example/fingerprint' } }],
    ['email address', { note: 'person@example.com' }],
    ['IP address', { note: '192.0.2.10' }],
    ['authorization token', { note: 'Bearer abcdefghijklmnop' }],
    ['sensitive content field', { value: 'private form content' }],
  ];
  for (const [message, signals] of cases) {
    assert.throws(
      () => prepareContribution(contribution({ sample: { signals } })),
      new RegExp(message),
      message
    );
  }
});

test('accessibility tooling remains legitimate human evidence', () => {
  const { sample } = prepareContribution(contribution({
    sample: {
      scenario: 'edge-windows-nvda-keyboard',
      environment: {
        browser: { name: 'edge', versionMajor: 156 },
        os: { name: 'windows', versionMajor: 11 },
        inputMethods: ['keyboard'],
        assistiveTechnology: [
          { name: 'nvda', versionMajor: 2026, settings: ['browse-mode'] },
        ],
      },
    },
  }));
  assert.equal(sample.label, 'human');
  assert.equal(sample.labelEvidence, 'verified-human');
  assert.equal(sample.capture.assistiveTechnology[0].name, 'nvda');
});

test('agent contributions require pinned actor metadata and observed-agent evidence', () => {
  const source = contribution({
    sample: {
      label: 'agent',
      scenario: 'chrome-browser-use-form',
      captureMethod: 'external-cdp',
      labelEvidence: 'observed-agent',
      actor: { name: 'browser-use', version: '0.11.2', commit: 'b'.repeat(40) },
      environment: {
        browser: { name: 'chrome', versionMajor: 156 },
        os: { name: 'macos', versionMajor: 26 },
        inputMethods: ['mouse', 'keyboard'],
        assistiveTechnology: [],
      },
    },
  });
  const { sample } = prepareContribution(source);
  assert.equal(sample.labelEvidence, 'observed-agent');
  assert.equal(sample.capture.actor.name, 'browser-use');

  delete source.sample.actor;
  assert.throws(() => prepareContribution(source), /require sample.actor/);
});

test('detects exact duplicates and records repeated capture families', () => {
  const first = prepareContribution(contribution()).sample;
  assert.throws(
    () => prepareContribution(contribution(), [first]),
    /exact sanitized capture already exists/
  );
  assert.throws(
    () => prepareContribution(contribution({ captureFamilyNonce: 'b'.repeat(64) }), [first]),
    /exact sanitized capture already exists/
  );

  const changed = contribution();
  changed.sample.signals.behavioral = { totalPoints: 42 };
  const second = prepareContribution(changed, [first]);
  assert.equal(second.manifest.checks.existingCaptureFamilySamples, 1);
  assert.equal(second.sample.capture.community.familyId, first.capture.community.familyId);
  assert.notEqual(second.sample.capture.community.sampleFingerprint, first.capture.community.sampleFingerprint);
});

test('coverage is aggregate and never exposes family or contributor identifiers', () => {
  const first = prepareContribution(contribution()).sample;
  const changed = contribution();
  changed.sample.signals.behavioral = { totalPoints: 42 };
  const second = prepareContribution(changed, [first]).sample;
  const coverage = summarizeCommunityCoverage([first, second]);
  const serialized = JSON.stringify(coverage);

  assert.equal(coverage.captures, 2);
  assert.equal(coverage.captureFamilies, 1);
  assert.deepEqual(coverage.browsers, { safari: 2 });
  assert.deepEqual(coverage.assistiveTechnology, { voiceover: 2 });
  assert.equal(serialized.includes(first.capture.community.familyId), false);
  assert.equal(serialized.includes(first.id), false);
});
