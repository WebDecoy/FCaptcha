'use strict';

const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const { CONSENT_STATEMENT } = require('./community-contribution');
const { parseArgs, run } = require('../tools/prepare-community-contribution');

function source() {
  return {
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
    captureFamilyNonce: 'd'.repeat(64),
    sample: {
      label: 'human',
      scenario: 'firefox-linux-keyboard',
      captureMethod: 'manual-browser',
      labelEvidence: 'verified-human',
      limitations: ['One operator and one browser profile.'],
      environment: {
        browser: { name: 'firefox', versionMajor: 160 },
        os: { name: 'linux', versionMajor: 26 },
        inputMethods: ['keyboard'],
        assistiveTechnology: [],
      },
      endpoint: '/api/score',
      mode: 'invisible',
      signals: { meta: { challengeNonce: 'removed', stable: true } },
    },
  };
}

test('community CLI parses explicit input, sample, and manifest paths', () => {
  const args = parseArgs([
    'node', 'prepare-community-contribution.js',
    '--input', 'capture.json',
    '--sample-out', 'sample.json',
    '--manifest-out', 'manifest.json',
  ]);
  assert.deepEqual(args, {
    input: 'capture.json',
    sampleOut: 'sample.json',
    manifestOut: 'manifest.json',
  });
});

test('community CLI writes reviewable sample and manifest without overwriting', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fcaptcha-community-'));
  try {
    const input = path.join(directory, 'capture.json');
    const sampleOut = path.join(directory, 'sample.json');
    const manifestOut = path.join(directory, 'manifest.json');
    fs.writeFileSync(input, `${JSON.stringify(source(), null, 2)}\n`);

    const result = run({ input, sampleOut, manifestOut });
    const samples = JSON.parse(fs.readFileSync(sampleOut, 'utf8'));
    const manifest = JSON.parse(fs.readFileSync(manifestOut, 'utf8'));

    assert.equal(samples.length, 1);
    assert.equal(samples[0].id, result.sample.id);
    assert.equal(samples[0].signals.meta.challengeNonce, undefined);
    assert.match(manifest.inputSha256, /^[a-f0-9]{64}$/);
    assert.match(manifest.sampleSha256, /^[a-f0-9]{64}$/);
    assert.equal(manifest.sampleId, result.sample.id);
    assert.throws(() => run({ input, sampleOut, manifestOut }), /refusing to overwrite/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
