'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { deriveVariant, loadCorpus, validate, validateCorpusIntegrity } = require('./corpus');

test('every committed sample declares capture method and label evidence', () => {
  const corpus = loadCorpus();
  assert.ok(corpus.length > 0);
  assert.ok(corpus.some((sample) => sample.labelEvidence === 'verified-human'));
  assert.ok(corpus.some((sample) => sample.labelEvidence === 'simulated-human'));
  assert.ok(corpus.some((sample) => sample.labelEvidence === 'observed-agent'));
});

test('human and agent evidence vocabularies cannot be crossed', () => {
  const base = {
    id: 'human/manual/0000',
    label: 'human',
    group: 'manual',
    provenance: 'captured',
    captureMethod: 'manual-browser',
    labelEvidence: 'observed-agent',
    signals: {},
  };
  assert.throws(() => validate(base), /human sample has agent labelEvidence/);
  assert.throws(
    () => validate({ ...base, label: 'agent', labelEvidence: 'verified-human' }),
    /agent sample has human labelEvidence/
  );
});

test('derived variants preserve evidence metadata without becoming independent captures', () => {
  const sample = {
    id: 'human/manual/0000',
    label: 'human',
    group: 'manual',
    provenance: 'captured',
    captureMethod: 'manual-browser',
    labelEvidence: 'verified-human',
    signals: { behavioral: { totalPoints: 10 } },
  };
  const derived = deriveVariant(sample, { jitter: (value) => value }, 0);
  assert.equal(derived.provenance, 'derived');
  assert.equal(derived.source, sample.id);
  assert.equal(derived.captureMethod, sample.captureMethod);
  assert.equal(derived.labelEvidence, sample.labelEvidence);
  assert.doesNotThrow(() => validate(derived));
});

test('community captures require permanent consent metadata and declared limitations', () => {
  const sample = {
    id: 'human/community/0000',
    label: 'human',
    group: 'community',
    provenance: 'captured',
    captureMethod: 'manual-browser',
    labelEvidence: 'verified-human',
    caveats: ['One operator.'],
    signals: {},
    capture: {
      community: {
        schemaVersion: 1,
        familyId: 'a'.repeat(64),
        sampleFingerprint: 'b'.repeat(64),
        publicationConsent: 'permanent-publication-mit-v1',
      },
    },
  };
  assert.doesNotThrow(() => validate(sample));
  assert.throws(
    () => validate({ ...sample, caveats: [] }),
    /must declare limitations/
  );
  assert.throws(
    () => validate({
      ...sample,
      capture: { community: { ...sample.capture.community, publicationConsent: 'seven-day-research' } },
    }),
    /publication consent is missing/
  );
  assert.throws(
    () => validate({
      ...sample,
      capture: { community: { ...sample.capture.community, contributorName: 'not allowed' } },
    }),
    /unknown or missing fields/
  );
});

test('corpus integrity rejects duplicate ids and community fingerprints', () => {
  const first = {
    id: 'human/community/0000',
    capture: { community: { sampleFingerprint: 'c'.repeat(64) } },
  };
  assert.throws(() => validateCorpusIntegrity([first, { ...first }]), /duplicate corpus id/);
  assert.throws(
    () => validateCorpusIntegrity([first, {
      id: 'human/community/0001',
      capture: { community: { sampleFingerprint: 'c'.repeat(64) } },
    }]),
    /duplicate community capture fingerprint/
  );
});
