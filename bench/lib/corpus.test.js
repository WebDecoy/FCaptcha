'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { deriveVariant, loadCorpus, validate } = require('./corpus');

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
