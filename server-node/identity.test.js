'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { identityObservation, IDENTITY_POLICY } = require('./identity');
const { evaluateExperimental } = require('./experimental');
const fixtures = require('../test/fixtures/identity-coherence.json');

for (const fixture of fixtures.cases) {
  test(`identity parity: ${fixture.name}`, () => {
    const before = JSON.stringify(fixture);
    assert.deepEqual(identityObservation(fixture.signals), fixture.expected);
    // Observe-only even when an operator has opted into a blocking policy.
    assert.equal(evaluateExperimental(fixture.signals, 0.1, [], true).observations[IDENTITY_POLICY].mode, 'observe');
    assert.equal(JSON.stringify(fixture), before, 'observations must not mutate inputs');
  });
}
