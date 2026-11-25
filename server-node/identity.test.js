'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { identityObservation, IDENTITY_POLICY } = require('./identity');
const { evaluateExperimental } = require('./experimental');
const fixtures = require('../test/fixtures/identity-coherence.json');

for (const fixture of fixtures.cases) {
  test(`identity parity: ${fixture.name}`, () => {
    const before = JSON.stringify(fixture);
    assert.deepEqual(identityObservation(fixture.signals, fixture.ja4), fixture.expected);
    // Observe-only even when an operator has opted into a blocking policy.
    assert.deepEqual(
      evaluateExperimental(fixture.signals, 0.1, [], true, { ja4: fixture.ja4 })
        .observations[IDENTITY_POLICY],
      fixture.expected);
    assert.equal(JSON.stringify(fixture), before, 'observations must not mutate inputs');
  });
}
