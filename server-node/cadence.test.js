'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { analyzeFormInteraction } = require('./detection');
const fixtures = require('../test/fixtures/keystroke-cadence.json');

const CADENCE_REASON = 'Keystroke cadence analysis';
const close = (a, b) => Math.abs(a - b) < 1e-9;

for (const fixture of fixtures.cases) {
  test(`cadence parity: ${fixture.name}`, () => {
    const form = { textareaKeyboard: { message: fixture.stats } };
    const got = analyzeFormInteraction(form, { humanPresent: true })
      .find(d => d.reason.startsWith(CADENCE_REASON));
    const want = fixture.expected;

    if (want === null) {
      assert.equal(got, undefined, `cadence fired: ${JSON.stringify(got)}`);
      return;
    }
    assert.ok(got, 'cadence did not fire');
    assert.equal(got.category, 'bot');
    assert.ok(close(got.score, want.score), `score ${got.score}, want ${want.score}`);
    assert.ok(close(got.confidence, want.confidence), `confidence ${got.confidence}, want ${want.confidence}`);
    assert.ok(close(got.details.cadenceHumanScore, want.cadenceHumanScore),
      `cadenceHumanScore ${got.details.cadenceHumanScore}, want ${want.cadenceHumanScore}`);
    assert.deepEqual(Object.keys(got.details.metrics).sort(), Object.keys(want.metrics).sort());
    for (const [k, w] of Object.entries(want.metrics)) {
      assert.ok(close(got.details.metrics[k], w), `metric ${k} ${got.details.metrics[k]}, want ${w}`);
    }
  });
}
