'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { computeMetrics } = require('./metrics');
const { renderResearchReport } = require('./report');

test('research-only report is explicitly exploratory and contains no gate claims', () => {
  const results = [{
    sample: {
      id: 'human/hosted-demo-chrome-macos-trackpad/research-0000',
      label: 'human',
      group: 'self-reported-chrome-macos-trackpad',
      provenance: 'self-reported',
      capture: {
        browser: 'chrome',
        os: 'macos',
        input: 'trackpad',
        endpoint: 'verify',
      },
    },
    score: 0.2,
    recommendation: 'allow',
    detections: [{ reason: 'Observed signal', category: 'behavioral' }],
  }];
  const report = renderResearchReport(results, computeMetrics(results));

  assert.match(report, /Exploratory only/);
  assert.match(report, /chrome\/macos/);
  assert.match(report, /trackpad/);
  assert.match(report, /Observed signal/);
  assert.doesNotMatch(report, /Human panel|Agent corpus|Gate/);
});
