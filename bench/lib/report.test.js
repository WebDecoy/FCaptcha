'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { computeMetrics } = require('./metrics');
const { renderHostedSmokeReport, renderReport, renderResearchReport } = require('./report');

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
    experimental: {
      observations: {
        'animation-consistency-v1': { mode: 'observe', status: 'clear', detections: [] },
      },
    },
  }];
  const report = renderResearchReport(results, computeMetrics(results));

  assert.match(report, /Exploratory only/);
  assert.match(report, /chrome\/macos/);
  assert.match(report, /trackpad/);
  assert.match(report, /Observed signal/);
  assert.match(report, /Experimental observations — exploratory only/);
  assert.match(report, /animation-consistency-v1/);
  assert.match(report, /0\.00%/);
  assert.doesNotMatch(report, /Human panel|Agent corpus|Gate/);
});

test('hosted smoke report is operational and makes no detection-rate claims', () => {
  const results = [
    {
      sample: {
        id: 'human/widget/0000',
        label: 'human',
        group: 'widget-human',
        scenario: 'widget-human',
        capture: { endpoint: '/api/verify' },
      },
      score: 0.95,
      recommendation: 'block',
      detections: [{ reason: 'shared egress artifact' }],
    },
    {
      sample: {
        id: 'agent/invisible/0000',
        label: 'agent',
        group: 'invisible-agent',
        scenario: 'invisible-agent',
        capture: { endpoint: '/api/score' },
      },
      error: '/api/score returned 503',
    },
  ];
  const report = renderHostedSmokeReport(results);

  assert.match(report, /Operational only/);
  assert.match(report, /\/api\/verify/);
  assert.match(report, /\/api\/score/);
  assert.match(report, /1\/2 checks completed/);
  assert.match(report, /returned 503/);
  assert.doesNotMatch(report, /0\.950|block|shared egress artifact/);
  assert.doesNotMatch(report, /Human panel|Agent corpus|Gate/);
});

test('repeated community captures report one family without inventing exclusions', () => {
  const familyId = 'a'.repeat(64);
  const result = (id) => ({
    sample: {
      id,
      label: 'human',
      group: 'community-keyboard',
      provenance: 'captured',
      captureMethod: 'manual-browser',
      labelEvidence: 'verified-human',
      caveats: ['One operator.'],
      capture: { community: { familyId } },
    },
    score: 0.1,
    detections: [],
  });
  const results = [result('human/community/0000'), result('human/community/0001')];
  const report = renderReport(
    computeMetrics(results),
    results.map((row) => row.sample),
    { failures: [], warnings: [], exempted: [] }
  );

  assert.match(report, /0\/1 independently observed capture families; 0\/2 base captures/);
  assert.doesNotMatch(report, /fixture\(s\) measured but excluded/);
});
