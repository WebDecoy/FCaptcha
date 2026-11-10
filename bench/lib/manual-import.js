'use strict';

const crypto = require('crypto');

const REPLAY_HEADERS = new Set([
  'accept-encoding',
  'accept-language',
  'dnt',
  'priority',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'user-agent',
]);

function fail(message) {
  throw new Error(`invalid manual capture: ${message}`);
}

function selectedHeaders(headers = {}) {
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => REPLAY_HEADERS.has(name.toLowerCase()))
  );
}

function toCorpusSample(report, options, reportBytes = null) {
  if (!report || typeof report !== 'object') fail('report must be an object');
  if (!Array.isArray(report.samples) || report.samples.length !== 1) {
    fail('report must contain exactly one sample');
  }

  const source = report.samples[0];
  if (source.label !== 'human') fail('sample label must be human');
  if (source.provenance !== 'captured') fail('sample provenance must be captured');
  if (source.inputSource !== 'operator-declared manual input' &&
      !String(source.inputSource || '').toLowerCase().includes('user completed')) {
    fail('sample was not recorded as manual input');
  }
  if (source.normalization !== 'none') fail('manual sample must not be normalized');
  if (source.error) fail(source.error);

  const capture = source.capture;
  const signals = capture?.request?.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) {
    fail('capture.request.signals is missing');
  }
  if (!['/api/score', '/api/verify'].includes(capture.endpoint)) {
    fail(`unexpected scoring endpoint ${capture.endpoint || '(missing)'}`);
  }

  const cleanSignals = structuredClone(signals);
  if (cleanSignals.meta) delete cleanSignals.meta.challengeNonce;

  const browser = String(source.browser || options.environment || 'operator-described browser');
  const input = String(options.input || 'operator-described input');
  const notes = options.notes ||
    `real person using ${browser}; input: ${input}; mode: ${source.mode || 'unknown'}; no normalization`;

  return {
    id: `human/${options.scenario}/${String(options.index).padStart(4, '0')}`,
    label: 'human',
    group: options.group,
    scenario: options.scenario,
    provenance: 'captured',
    notes,
    headers: selectedHeaders(capture.headers),
    signals: cleanSignals,
    capture: {
      browser,
      input,
      endpoint: capture.endpoint,
      mode: source.mode || null,
      normalization: source.normalization,
      reportSha256: reportBytes
        ? crypto.createHash('sha256').update(reportBytes).digest('hex')
        : null,
    },
  };
}

function toBrowserInternalSample(report, options, reportBytes = null) {
  if (!report || typeof report !== 'object') fail('report must be an object');
  if (!Array.isArray(report.samples) || report.samples.length !== 1) {
    fail('report must contain exactly one sample');
  }

  const source = report.samples[0];
  if (source.label !== 'agent') fail('sample label must be agent');
  if (source.provenance !== 'captured') fail('sample provenance must be captured');
  if (source.inputSource !== 'operator-declared browser-internal automation') {
    fail('sample was not recorded in external browser-internal mode');
  }
  if (!String(source.agent || '').trim()) fail('browser-internal agent label is missing');
  if (source.normalization !== 'none') fail('browser-internal sample must not be normalized');
  if (source.error) fail(source.error);

  const capture = source.capture;
  const signals = capture?.request?.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) {
    fail('capture.request.signals is missing');
  }
  if (!['/api/score', '/api/verify'].includes(capture.endpoint)) {
    fail(`unexpected scoring endpoint ${capture.endpoint || '(missing)'}`);
  }

  const cleanSignals = structuredClone(signals);
  if (cleanSignals.meta) delete cleanSignals.meta.challengeNonce;
  const browser = String(source.browser || 'operator-described browser');
  const agent = String(source.agent);
  const input = String(options.input || 'browser-internal actuation');
  const notes = options.notes ||
    `${agent} in ${browser}; input: ${input}; mode: ${source.mode || 'unknown'}; no external driver or normalization`;

  return {
    id: `agent/${options.scenario}/${String(options.index).padStart(4, '0')}`,
    label: 'agent',
    group: 'browser-internal',
    scenario: options.scenario,
    provenance: 'captured',
    notes,
    headers: selectedHeaders(capture.headers),
    signals: cleanSignals,
    capture: {
      browser,
      agent,
      input,
      endpoint: capture.endpoint,
      mode: source.mode || null,
      normalization: source.normalization,
      reportSha256: reportBytes
        ? crypto.createHash('sha256').update(reportBytes).digest('hex')
        : null,
    },
  };
}

module.exports = { selectedHeaders, toCorpusSample, toBrowserInternalSample };
