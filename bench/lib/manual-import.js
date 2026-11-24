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

function validateReleasedClient(capture, signals, expectedVersion) {
  if (!expectedVersion) return;
  if (capture.clientVersion !== expectedVersion) {
    fail(`expected FCaptcha client ${expectedVersion}, captured ${capture.clientVersion || 'no version'}`);
  }
  if (!/^[a-f0-9]{64}$/.test(capture.clientSha256 || '')) {
    fail('captured client SHA-256 is missing or invalid');
  }
  const forensics = signals.behavioral?.inputForensics;
  if (forensics?.clickPrelude?.version !== 1 || forensics?.keyTiming?.version !== 1) {
    fail('released browser-internal input telemetry is missing');
  }
}

function clientMetadata(capture) {
  return {
    clientVersion: capture.clientVersion || null,
    clientSha256: capture.clientSha256 || null,
  };
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
  validateReleasedClient(capture, signals, options.expectedClientVersion);

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
      ...clientMetadata(capture),
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
  if (source.operatorOutcome !== 'completed') {
    fail('operator did not confirm completion without takeover');
  }
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
  validateReleasedClient(capture, signals, options.expectedClientVersion);

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
      ...clientMetadata(capture),
      reportSha256: reportBytes
        ? crypto.createHash('sha256').update(reportBytes).digest('hex')
        : null,
    },
  };
}

function toExternalDriverSample(report, options, reportBytes = null) {
  if (!report || typeof report !== 'object') fail('report must be an object');
  if (!Array.isArray(report.samples) || report.samples.length !== 1) {
    fail('report must contain exactly one sample');
  }

  const source = report.samples[0];
  if (source.label !== 'agent') fail('sample label must be agent');
  if (source.provenance !== 'captured') fail('sample provenance must be captured');
  if (source.inputSource !== 'operator-declared external browser automation') {
    fail('sample was not recorded in external-driver mode');
  }
  if (source.operatorOutcome !== 'completed') {
    fail('operator did not confirm completion without takeover');
  }
  if (source.normalization !== 'none') fail('external-driver sample must not be normalized');
  if (source.error) fail(source.error);

  const driver = source.driver;
  if (!driver || typeof driver !== 'object' || Array.isArray(driver)) {
    fail('external driver provenance is missing');
  }
  for (const field of ['name', 'version', 'commit']) {
    if (!String(driver[field] || '').trim()) fail(`external driver ${field} is missing`);
  }
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(driver.name)) {
    fail('external driver name must be a lowercase hyphenated slug');
  }
  if (!/^[a-f0-9]{40}$/.test(driver.commit)) {
    fail('external driver commit must be a full lowercase Git SHA');
  }
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(driver.version)) {
    fail('external driver version must be semantic');
  }
  const expected = {
    name: options.expectedDriverName,
    version: options.expectedDriverVersion,
    commit: options.expectedDriverCommit,
  };
  for (const [field, value] of Object.entries(expected)) {
    if (!value) fail(`expected external driver ${field} is required`);
    if (driver[field] !== value) {
      fail(`expected external driver ${field} ${value}, captured ${driver[field]}`);
    }
  }

  const capture = source.capture;
  const signals = capture?.request?.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) {
    fail('capture.request.signals is missing');
  }
  if (!['/api/score', '/api/verify'].includes(capture.endpoint)) {
    fail(`unexpected scoring endpoint ${capture.endpoint || '(missing)'}`);
  }
  validateReleasedClient(capture, signals, options.expectedClientVersion);

  const cleanSignals = structuredClone(signals);
  if (cleanSignals.meta) delete cleanSignals.meta.challengeNonce;
  const browser = String(source.browser || 'operator-described browser');
  const input = String(options.input || 'external browser automation');
  const notes = options.notes ||
    `${driver.name} ${driver.version} (${driver.commit}) in ${browser}; ` +
    `input: ${input}; mode: ${source.mode || 'unknown'}; no normalization`;

  return {
    id: `agent/${options.scenario}/${String(options.index).padStart(4, '0')}`,
    label: 'agent',
    group: `${driver.name}-cdp-agent`,
    scenario: options.scenario,
    provenance: 'captured',
    notes,
    headers: selectedHeaders(capture.headers),
    signals: cleanSignals,
    capture: {
      browser,
      driver: structuredClone(driver),
      input,
      endpoint: capture.endpoint,
      mode: source.mode || null,
      normalization: source.normalization,
      ...clientMetadata(capture),
      reportSha256: reportBytes
        ? crypto.createHash('sha256').update(reportBytes).digest('hex')
        : null,
    },
  };
}

module.exports = {
  selectedHeaders,
  toBrowserInternalSample,
  toCorpusSample,
  toExternalDriverSample,
  validateReleasedClient,
};
