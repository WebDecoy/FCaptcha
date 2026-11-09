'use strict';

const fs = require('fs');
const { TextDecoder } = require('util');

const DEFAULT_EXPORT_URL = 'https://fcaptcha.webdecoy.com/api/research/captures';
const MAX_EXPORT_BYTES = 64 * 1024 * 1024;
const MAX_RECORD_BYTES = 2 * 1024 * 1024;
const MAX_RECORDS = 5000;
const MAX_SIGNAL_DEPTH = 24;
const MAX_SIGNAL_NODES = 200000;
const MAX_SIGNAL_STRING_BYTES = 16384;

const TOP_LEVEL_FIELDS = new Set([
  'schemaVersion',
  'id',
  'capturedAt',
  'expiresAt',
  'endpoint',
  'label',
  'labelSource',
  'inputMethod',
  'subjectId',
  'browser',
  'os',
  'signals',
  'verdict',
]);
const ENDPOINTS = new Set(['score', 'verify']);
const INPUT_METHODS = new Set(['keyboard', 'mouse', 'touch', 'trackpad', 'unknown']);
const BROWSERS = new Set(['chrome', 'edge', 'firefox', 'other', 'safari']);
const OPERATING_SYSTEMS = new Set(['android', 'ios', 'linux', 'macos', 'other', 'windows']);
const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const PRIVATE_SIGNAL_KEYS = new Set([
  'challengenonce',
  'hostname',
  'ipaddress',
  'localip',
  'screensize',
  'sessionid',
  'sitekey',
  'timestamp',
  'timezone',
  'useragent',
  'viewportsize',
  'widgetid',
]);

function fail(message) {
  throw new Error(`invalid research export: ${message}`);
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireEnum(value, allowed, field) {
  if (typeof value !== 'string' || !allowed.has(value)) {
    fail(`${field} must be one of ${[...allowed].join('|')}`);
  }
}

function validateTimestamp(value, field) {
  const rfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
  if (typeof value !== 'string' || !rfc3339.test(value)) {
    fail(`${field} must be an ISO-8601 timestamp`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) fail(`${field} must be an ISO-8601 timestamp`);
  return parsed;
}

function sanitizeSignals(signals) {
  if (!isPlainObject(signals)) fail('signals must be an object');
  const state = { nodes: 0 };

  const visit = (value, depth, path) => {
    state.nodes++;
    if (state.nodes > MAX_SIGNAL_NODES) fail('signals exceed the node limit');
    if (depth > MAX_SIGNAL_DEPTH) fail('signals exceed the nesting limit');

    if (value === null || typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) fail(`${path} contains a non-finite number`);
      return value;
    }
    if (typeof value === 'string') {
      if (Buffer.byteLength(value, 'utf8') > MAX_SIGNAL_STRING_BYTES) {
        fail(`${path} contains an oversized string`);
      }
      return value;
    }
    if (Array.isArray(value)) {
      return value.map((entry, index) => visit(entry, depth + 1, `${path}[${index}]`));
    }
    if (!isPlainObject(value)) fail(`${path} contains an unsupported value`);

    const out = Object.create(null);
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_OBJECT_KEYS.has(key)) fail(`${path} contains forbidden key ${key}`);
      if (Buffer.byteLength(key, 'utf8') > 128) fail(`${path} contains an oversized key`);
      if (PRIVATE_SIGNAL_KEYS.has(key.toLowerCase())) continue;
      if (path === 'signals.environmental' && key.toLowerCase() === 'screen') continue;
      out[key] = visit(child, depth + 1, `${path}.${key}`);
    }
    return out;
  };

  const clean = visit(signals, 0, 'signals');
  const keyboard = clean.formAnalysis?.textareaKeyboard;
  if (isPlainObject(keyboard)) {
    const anonymized = Object.create(null);
    Object.keys(keyboard).sort().forEach((key, index) => {
      anonymized[`field_${index + 1}`] = keyboard[key];
    });
    clean.formAnalysis.textareaKeyboard = anonymized;
  }
  return clean;
}

function validateRecord(record, lineNumber = null) {
  const location = lineNumber === null ? '' : ` on line ${lineNumber}`;
  if (!isPlainObject(record)) fail(`record${location} must be an object`);
  for (const key of Object.keys(record)) {
    if (FORBIDDEN_OBJECT_KEYS.has(key)) fail(`record${location} contains forbidden key ${key}`);
    if (!TOP_LEVEL_FIELDS.has(key)) fail(`record${location} contains unknown field ${key}`);
  }
  for (const field of TOP_LEVEL_FIELDS) {
    if (!Object.hasOwn(record, field)) fail(`record${location} is missing ${field}`);
  }
  if (record.schemaVersion !== 1) fail(`record${location} has unsupported schemaVersion`);
  if (typeof record.id !== 'string' || !/^[a-f0-9]{32}$/.test(record.id)) {
    fail(`record${location} id must be 32 lowercase hex characters`);
  }
  if (record.label !== 'human' || record.labelSource !== 'self_report') {
    fail(`record${location} must have the self-reported human label`);
  }
  requireEnum(record.endpoint, ENDPOINTS, `record${location} endpoint`);
  requireEnum(record.inputMethod, INPUT_METHODS, `record${location} inputMethod`);
  requireEnum(record.browser, BROWSERS, `record${location} browser`);
  requireEnum(record.os, OPERATING_SYSTEMS, `record${location} os`);
  if (typeof record.subjectId !== 'string' || !/^[a-f0-9]{24}$/.test(record.subjectId)) {
    fail(`record${location} subjectId must be 24 lowercase hex characters`);
  }
  const capturedAt = validateTimestamp(record.capturedAt, `record${location} capturedAt`);
  const expiresAt = validateTimestamp(record.expiresAt, `record${location} expiresAt`);
  if (expiresAt <= capturedAt || expiresAt - capturedAt > 30 * 24 * 60 * 60 * 1000) {
    fail(`record${location} retention window is invalid`);
  }
  if (!isPlainObject(record.verdict)) fail(`record${location} verdict must be an object`);
  return sanitizeSignals(record.signals);
}

function toCorpusSample(record, lineNumber = null, sampleIndex = 0) {
  const signals = validateRecord(record, lineNumber);
  const scenario = `hosted-demo-${record.browser}-${record.os}-${record.inputMethod}`;

  return {
    id: `human/${scenario}/research-${String(sampleIndex).padStart(4, '0')}`,
    label: 'human',
    group: `self-reported-${record.browser}-${record.os}-${record.inputMethod}`,
    scenario,
    provenance: 'self-reported',
    notes: 'explicitly consented hosted-demo trace; visitor supplied the human label; not verified ground truth',
    headers: {},
    signals,
    capture: {
      source: 'hosted-demo',
      labelSource: 'self_report',
      browser: record.browser,
      os: record.os,
      input: record.inputMethod,
      endpoint: record.endpoint,
      schemaVersion: record.schemaVersion,
    },
  };
}

function parseExport(bytes, options = {}) {
  const maxBytes = options.maxBytes || MAX_EXPORT_BYTES;
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length > maxBytes) fail(`export exceeds ${maxBytes} bytes`);

  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    fail('export is not valid UTF-8');
  }
  const lines = text.split('\n');
  const samples = [];
  const sourceIds = new Set();
  const sampleIds = new Set();

  for (let index = 0; index < lines.length; index++) {
    let line = lines[index];
    if (line.endsWith('\r')) line = line.slice(0, -1);
    if (!line.trim()) continue;
    const lineNumber = index + 1;
    if (Buffer.byteLength(line, 'utf8') > MAX_RECORD_BYTES) {
      fail(`record on line ${lineNumber} exceeds ${MAX_RECORD_BYTES} bytes`);
    }
    if (samples.length >= MAX_RECORDS) fail(`export exceeds ${MAX_RECORDS} records`);

    let record;
    try {
      record = JSON.parse(line);
    } catch {
      fail(`line ${lineNumber} is not valid JSON`);
    }
    const sample = toCorpusSample(record, lineNumber, samples.length);
    if (sourceIds.has(record.id) || sampleIds.has(sample.id)) {
      fail(`duplicate record on line ${lineNumber}`);
    }
    sourceIds.add(record.id);
    sampleIds.add(sample.id);
    samples.push(sample);
  }
  if (!samples.length) fail('export contains no records');
  return samples;
}

function readExportFile(file, options = {}) {
  const maxBytes = options.maxBytes || MAX_EXPORT_BYTES;
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) fail('input must be a regular file, not a symlink');
    if (stat.size > maxBytes) fail(`export exceeds ${maxBytes} bytes`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size) {
      fail('input changed while it was being read');
    }
    return bytes;
  } catch (error) {
    if (error?.code === 'ELOOP') fail('input must be a regular file, not a symlink');
    throw error;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

async function readBoundedResponse(response, maxBytes) {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) fail(`export exceeds ${maxBytes} bytes`);
  if (!response.body || typeof response.body.getReader !== 'function') fail('export response has no body');

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      fail(`export exceeds ${maxBytes} bytes`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

async function fetchExport(rawUrl, token, options = {}) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('invalid research export URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    throw new Error('research export URL must be HTTPS without credentials, a query, or a fragment');
  }
  if (url.pathname !== '/api/research/captures') {
    throw new Error('research export URL must use /api/research/captures');
  }
  if (typeof token !== 'string' || token.trim().length < 32) {
    throw new Error('FCAPTCHA_CAPTURE_EXPORT_TOKEN must contain at least 32 characters');
  }

  const fetchImpl = options.fetchImpl || fetch;
  const maxBytes = options.maxBytes || MAX_EXPORT_BYTES;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 15000);
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        Accept: 'application/x-ndjson',
        Authorization: `Bearer ${token.trim()}`,
      },
    });
    if (response.status >= 300 && response.status < 400) {
      throw new Error('research export refused a redirect');
    }
    if (!response.ok) throw new Error(`research export returned HTTP ${response.status}`);
    const contentType = (response.headers.get('content-type') || '').split(';', 1)[0].trim();
    if (contentType !== 'application/x-ndjson') {
      throw new Error(`research export returned unexpected content type ${contentType || '(missing)'}`);
    }
    return await readBoundedResponse(response, maxBytes);
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = {
  DEFAULT_EXPORT_URL,
  MAX_EXPORT_BYTES,
  MAX_RECORDS,
  fetchExport,
  parseExport,
  readExportFile,
  sanitizeSignals,
  toCorpusSample,
  validateRecord,
};
