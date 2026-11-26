'use strict';

const crypto = require('crypto');

const { sanitizeSignals } = require('./research-import');

const COMMUNITY_SCHEMA_VERSION = 1;
const CONSENT_STATEMENT =
  'I consent to permanent public publication of this sanitized FCaptcha benchmark capture under the MIT license.';

const BROWSERS = new Set(['chrome', 'edge', 'firefox', 'safari', 'other']);
const OPERATING_SYSTEMS = new Set(['android', 'ios', 'linux', 'macos', 'windows', 'other']);
const INPUT_METHODS = new Set([
  'autofill',
  'keyboard',
  'mouse',
  'password-manager',
  'switch-input',
  'touch',
  'trackpad',
  'voice-control',
]);
const MODES = new Set(['form', 'invisible', 'widget']);
const ENDPOINTS = new Set(['/api/score', '/api/verify']);
const HUMAN_EVIDENCE = new Set(['verified-human', 'paired-human-control']);
const AGENT_EVIDENCE = new Set(['observed-agent']);
const CAPTURE_METHODS = new Set([
  'automated-browser',
  'browser-internal',
  'external-cdp',
  'manual-browser',
]);
const REQUIRED_ATTESTATIONS = [
  'freshTestContext',
  'noPersonalAccounts',
  'noUnrelatedExtensions',
  'noPersonalHistory',
  'noPersonalFormContent',
  'noOperationalIdentifiers',
  'familyNonceScopedToThisDataset',
  'labelAccurate',
];
const SENSITIVE_KEYS = new Set([
  'authorization',
  'content',
  'cookie',
  'email',
  'href',
  'hostname',
  'innerhtml',
  'innertext',
  'ip',
  'ipaddress',
  'localip',
  'origin',
  'password',
  'rawvalue',
  'secret',
  'text',
  'token',
  'url',
  'value',
]);

function fail(message) {
  throw new Error(`invalid community contribution: ${message}`);
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, allowed, path) {
  if (!isPlainObject(value)) fail(`${path} must be an object`);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${path} contains unknown field ${key}`);
  }
}

function requireSlug(value, path) {
  if (typeof value !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value)) {
    fail(`${path} must be a lowercase hyphenated slug`);
  }
  return value;
}

function requireEnum(value, allowed, path) {
  if (typeof value !== 'string' || !allowed.has(value)) {
    fail(`${path} must be one of ${[...allowed].join('|')}`);
  }
  return value;
}

function requireMajorVersion(value, path) {
  if (!Number.isInteger(value) || value < 1 || value > 9999) {
    fail(`${path} must be an integer from 1 to 9999`);
  }
  return value;
}

function requireSafeVersion(value, path) {
  if (typeof value !== 'string' || value.length > 64 || !/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/.test(value)) {
    fail(`${path} must be a bounded version identifier without spaces`);
  }
  return value;
}

function scanString(value, path) {
  if (Buffer.byteLength(value, 'utf8') > 2048) fail(`${path} contains an oversized string`);
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    fail(`${path} contains control characters`);
  }
  if (/\b(?:https?|wss?):\/\/|\bwww\./i.test(value)) fail(`${path} contains a URL`);
  if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(value)) fail(`${path} contains an email address`);
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(value) || /\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,}\b/i.test(value)) {
    fail(`${path} contains an IP address`);
  }
  if (/\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b/i.test(value)) fail(`${path} contains a hostname`);
  if (/-----BEGIN [A-Z ]+PRIVATE KEY-----/.test(value)) fail(`${path} contains a private key`);
  if (/\b(?:bearer|basic)\s+[A-Za-z0-9+/=_-]{8,}/i.test(value)) fail(`${path} contains an authorization token`);
  if (/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/.test(value)) {
    fail(`${path} contains a JWT-like token`);
  }
}

function scanForLeaks(value, path = 'sample') {
  if (typeof value === 'string') {
    scanString(value, path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => scanForLeaks(entry, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) fail(`${path}.${key} is a sensitive content field`);
    scanForLeaks(child, `${path}.${key}`);
  }
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, stableValue(value[key])])
  );
}

function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function pseudonymizeStableHashes(value, nonce, redactions, path = 'signals') {
  if (Array.isArray(value)) {
    return value.map((entry, index) =>
      pseudonymizeStableHashes(entry, nonce, redactions, `${path}[${index}]`)
    );
  }
  if (!value || typeof value !== 'object') return value;

  const clean = Object.create(null);
  for (const [key, child] of Object.entries(value)) {
    const childPath = `${path}.${key}`;
    if (key.toLowerCase() === 'hash' && (typeof child === 'string' || typeof child === 'number')) {
      clean[key] = crypto
        .createHmac('sha256', Buffer.from(nonce, 'hex'))
        .update(`fcaptcha-community-signal-hash-v1\0${String(child)}`)
        .digest('hex');
      redactions.push({ path: childPath, action: 'pseudonymized-stable-hash' });
      continue;
    }
    clean[key] = pseudonymizeStableHashes(child, nonce, redactions, childPath);
  }
  return clean;
}

function validateEnvironment(environment) {
  exactKeys(environment, new Set(['browser', 'os', 'inputMethods', 'assistiveTechnology']), 'sample.environment');
  exactKeys(environment.browser, new Set(['name', 'versionMajor']), 'sample.environment.browser');
  exactKeys(environment.os, new Set(['name', 'versionMajor']), 'sample.environment.os');

  const clean = {
    browser: {
      name: requireEnum(environment.browser.name, BROWSERS, 'sample.environment.browser.name'),
      versionMajor: requireMajorVersion(environment.browser.versionMajor, 'sample.environment.browser.versionMajor'),
    },
    os: {
      name: requireEnum(environment.os.name, OPERATING_SYSTEMS, 'sample.environment.os.name'),
      versionMajor: requireMajorVersion(environment.os.versionMajor, 'sample.environment.os.versionMajor'),
    },
  };

  if (!Array.isArray(environment.inputMethods) || environment.inputMethods.length < 1 || environment.inputMethods.length > 8) {
    fail('sample.environment.inputMethods must contain 1 to 8 values');
  }
  clean.inputMethods = [...new Set(environment.inputMethods.map((value) =>
    requireEnum(value, INPUT_METHODS, 'sample.environment.inputMethods')
  ))].sort();

  if (!Array.isArray(environment.assistiveTechnology) || environment.assistiveTechnology.length > 8) {
    fail('sample.environment.assistiveTechnology must be an array of at most 8 tools');
  }
  clean.assistiveTechnology = environment.assistiveTechnology.map((tool, index) => {
    const path = `sample.environment.assistiveTechnology[${index}]`;
    exactKeys(tool, new Set(['name', 'versionMajor', 'settings']), path);
    if (!Array.isArray(tool.settings) || tool.settings.length > 16) {
      fail(`${path}.settings must be an array of at most 16 slugs`);
    }
    return {
      name: requireSlug(tool.name, `${path}.name`),
      versionMajor: requireMajorVersion(tool.versionMajor, `${path}.versionMajor`),
      settings: [...new Set(tool.settings.map((setting) => requireSlug(setting, `${path}.settings`)))].sort(),
    };
  }).sort((left, right) => left.name.localeCompare(right.name));
  return clean;
}

function validateActor(actor) {
  exactKeys(actor, new Set(['name', 'version', 'commit']), 'sample.actor');
  const clean = {
    name: requireSlug(actor.name, 'sample.actor.name'),
    version: requireSafeVersion(actor.version, 'sample.actor.version'),
  };
  if (actor.commit !== undefined) {
    if (typeof actor.commit !== 'string' || !/^[a-f0-9]{40}$/.test(actor.commit)) {
      fail('sample.actor.commit must be a full lowercase Git SHA');
    }
    clean.commit = actor.commit;
  }
  return clean;
}

function validateSource(source) {
  exactKeys(
    source,
    new Set(['schemaVersion', 'publicationConsent', 'attestations', 'captureFamilyNonce', 'sample']),
    'contribution'
  );
  if (source.schemaVersion !== COMMUNITY_SCHEMA_VERSION) fail('unsupported schemaVersion');

  exactKeys(source.publicationConsent, new Set(['permanentPublic', 'license', 'statement']), 'publicationConsent');
  if (source.publicationConsent.permanentPublic !== true) fail('permanent public publication consent is required');
  if (source.publicationConsent.license !== 'MIT') fail('publication license must be MIT');
  if (source.publicationConsent.statement !== CONSENT_STATEMENT) fail('publication consent statement does not match');

  exactKeys(source.attestations, new Set(REQUIRED_ATTESTATIONS), 'attestations');
  for (const field of REQUIRED_ATTESTATIONS) {
    if (source.attestations[field] !== true) fail(`attestations.${field} must be true`);
  }
  if (typeof source.captureFamilyNonce !== 'string' || !/^[a-f0-9]{64}$/.test(source.captureFamilyNonce)) {
    fail('captureFamilyNonce must be 64 lowercase hex characters');
  }

  exactKeys(
    source.sample,
    new Set([
      'label', 'scenario', 'captureMethod', 'labelEvidence', 'limitations',
      'environment', 'endpoint', 'mode', 'actor', 'signals',
    ]),
    'sample'
  );
  if (!['human', 'agent'].includes(source.sample.label)) fail('sample.label must be human or agent');
  const scenario = requireSlug(source.sample.scenario, 'sample.scenario');
  const captureMethod = requireEnum(source.sample.captureMethod, CAPTURE_METHODS, 'sample.captureMethod');
  const evidence = source.sample.label === 'human' ? HUMAN_EVIDENCE : AGENT_EVIDENCE;
  const labelEvidence = requireEnum(source.sample.labelEvidence, evidence, 'sample.labelEvidence');
  if (source.sample.label === 'human' && captureMethod !== 'manual-browser') {
    fail('human contributions must use manual-browser captureMethod');
  }
  if (source.sample.label === 'agent' && captureMethod === 'manual-browser') {
    fail('agent contributions must use a browser automation captureMethod');
  }
  if (source.sample.label === 'agent' && !source.sample.actor) fail('agent contributions require sample.actor');
  if (source.sample.label === 'human' && source.sample.actor !== undefined) fail('human contributions must not declare sample.actor');

  if (!Array.isArray(source.sample.limitations) || source.sample.limitations.length < 1 || source.sample.limitations.length > 12) {
    fail('sample.limitations must contain 1 to 12 declared limitations');
  }
  const limitations = source.sample.limitations.map((value, index) => {
    if (typeof value !== 'string' || value.length < 1 || value.length > 240) {
      fail(`sample.limitations[${index}] must contain 1 to 240 characters`);
    }
    scanString(value, `sample.limitations[${index}]`);
    return value;
  });

  return {
    label: source.sample.label,
    scenario,
    captureMethod,
    labelEvidence,
    limitations,
    environment: validateEnvironment(source.sample.environment),
    endpoint: requireEnum(source.sample.endpoint, ENDPOINTS, 'sample.endpoint'),
    mode: requireEnum(source.sample.mode, MODES, 'sample.mode'),
    ...(source.sample.actor ? { actor: validateActor(source.sample.actor) } : {}),
  };
}

function prepareContribution(source, existingCorpus = []) {
  if (!isPlainObject(source)) fail('contribution must be an object');
  const metadata = validateSource(source);
  const redactions = [];
  const sanitizedSignals = sanitizeSignals(source.sample.signals, {
    onRedact: (entry) => redactions.push(entry),
  });
  // Scan before pseudonymization so a malicious value cannot hide a URL,
  // secret, or content leak merely by placing it under a field named `hash`.
  scanForLeaks(sanitizedSignals, 'signals');
  const signals = pseudonymizeStableHashes(
    sanitizedSignals,
    source.captureFamilyNonce,
    redactions
  );
  scanForLeaks(metadata, 'metadata');

  const familyId = sha256(`fcaptcha-community-family-v1\0${source.captureFamilyNonce}`);
  const fingerprintPayload = stableValue({
    schemaVersion: COMMUNITY_SCHEMA_VERSION,
    metadata,
    // Keep duplicate detection independent from the contributor-supplied
    // family nonce. The digest is over the whole sanitized payload; individual
    // stable hash values are still never published.
    signals: sanitizedSignals,
  });
  const sampleFingerprint = sha256(JSON.stringify(fingerprintPayload));
  const existingDuplicate = existingCorpus.find(
    (sample) => sample.capture?.community?.sampleFingerprint === sampleFingerprint
  );
  if (existingDuplicate) fail(`exact sanitized capture already exists as ${existingDuplicate.id}`);
  const existingFamilySamples = existingCorpus.filter(
    (sample) => sample.capture?.community?.familyId === familyId
  ).length;

  const prefix = metadata.label === 'human' ? 'human' : 'agent';
  const id = `${prefix}/${metadata.scenario}/community-${sampleFingerprint.slice(0, 16)}`;
  if (existingCorpus.some((sample) => sample.id === id)) fail(`corpus already contains id ${id}`);

  const assistiveNames = metadata.environment.assistiveTechnology.map((tool) => tool.name);
  const notes = metadata.label === 'human'
    ? `consented community human capture; assistive technology: ${assistiveNames.join(', ') || 'none'}`
    : `consented community observed-agent capture; actor: ${metadata.actor.name} ${metadata.actor.version}`;

  const sample = {
    id,
    label: metadata.label,
    group: `community-${metadata.scenario}`,
    scenario: metadata.scenario,
    provenance: 'captured',
    captureMethod: metadata.captureMethod,
    labelEvidence: metadata.labelEvidence,
    notes,
    caveats: [...metadata.limitations],
    headers: {},
    signals,
    capture: {
      browser: metadata.environment.browser,
      os: metadata.environment.os,
      inputMethods: metadata.environment.inputMethods,
      assistiveTechnology: metadata.environment.assistiveTechnology,
      endpoint: metadata.endpoint,
      mode: metadata.mode,
      ...(metadata.actor ? { actor: metadata.actor } : {}),
      community: {
        schemaVersion: COMMUNITY_SCHEMA_VERSION,
        familyId,
        sampleFingerprint,
        publicationConsent: 'permanent-publication-mit-v1',
      },
    },
  };

  return {
    sample,
    manifest: {
      schemaVersion: COMMUNITY_SCHEMA_VERSION,
      sampleId: id,
      redactions: redactions.sort((left, right) => left.path.localeCompare(right.path)),
      checks: {
        strictSchema: 'passed',
        boundedFields: 'passed',
        secretUrlEmailHostnameTokenLeaks: 'none-found',
        exactCorpusDuplicate: 'none-found',
        existingCaptureFamilySamples: existingFamilySamples,
      },
      publication: {
        permanentPublic: true,
        license: 'MIT',
        consentVersion: 'permanent-publication-mit-v1',
      },
    },
  };
}

function summarizeCommunityCoverage(samples) {
  const community = samples.filter((sample) => sample.capture?.community?.schemaVersion === COMMUNITY_SCHEMA_VERSION);
  const countBy = (values) => Object.fromEntries(
    [...values.reduce((map, value) => map.set(value, (map.get(value) || 0) + 1), new Map())]
      .sort(([left], [right]) => left.localeCompare(right))
  );
  return {
    schemaVersion: COMMUNITY_SCHEMA_VERSION,
    captures: community.length,
    captureFamilies: new Set(community.map((sample) => sample.capture.community.familyId)).size,
    labels: countBy(community.map((sample) => sample.label)),
    browsers: countBy(community.map((sample) => sample.capture.browser.name)),
    operatingSystems: countBy(community.map((sample) => sample.capture.os.name)),
    inputMethods: countBy(community.flatMap((sample) => sample.capture.inputMethods)),
    assistiveTechnology: countBy(
      community.flatMap((sample) => sample.capture.assistiveTechnology.map((tool) => tool.name))
    ),
    scenarios: countBy(community.map((sample) => sample.scenario)),
  };
}

module.exports = {
  COMMUNITY_SCHEMA_VERSION,
  CONSENT_STATEMENT,
  prepareContribution,
  scanForLeaks,
  summarizeCommunityCoverage,
};
