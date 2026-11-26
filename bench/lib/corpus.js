'use strict';

/**
 * The corpus format, and the provenance rules that go with it.
 *
 * A sample is one labeled signal payload, exactly as a client would POST it to
 * `/api/verify` or `/api/score`, plus the metadata needed to score it honestly:
 *
 *   {
 *     "id":        "human/keyboard-only/0003",
 *     "label":     "human" | "agent",
 *     "group":     "keyboard-only"            // persona (human) or class (agent)
 *     "scenario":  "stealth-humanized"        // capture choreography/configuration
 *     "provenance":"captured" | "derived" | "self-reported" | "synthetic",
 *     "captureMethod":"manual-browser" | "browser-internal" | "external-cdp" |
 *                     "automated-browser" | "production-export" | "synthetic-payload",
 *     "labelEvidence":"verified-human" | "paired-human-control" | "simulated-human" |
 *                     "self-reported-human" | "observed-agent" | "simulated-agent" |
 *                     "literature-agent",
 *     "source":    "human/keyboard-only/0000" // for derived: the capture it came from
 *     "notes":     "...",                     // free text, shown in the report
 *     "headers":   { "User-Agent": "...", ... },
 *     "signals":   { behavioral: {...}, environmental: {...}, ... }
 *     "capture":   { endpoint: "/api/verify" | "/api/score", ... }
 *   }
 *
 * Provenance says how the payload came into existence. Capture method says how
 * the browser was actuated. Label evidence says why the human/agent label is
 * believed. These are deliberately separate: a payload can come from a real
 * browser while its "human" behaviour is a scripted structural stand-in.
 *
 *   captured  — recorded from a real browser. Label evidence still decides
 *               whether it represents an observed person or a scripted fixture.
 *   derived   — a captured sample with its numeric fields jittered. Measures the
 *               neighbourhood around a real capture. Supports a claim about
 *               robustness near observed behaviour; does NOT support a
 *               population false-positive rate.
 *   self-reported — an explicitly consented production trace whose human label
 *               was supplied by the visitor. It is useful for finding coverage
 *               gaps, but the label is not trusted ground truth and therefore
 *               cannot support a false-positive claim or gate.
 *   synthetic — hand-authored from a description in a paper or vendor writeup.
 *               Supports regression detection only. Never a published number.
 *
 * The reporter prints an observed-human result only from captured
 * verified-human and paired-human-control rows. Derived rows are grouped by
 * source capture and reported separately as robustness. See report.js.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const LABELS = new Set(['human', 'agent']);
const PROVENANCE = new Set(['captured', 'derived', 'self-reported', 'synthetic']);
const CAPTURE_METHODS = new Set([
  'manual-browser',
  'browser-internal',
  'external-cdp',
  'automated-browser',
  'production-export',
  'synthetic-payload',
]);
const LABEL_EVIDENCE = new Set([
  'verified-human',
  'paired-human-control',
  'simulated-human',
  'self-reported-human',
  'observed-agent',
  'simulated-agent',
  'literature-agent',
]);

/** Human labels strong enough to support an observed false-positive result. */
const HUMAN_FP_EVIDENCE = new Set(['verified-human', 'paired-human-control']);

const CORPUS_DIR = path.join(__dirname, '..', 'corpus');

function validate(sample, where) {
  const fail = (msg) => {
    throw new Error(`invalid sample${where ? ` in ${where}` : ''}: ${msg}`);
  };

  if (!sample || typeof sample !== 'object') fail('not an object');
  if (typeof sample.id !== 'string' || !sample.id) fail('missing id');
  if (!LABELS.has(sample.label)) fail(`label must be one of ${[...LABELS].join('|')}`);
  if (typeof sample.group !== 'string' || !sample.group) fail(`${sample.id}: missing group`);
  if (!PROVENANCE.has(sample.provenance)) {
    fail(`${sample.id}: provenance must be one of ${[...PROVENANCE].join('|')}`);
  }
  if (!CAPTURE_METHODS.has(sample.captureMethod)) {
    fail(`${sample.id}: captureMethod must be one of ${[...CAPTURE_METHODS].join('|')}`);
  }
  if (!LABEL_EVIDENCE.has(sample.labelEvidence)) {
    fail(`${sample.id}: labelEvidence must be one of ${[...LABEL_EVIDENCE].join('|')}`);
  }
  if (sample.label === 'human' && !sample.labelEvidence.includes('human') && sample.labelEvidence !== 'paired-human-control') {
    fail(`${sample.id}: human sample has agent labelEvidence ${sample.labelEvidence}`);
  }
  if (sample.label === 'agent' && !sample.labelEvidence.includes('agent')) {
    fail(`${sample.id}: agent sample has human labelEvidence ${sample.labelEvidence}`);
  }
  if (sample.provenance === 'derived' && !sample.source) {
    fail(`${sample.id}: derived samples must name the capture they came from`);
  }
  if (sample.caveats && !Array.isArray(sample.caveats)) {
    fail(`${sample.id}: caveats must be an array of strings`);
  }
  if (sample.capture?.community) {
    const community = sample.capture.community;
    if (!community || typeof community !== 'object' || Array.isArray(community)) {
      fail(`${sample.id}: community metadata must be an object`);
    }
    const communityFields = Object.keys(community).sort();
    const expectedCommunityFields = [
      'familyId',
      'publicationConsent',
      'sampleFingerprint',
      'schemaVersion',
    ];
    if (communityFields.length !== expectedCommunityFields.length ||
        communityFields.some((field, index) => field !== expectedCommunityFields[index])) {
      fail(`${sample.id}: community metadata contains unknown or missing fields`);
    }
    if (community.schemaVersion !== 1) fail(`${sample.id}: unsupported community schema version`);
    if (!/^[a-f0-9]{64}$/.test(community.familyId || '')) {
      fail(`${sample.id}: community familyId must be a SHA-256 digest`);
    }
    if (!/^[a-f0-9]{64}$/.test(community.sampleFingerprint || '')) {
      fail(`${sample.id}: community sampleFingerprint must be a SHA-256 digest`);
    }
    if (community.publicationConsent !== 'permanent-publication-mit-v1') {
      fail(`${sample.id}: community publication consent is missing`);
    }
    if (!Array.isArray(sample.caveats) || sample.caveats.length === 0 ||
        sample.caveats.some((value) => typeof value !== 'string' || !value)) {
      fail(`${sample.id}: community samples must declare limitations`);
    }
  }
  // A gap entry documents a class we have no data for. It carries no signals
  // because inventing them is exactly what it exists to avoid.
  if (sample.unmeasured) {
    if (!sample.notes) fail(`${sample.id}: an unmeasured entry must say why`);
    return sample;
  }
  if (!sample.signals || typeof sample.signals !== 'object') fail(`${sample.id}: missing signals`);
  return sample;
}

/**
 * Reads every *.json under corpus/, recursively. Each file is either one sample
 * or an array of them — the capture recorder writes arrays, hand-authored
 * fixtures tend to be single objects.
 */
function loadCorpus(dir = CORPUS_DIR) {
  const out = [];
  if (!fs.existsSync(dir)) return out;

  const walk = (d) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith('.json') && entry.name !== 'known-artifacts.json') {
        const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
        for (const s of Array.isArray(parsed) ? parsed : [parsed]) {
          out.push(validate(s, path.relative(CORPUS_DIR, full)));
        }
      }
    }
  };

  walk(dir);
  return validateCorpusIntegrity(out);
}

function validateCorpusIntegrity(samples) {
  const ids = new Set();
  const fingerprints = new Map();
  for (const sample of samples) {
    if (ids.has(sample.id)) throw new Error(`duplicate corpus id ${sample.id}`);
    ids.add(sample.id);
    const fingerprint = sample.capture?.community?.sampleFingerprint;
    if (!fingerprint) continue;
    if (fingerprints.has(fingerprint)) {
      throw new Error(
        `duplicate community capture fingerprint in ${fingerprints.get(fingerprint)} and ${sample.id}`
      );
    }
    fingerprints.set(fingerprint, sample.id);
  }
  return samples;
}

function saveSamples(file, samples) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  samples.forEach((s) => validate(s, file));
  fs.writeFileSync(file, `${JSON.stringify(samples, null, 2)}\n`);
  return file;
}

/**
 * Walks every number in a signal tree and jitters it, leaving strings, booleans
 * and nulls alone.
 *
 * The point is to explore the neighbourhood of a real capture: if a signal only
 * stays FP-safe at exactly the values one browser produced on one machine, it is
 * not FP-safe. Counts (`totalPoints`, `keyEvents`) are rounded back to integers
 * because a fractional event count is not a thing a client can send, and a
 * server reading one is being tested on an impossible input.
 */
function deriveVariant(sample, rng, index, pct = 0.15) {
  const jitterTree = (node, keyPath) => {
    if (Array.isArray(node)) return node.map((v, i) => jitterTree(v, `${keyPath}[${i}]`));
    if (node && typeof node === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(node)) out[k] = jitterTree(v, `${keyPath}.${k}`);
      return out;
    }
    if (typeof node !== 'number' || !Number.isFinite(node)) return node;

    // Timestamps and ids are not measurements; jittering them just corrupts.
    if (/timestamp|Time$|expiresAt|widgetId/i.test(keyPath)) return node;

    const jittered = rng.jitter(node, pct);
    return Number.isInteger(node) ? Math.max(0, Math.round(jittered)) : jittered;
  };

  const signals = jitterTree(sample.signals, '');

  // A derived sample stands for *another person behaving similarly*, not for
  // the same person seen again from a different address, so it needs its own
  // device. (replay.js does the same for captured samples, which all came off
  // one machine; doing it here too keeps the id stable across runs.)
  if (signals.environmental?.canvasHash) {
    signals.environmental = {
      ...signals.environmental,
      canvasHash: {
        ...signals.environmental.canvasHash,
        hash: crypto
          .createHash('sha256')
          .update(`${sample.id}:${index}:${signals.environmental.canvasHash.hash || ''}`)
          .digest('hex')
          .slice(0, 32),
      },
    };
  }

  return {
    id: `${sample.group}/derived/${String(index).padStart(4, '0')}`,
    label: sample.label,
    group: sample.group,
    scenario: sample.scenario,
    provenance: 'derived',
    captureMethod: sample.captureMethod,
    labelEvidence: sample.labelEvidence,
    source: sample.id,
    notes: `±${Math.round(pct * 100)}% jitter around ${sample.id}, distinct synthetic device`,
    headers: { ...(sample.headers || {}) },
    ...(sample.capture ? { capture: { ...sample.capture } } : {}),
    signals,
  };
}

module.exports = {
  CAPTURE_METHODS,
  CORPUS_DIR,
  HUMAN_FP_EVIDENCE,
  LABELS,
  LABEL_EVIDENCE,
  PROVENANCE,
  deriveVariant,
  loadCorpus,
  saveSamples,
  validate,
  validateCorpusIntegrity,
};
