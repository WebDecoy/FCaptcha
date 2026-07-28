'use strict';

/**
 * The corpus format, and the provenance rules that go with it.
 *
 * A sample is one labeled signal payload, exactly as a client would POST it to
 * `/api/verify`, plus the metadata needed to score it honestly:
 *
 *   {
 *     "id":        "human/keyboard-only/0003",
 *     "label":     "human" | "agent",
 *     "group":     "keyboard-only"            // persona (human) or class (agent)
 *     "provenance":"captured" | "derived" | "synthetic",
 *     "source":    "human/keyboard-only/0000" // for derived: the capture it came from
 *     "notes":     "...",                     // free text, shown in the report
 *     "headers":   { "User-Agent": "...", ... },
 *     "signals":   { behavioral: {...}, environmental: {...}, ... }
 *   }
 *
 * `provenance` is the field that keeps this harness honest, so it is required
 * and validated rather than defaulted:
 *
 *   captured  — recorded from a real browser driven by a real input sequence.
 *               The only provenance that supports a claim about real users.
 *   derived   — a captured sample with its numeric fields jittered. Measures the
 *               neighbourhood around a real capture. Supports a claim about
 *               robustness near observed behaviour; does NOT support a
 *               population false-positive rate.
 *   synthetic — hand-authored from a description in a paper or vendor writeup.
 *               Supports regression detection only. Never a published number.
 *
 * The reporter refuses to print a headline FPR from anything but `captured`
 * plus `derived`, and labels which it used. See report.js.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const LABELS = new Set(['human', 'agent']);
const PROVENANCE = new Set(['captured', 'derived', 'synthetic']);

/** Provenance strong enough to support a false-positive claim. */
const EVIDENTIAL = new Set(['captured', 'derived']);

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
  if (sample.provenance === 'derived' && !sample.source) {
    fail(`${sample.id}: derived samples must name the capture they came from`);
  }
  if (sample.caveats && !Array.isArray(sample.caveats)) {
    fail(`${sample.id}: caveats must be an array of strings`);
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
  return out;
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
    provenance: 'derived',
    source: sample.id,
    notes: `±${Math.round(pct * 100)}% jitter around ${sample.id}, distinct synthetic device`,
    headers: { ...(sample.headers || {}) },
    signals,
  };
}

module.exports = {
  CORPUS_DIR,
  EVIDENTIAL,
  LABELS,
  PROVENANCE,
  deriveVariant,
  loadCorpus,
  saveSamples,
  validate,
};
