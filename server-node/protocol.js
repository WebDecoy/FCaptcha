'use strict';

const crypto = require('crypto');

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function invalidRequest() {
  return Object.assign(new Error('invalid_request'), { status: 400 });
}

// Resolve the exact bytes committed by the proof before any detector mutates
// signals. Legacy proofs without a commitment still use the signals object.
function resolveSignals(signals, signalsJson, signalsHash) {
  let commitmentValid = true;
  if (signalsHash) {
    if (typeof signalsJson !== 'string' || typeof signalsHash !== 'string') {
      commitmentValid = false;
    } else {
      commitmentValid = crypto.createHash('sha256').update(signalsJson).digest('hex') === signalsHash;
      try { signals = JSON.parse(signalsJson); } catch { throw invalidRequest(); }
    }
  }
  if (!isObject(signals)) throw invalidRequest();
  for (const key of ['behavioral', 'environmental', 'temporal', 'meta', 'formAnalysis']) {
    if (signals[key] != null && !isObject(signals[key])) throw invalidRequest();
  }
  return { signals, commitmentValid };
}

module.exports = { resolveSignals, isObject, invalidRequest };
