'use strict';

function encodedString(value, field) {
  if (typeof value !== 'string') throw new TypeError(`${field} must be a string`);
  return Buffer.from(value, 'utf8').toString('base64url');
}

/**
 * Version 2 signs a language-neutral, length-safe representation instead of
 * reserializing JSON. Native JSON encoders disagree on integral floats and on
 * escaping Unicode/HTML-sensitive strings, which broke mixed-runtime pools.
 * Tokens without v=2 retain the legacy canonicalization for a rolling upgrade.
 */
function canonicalTokenPayload(data) {
  if (data.v !== 2) return JSON.stringify(data, Object.keys(data).sort());
  if (!Number.isSafeInteger(data.timestamp)) throw new TypeError('timestamp must be an integer');
  if (typeof data.score !== 'number' || !Number.isFinite(data.score)) throw new TypeError('score must be finite');

  return [
    'fcaptcha-token-v2',
    encodedString(data.site_key, 'site_key'),
    encodedString(data.jti, 'jti'),
    String(data.timestamp),
    data.score.toFixed(3),
    encodedString(data.ip_hash, 'ip_hash'),
    encodedString(data.hostname, 'hostname'),
    encodedString(data.action, 'action'),
    encodedString(data.cdata, 'cdata')
  ].join('\n');
}

module.exports = { canonicalTokenPayload };
