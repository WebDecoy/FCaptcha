'use strict';

/**
 * Drop-in compatibility with the Turnstile / reCAPTCHA / hCaptcha siteverify
 * contract.
 *
 * Every one of those services validates a token the same way: a server-to-server
 * POST carrying `secret` and `response`, answered with a small JSON object whose
 * shape has been stable for a decade. Every backend SDK, CMS plugin and Stack
 * Overflow snippet in circulation speaks it:
 *
 *     POST /turnstile/v0/siteverify        (form-encoded or JSON)
 *       secret, response, remoteip, idempotency_key
 *     -> {success, challenge_ts, hostname, action, cdata, error-codes}
 *
 * FCaptcha's native endpoint (`POST /api/token/verify` -> `{valid, score, ...}`)
 * is a different shape, which means none of that existing integration work
 * applies. Serving the familiar contract alongside the native one turns a
 * migration into a base-URL change, so this module is deliberately an *adapter*
 * over `verifyToken` rather than a second verification path — there is one
 * implementation of token validity and this translates its vocabulary.
 *
 * Three things the native endpoint did not do, which the contract requires:
 *
 *   - `secret` is checked. All three servers previously accepted the parameter
 *     and ignored it, so anyone who could reach the endpoint could verify
 *     tokens. The README documented sending it, which made the omission worse:
 *     integrators believed they were authenticated.
 *   - `hostname` is reported, so the caller can confirm the token was minted on
 *     a page they actually serve. This is what stops a lifted site key from
 *     being used against someone else's deployment.
 *   - `idempotency_key` makes retries safe. Tokens are single-use, so a network
 *     timeout on the first validation would otherwise burn the token and fail
 *     the user's request on the retry.
 *
 * Mirrors server-go/siteverify.go and server-python/siteverify.py.
 */

const crypto = require('crypto');
const { BoundedMap } = require('./limits');

// How long a validation result stays replayable under its idempotency key.
// Matched to the token lifetime: past that the token is expired anyway, so a
// retry has nothing left to be idempotent about.
const IDEMPOTENCY_TTL_SECONDS = 300;

// Bounded because the key is caller-supplied. Same reasoning as limits.js:
// anything keyed on a value the client chooses needs a ceiling.
const MAX_IDEMPOTENCY_ENTRIES = 10000;

// `action` and `cdata` are echoed back verbatim, so they are attacker-controlled
// output. Length-capped to keep them from bloating the token, and in cdata's
// case to keep it a label rather than a smuggling channel.
const MAX_ACTION_LENGTH = 32;
const MAX_CDATA_LENGTH = 255;

/**
 * The error-code vocabulary. These strings are the contract — integrators
 * branch on them — so they match Cloudflare's spelling exactly, hyphens and all.
 */
const ERROR_CODES = {
  MISSING_SECRET: 'missing-input-secret',
  INVALID_SECRET: 'invalid-input-secret',
  MISSING_RESPONSE: 'missing-input-response',
  INVALID_RESPONSE: 'invalid-input-response',
  BAD_REQUEST: 'bad-request',
  TIMEOUT_OR_DUPLICATE: 'timeout-or-duplicate',
  INTERNAL_ERROR: 'internal-error',
};

/**
 * How `verifyToken`'s internal `reason` maps onto that vocabulary.
 *
 * The collapse is lossy on purpose. A caller learning *why* a token failed
 * learns something about the signing key or the replay window, so every
 * structural failure reports the same `invalid-input-response`, and expiry and
 * replay share `timeout-or-duplicate` exactly as Cloudflare's do.
 */
const REASON_TO_ERROR_CODE = {
  expired: ERROR_CODES.TIMEOUT_OR_DUPLICATE,
  token_already_used: ERROR_CODES.TIMEOUT_OR_DUPLICATE,
  invalid_signature: ERROR_CODES.INVALID_RESPONSE,
  invalid_encoding: ERROR_CODES.INVALID_RESPONSE,
  invalid_json: ERROR_CODES.INVALID_RESPONSE,
  missing_signature: ERROR_CODES.INVALID_RESPONSE,
  ip_mismatch: ERROR_CODES.INVALID_RESPONSE,
  hostname_not_allowed: ERROR_CODES.INVALID_RESPONSE,
};

function reasonToErrorCode(reason) {
  return REASON_TO_ERROR_CODE[reason] || ERROR_CODES.INVALID_RESPONSE;
}

/**
 * Pull the host out of a URL-shaped header value.
 *
 * Returns '' rather than throwing on anything unparseable, including the
 * literal `null` that browsers send as Origin from a sandboxed iframe or a
 * file:// page. An opaque origin is genuinely the absence of a hostname, not an
 * error — the token simply carries no host binding.
 */
function hostFromUrl(value) {
  if (!value || typeof value !== 'string') return '';
  if (value === 'null') return '';
  try {
    // URL.hostname excludes the port and keeps IPv6 brackets, which is the
    // normalisation we want: example.com:8443 and example.com are one host.
    return new URL(value).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * The hostname a token should be bound to, from the headers of the request that
 * mints it.
 *
 * Origin first: the widget's verification call is a CORS POST, so browsers
 * attach it, and unlike Referer it is not suppressed by referrer policy. Referer
 * is the fallback for same-origin deployments where Origin may be absent on some
 * request shapes. Neither is trustworthy against a non-browser caller — anything
 * that can forge one can forge both — so this binds the *browser* case, which is
 * the case that matters: it stops a site key lifted from your page from minting
 * tokens that your own backend will accept.
 */
function requestHostname(headers) {
  if (!headers) return '';
  return hostFromUrl(headers['origin']) || hostFromUrl(headers['referer']) || '';
}

/** Trim a caller-supplied label to something safe to sign and echo. */
function sanitizeLabel(value, maxLength) {
  if (typeof value !== 'string') return '';
  // Control characters would ride through into the JSON response and any log
  // line that records it.
  return value.replace(/[\x00-\x1f\x7f]/g, '').slice(0, maxLength);
}

function sanitizeAction(value) {
  return sanitizeLabel(value, MAX_ACTION_LENGTH);
}

function sanitizeCdata(value) {
  return sanitizeLabel(value, MAX_CDATA_LENGTH);
}

/**
 * Constant-time secret comparison.
 *
 * timingSafeEqual demands equal-length buffers and throws otherwise, which would
 * itself leak length, so both sides are hashed to a fixed width first.
 */
function secretMatches(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  const a = crypto.createHash('sha256').update(provided).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

/**
 * Optional allowlist of hostnames permitted to mint tokens.
 *
 * Off by default so zero-config self-hosting keeps working, and reported rather
 * than enforced when a request carries no derivable Origin — a native mobile
 * client or a server-side integration legitimately has none, and refusing those
 * would break them for no security gain.
 */
class HostnameAllowlist {
  constructor(hostnames = []) {
    this.hostnames = new Set(
      hostnames
        .map((h) => String(h).trim().toLowerCase())
        .filter(Boolean)
    );
  }

  static fromEnv(env = process.env) {
    const raw = env.FCAPTCHA_ALLOWED_HOSTNAMES || '';
    return new HostnameAllowlist(raw.split(',').filter(Boolean));
  }

  get enabled() {
    return this.hostnames.size > 0;
  }

  /**
   * Whether a hostname may mint tokens. An empty hostname passes: see the class
   * comment — absence of an Origin is not evidence of a bad one.
   */
  permits(hostname) {
    if (!this.enabled) return true;
    if (!hostname) return true;
    return this.hostnames.has(hostname);
  }

  describe() {
    return this.enabled ? [...this.hostnames].join(', ') : 'any (unrestricted)';
  }
}

/**
 * Caches validation results so a retried siteverify returns the first answer
 * instead of tripping the single-use guard.
 *
 * Keyed on the idempotency key *and* the token: reusing one key across different
 * tokens is a caller bug, and answering the second one from the first one's
 * cache entry would report success for a token nobody validated. Binding both
 * degrades that case to an ordinary fresh verification.
 */
class IdempotencyStore {
  constructor({ ttlSeconds = IDEMPOTENCY_TTL_SECONDS, maxEntries = MAX_IDEMPOTENCY_ENTRIES } = {}) {
    this.ttlMs = ttlSeconds * 1000;
    this.entries = new BoundedMap(maxEntries);
  }

  _key(idempotencyKey, token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex').slice(0, 32);
    return `${idempotencyKey}:${tokenHash}`;
  }

  get(idempotencyKey, token) {
    if (!idempotencyKey) return null;
    const entry = this.entries.get(this._key(idempotencyKey, token));
    if (!entry) return null;
    // >= so that a zero TTL means "never replay" rather than "replay once".
    if (Date.now() - entry.storedAt >= this.ttlMs) return null;
    return entry.response;
  }

  set(idempotencyKey, token, response) {
    if (!idempotencyKey) return;
    this.entries.set(this._key(idempotencyKey, token), {
      storedAt: Date.now(),
      response,
    });
  }
}

/** A failing siteverify response carrying the given codes. */
function failure(...codes) {
  return { success: false, 'error-codes': codes };
}

/**
 * Read the siteverify parameters out of a request body.
 *
 * Both encodings are accepted because the contract accepts both, and callers in
 * the wild are split: PHP and Python examples overwhelmingly post form-encoded,
 * Node and Go examples post JSON.
 */
function readParams(body) {
  if (!body || typeof body !== 'object') return {};
  const str = (v) => (typeof v === 'string' ? v : v == null ? '' : String(v));
  return {
    secret: str(body.secret),
    response: str(body.response),
    remoteip: str(body.remoteip),
    idempotencyKey: str(body.idempotency_key),
  };
}

/**
 * Run a siteverify request.
 *
 * `verifyToken` is injected rather than imported so the standalone server and
 * the library export can each supply their own — they hold separate token
 * stores, and this module should not decide which one is authoritative.
 */
function siteverify({
  body,
  verifyToken,
  expectedSecret,
  idempotencyStore,
  requireSecret = true,
}) {
  const { secret, response, remoteip, idempotencyKey } = readParams(body);

  if (requireSecret) {
    if (!secret) return failure(ERROR_CODES.MISSING_SECRET);
    if (!secretMatches(secret, expectedSecret)) return failure(ERROR_CODES.INVALID_SECRET);
  }

  if (!response) return failure(ERROR_CODES.MISSING_RESPONSE);

  const cached = idempotencyStore && idempotencyStore.get(idempotencyKey, response);
  if (cached) return cached;

  let result;
  try {
    // remoteip is passed through to the IP-binding check. Empty means the caller
    // declined to assert one, which the token verifier treats as "don't check".
    result = verifyToken(response, remoteip || null);
  } catch {
    // Never surface an exception's text: it can carry key material or internals.
    return failure(ERROR_CODES.INTERNAL_ERROR);
  }

  const out = result && result.valid
    ? {
        success: true,
        challenge_ts: new Date((result.timestamp || 0) * 1000).toISOString(),
        hostname: result.hostname || '',
        action: result.action || '',
        cdata: result.cdata || '',
        'error-codes': [],
        // Not part of the upstream contract, but the whole reason to run
        // FCaptcha: a caller that only wants pass/fail can ignore it, and one
        // that wants to risk-band on the score has it without a second call.
        score: typeof result.score === 'number' ? result.score : null,
      }
    : failure(reasonToErrorCode(result && result.reason));

  if (idempotencyStore) idempotencyStore.set(idempotencyKey, response, out);
  return out;
}

// Async form used by Redis-backed servers. Kept separate so the public
// synchronous adapter remains backward compatible for library callers.
async function siteverifyAsync({
  body,
  verifyToken,
  expectedSecret,
  idempotencyStore,
  requireSecret = true,
}) {
  const { secret, response, remoteip, idempotencyKey } = readParams(body);
  if (requireSecret) {
    if (!secret) return failure(ERROR_CODES.MISSING_SECRET);
    if (!secretMatches(secret, expectedSecret)) return failure(ERROR_CODES.INVALID_SECRET);
  }
  if (!response) return failure(ERROR_CODES.MISSING_RESPONSE);

  try {
    const cached = idempotencyStore && await idempotencyStore.get(idempotencyKey, response);
    if (cached) return cached;
    const result = await verifyToken(response, remoteip || null);
    const out = result && result.valid
      ? {
          success: true,
          challenge_ts: new Date((result.timestamp || 0) * 1000).toISOString(),
          hostname: result.hostname || '',
          action: result.action || '',
          cdata: result.cdata || '',
          'error-codes': [],
          score: typeof result.score === 'number' ? result.score : null,
        }
      : failure(reasonToErrorCode(result && result.reason));
    if (idempotencyStore) await idempotencyStore.set(idempotencyKey, response, out);
    return out;
  } catch {
    return failure(ERROR_CODES.INTERNAL_ERROR);
  }
}

module.exports = {
  ERROR_CODES,
  HostnameAllowlist,
  IdempotencyStore,
  hostFromUrl,
  requestHostname,
  reasonToErrorCode,
  sanitizeAction,
  sanitizeCdata,
  secretMatches,
  siteverify,
  siteverifyAsync,
  MAX_ACTION_LENGTH,
  MAX_CDATA_LENGTH,
  IDEMPOTENCY_TTL_SECONDS,
};
