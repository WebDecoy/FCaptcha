'use strict';

// Web Bot Auth (RFC 9421 HTTP Message Signatures) verification for signed AI
// agents. Built on Cloudflare's web-bot-auth crypto primitives; mirrors the Go
// server's ScoringEngine.CheckWebBotAuth verdict model:
//
//   - verified   → declared_ai (verified:true, high confidence): a trustworthy
//                  signed identity (e.g. OpenAI Operator). A policy signal.
//   - forged     → bot (low confidence, contributory): the request claimed an
//                  agent identity and the signature failed cryptographic
//                  verification. Only a genuine crypto failure counts.
//   - otherwise  → fail open to a presence-only declared_ai signal identical to
//                  the pre-verification behavior. A directory we could not fetch
//                  (unreachable, blocked, timed out) is not proof of spoofing,
//                  so it must never be scored as one.
//
// The signer's key directory is named by the untrusted Signature-Agent header,
// so every fetch is treated as an SSRF vector: https-only, a DNS-lookup guard
// that refuses any non-global-unicast address (blocks loopback, private,
// link-local — including the 169.254.169.254 cloud metadata endpoint — CGNAT,
// ULA, and IPv4-mapped IPv6), a response-size cap, a short timeout, and no
// redirect following. Directories are cached with a TTL.
//
// The upstream package (cloudflare/web-bot-auth) is the reference implementation
// the Go module (WebDecoy/web-bot-auth) is cross-validated against, so the two
// servers agree on verdicts. Python stays presence-only for now, though a
// maintained RFC 9421 implementation (pyauth/http-message-signatures) now exists
// and would close that gap.
//
// Wire format — draft-meunier-webbotauth-httpsig-protocol-00 (2026-06-26):
// Signature-Agent is a Structured Fields Dictionary whose member value is the
// discovery URL and whose optional `type` parameter selects how to resolve keys:
//
//   sig1="https://a.test"                          → directory (default)
//   sig1="https://a.test/jwks.json";type=jwks_uri  → the URL *is* a JWK Set
//   sig1="https://a.test/card";type=cimd           → Client ID Metadata Document
//
// The pre-00 bare-String form ("https://a.test") is still emitted by signers
// that have not migrated and stays supported. A parser that only understood the
// bare form silently lost the *verified* verdict for any signer using the two
// new discovery types, degrading them to presence-only.
//
// DOCUMENTED DIVERGENCE — `cimd`. This implementation resolves a Client ID
// Metadata Document (embedded `jwks`, or a nested `jwks_uri` re-fetched through
// the same guard). The Go module (WebDecoy/web-bot-auth v0.2.0) parses the type
// but returns "not resolvable", so Go fails open to presence-only where Node
// reaches verified. Go is otherwise fully protocol-00 compliant — it honors
// `directory` and `jwks_uri` and enforces the tag — so this is the single
// verdict difference. It is currently theoretical: no observed signer uses
// `cimd` (chatgpt.com and agent.bot.goog both serve `directory`). Parity
// requires a change in the Go module, not here. Tracked rather than silent, per
// the CLAUDE.md sync rule.

const https = require('https');
const dns = require('dns');
const { URL } = require('url');

const ipaddr = require('ipaddr.js');
const {
  verify,
  jwkToKeyID,
  helpers,
  HTTP_MESSAGE_SIGNATURES_DIRECTORY,
} = require('web-bot-auth');
const { verifierFromJWK } = require('web-bot-auth/crypto');

const VERIFY_TIMEOUT_MS = 3000;
const MAX_DIRECTORY_BYTES = 1 << 20; // 1 MiB, matches the Go client's cap
const DIRECTORY_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// The exact message web-bot-auth/crypto throws when crypto.subtle.verify()
// returns false. This — and only this — is affirmative evidence of a forged
// signature. Everything else (fetch failure, expiry, missing key) fails open.
const CRYPTO_FAILURE_MESSAGE = 'invalid signature';

// Discovery types from protocol-00. `directory` is the default when the header
// carries no `type` parameter.
const DISCOVERY_DIRECTORY = 'directory';
const DISCOVERY_JWKS_URI = 'jwks_uri';
const DISCOVERY_CIMD = 'cimd';

// protocol-00: `tag` MUST be "web-bot-auth". A signature tagged for some other
// protocol is not a web-bot-auth signature, so it earns no verified credit.
const REQUIRED_TAG = 'web-bot-auth';

// protocol-00 RECOMMENDS an expiry no more than 24h out. Because that is a
// RECOMMENDED and not a MUST, an over-long window is not treated as forgery or
// as a hard rejection — it just does not earn the *verified* verdict, and the
// request falls back to presence-only. That bounds the replay window a stolen
// signature buys without false-positiving a signer who picked a longer TTL.
const MAX_SIGNATURE_LIFETIME_S = 24 * 60 * 60;

// origin (https://host[:port]) → { keys: JsonWebKey[], fetchedAt: number }
const directoryCache = new Map();

// FetchFailure marks failures that are NOT cryptographic — the caller treats
// them as "could not verify" (fail open), never as a forged-signature signal.
class FetchFailure extends Error {}

// --- SSRF guard ---------------------------------------------------------------

// isPublicUnicast reports whether an IP literal is a globally-routable unicast
// address. ipaddr.process() un-maps IPv4-mapped IPv6 first, so an address like
// ::ffff:10.0.0.1 is classified by its embedded v4 range ('private'), not as a
// v6 unicast. Only 'unicast' (public) is allowed; every other range is refused.
function isPublicUnicast(ip) {
  let addr;
  try {
    addr = ipaddr.process(ip);
  } catch {
    return false;
  }
  return addr.range() === 'unicast';
}

// guardedLookup resolves a hostname and hands the socket a vetted IP. Passing
// the concrete address (not the hostname) to connect closes the DNS-rebinding
// window: the socket connects to exactly the address we validated.
function guardedLookup(hostname, options, callback) {
  const opts = typeof options === 'number' ? { family: options } : options || {};
  dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) {
      callback(err);
      return;
    }
    const list = Array.isArray(addresses)
      ? addresses
      : [{ address: addresses, family: opts.family || 0 }];
    for (const a of list) {
      if (isPublicUnicast(a.address)) {
        callback(null, a.address, a.family);
        return;
      }
    }
    callback(new FetchFailure(`refusing to connect to non-global address for ${hostname}`));
  });
}

// --- directory fetching -------------------------------------------------------

// fetchJSON retrieves and parses one https document under the SSRF guard, the
// size cap and the timeout. Shared by directory, jwks_uri and cimd fetches so a
// new discovery type cannot accidentally bypass the guard.
function fetchJSON(documentUrl) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(documentUrl);
    } catch {
      reject(new FetchFailure('invalid directory URL'));
      return;
    }
    if (url.protocol !== 'https:') {
      reject(new FetchFailure('directory URL is not https'));
      return;
    }

    const req = https.get(
      documentUrl,
      {
        lookup: guardedLookup,
        timeout: VERIFY_TIMEOUT_MS,
        headers: {
          accept: 'application/http-message-signatures-directory+json, application/json',
        },
      },
      (res) => {
        // https.get does not follow redirects; anything but 200 is a failure.
        if (res.statusCode !== 200) {
          res.resume();
          reject(new FetchFailure(`directory returned ${res.statusCode}`));
          return;
        }
        let len = 0;
        const chunks = [];
        res.on('data', (chunk) => {
          len += chunk.length;
          if (len > MAX_DIRECTORY_BYTES) {
            req.destroy(new FetchFailure('directory exceeds size cap'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            reject(new FetchFailure('directory is not valid JSON'));
          }
        });
      },
    );

    req.on('timeout', () => {
      req.destroy(new FetchFailure('directory fetch timed out'));
    });
    req.on('error', (e) => {
      reject(e instanceof FetchFailure ? e : new FetchFailure(`directory fetch: ${e.message}`));
    });
  });
}

// fetchKeySet pulls a JWK Set — the shape served by both the well-known
// directory and a jwks_uri.
async function fetchKeySet(url) {
  const doc = await fetchJSON(url);
  return doc && Array.isArray(doc.keys) ? doc.keys : [];
}

// fetchViaCIMD resolves a Client ID Metadata Document, which either embeds the
// JWK Set inline or points at one. The nested jwks_uri is re-validated and
// re-fetched through the same guard rather than trusted.
async function fetchViaCIMD(cimdUrl) {
  const doc = await fetchJSON(cimdUrl);
  if (doc && doc.jwks && Array.isArray(doc.jwks.keys)) {
    return doc.jwks.keys;
  }
  if (doc && typeof doc.jwks_uri === 'string') {
    let nested;
    try {
      nested = new URL(doc.jwks_uri);
    } catch {
      throw new FetchFailure('cimd jwks_uri is not a URL');
    }
    if (nested.protocol !== 'https:') {
      throw new FetchFailure('cimd jwks_uri is not https');
    }
    return fetchKeySet(nested.toString());
  }
  throw new FetchFailure('cimd document has no jwks or jwks_uri');
}

// getKeys caches by resolved URL, so the three discovery types share one cache
// without colliding.
async function getKeys(url, type) {
  const now = Date.now();
  const cached = directoryCache.get(url);
  if (cached && now - cached.fetchedAt < DIRECTORY_CACHE_TTL_MS) {
    return cached.keys;
  }
  const keys = type === DISCOVERY_CIMD ? await fetchViaCIMD(url) : await fetchKeySet(url);
  directoryCache.set(url, { keys, fetchedAt: now });
  return keys;
}

// resolveKey fetches the directory named by the Signature-Agent header and
// returns the JWK whose RFC 7638 thumbprint matches keyid (the Web Bot Auth
// keyid IS the thumbprint, not the JWK's `kid`). A reachable directory that
// lacks the key throws a FetchFailure — treated as fail-open, matching the Go
// engine, which counts only a crypto failure as forgery.
async function resolveKey(signatureAgentHeader, keyid) {
  const source = keySourceFromHeader(signatureAgentHeader);
  if (!source) {
    throw new FetchFailure('no resolvable Signature-Agent key source');
  }
  const keys = await getKeys(source.url, source.type);
  for (const jwk of keys) {
    let thumbprint;
    try {
      thumbprint = await jwkToKeyID(jwk, helpers.WEBCRYPTO_SHA256, helpers.BASE64URL_DECODE);
    } catch {
      continue; // unsupported/malformed key in the set — skip it
    }
    if (thumbprint === keyid) {
      return jwk;
    }
  }
  throw new FetchFailure('keyid not found in directory');
}

// --- header + request helpers -------------------------------------------------

// parseSignatureAgent reads the first member of the Signature-Agent Structured
// Fields Dictionary, returning its URL and discovery type. Accepts, in order of
// how signers actually emit them:
//
//   sig1="https://a.test/jwks.json";type=jwks_uri   protocol-00, typed
//   sig1="https://a.test"                           protocol-00, default type
//   "https://a.test"                                pre-00 bare String
//
// The previous implementation anchored on a closing quote at end-of-string, so
// any trailing parameter fell through to the raw header text and failed to
// parse as a URL. That silently cost the *verified* verdict.
function parseSignatureAgent(raw) {
  if (!raw) return null;
  const s = String(raw).trim();
  if (!s) return null;
  // Optional `key=` prefix, a quoted SF String, then optional ;params up to the
  // next dictionary member.
  const m = s.match(/^(?:[A-Za-z0-9_*-]+\s*=\s*)?"([^"]*)"((?:\s*;[^,]*)?)/);
  if (!m) return null;
  const url = m[1].trim();
  if (!url) return null;
  const typeMatch = (m[2] || '').match(/;\s*type\s*=\s*"?([A-Za-z0-9_-]+)"?/i);
  const type = typeMatch ? typeMatch[1].toLowerCase() : DISCOVERY_DIRECTORY;
  return { url, type };
}

function displayAgent(raw) {
  const parsed = parseSignatureAgent(raw);
  return (parsed && parsed.url) || 'unknown';
}

// keySourceFromHeader resolves the header to the concrete https URL keys are
// fetched from, plus the discovery type that says how to interpret it. Returns
// null for anything unusable — a non-https URL, or a discovery type this build
// does not implement (guessing would be worse than failing open).
function keySourceFromHeader(raw) {
  const parsed = parseSignatureAgent(raw);
  if (!parsed) return null;
  let u;
  try {
    u = new URL(parsed.url);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') return null;

  switch (parsed.type) {
    case DISCOVERY_DIRECTORY:
      // The member names the signer's origin; keys live at the well-known path.
      return { url: u.origin + HTTP_MESSAGE_SIGNATURES_DIRECTORY, type: DISCOVERY_DIRECTORY };
    case DISCOVERY_JWKS_URI:
    case DISCOVERY_CIMD:
      // The member names the document itself — path and query are significant.
      return { url: u.toString(), type: parsed.type };
    default:
      return null;
  }
}

function forwardedScheme(req) {
  const xfp = req.headers && req.headers['x-forwarded-proto'];
  if (xfp) return String(xfp).split(',')[0].trim().toLowerCase();
  if (req.protocol) return req.protocol; // express sets this
  return req.socket && req.socket.encrypted ? 'https' : 'http';
}

// --- detections (shape mirrors detection.js / the Go DetectionResult) ---------

function verifiedDetection(agent, keyId, algorithm) {
  return {
    category: 'declared_ai',
    score: 0.5,
    confidence: 0.99,
    reason: `Verified AI agent (Web Bot Auth): ${agent}`,
    details: { signatureAgent: agent, verified: true, keyId, algorithm },
  };
}

function forgedDetection(agent, err) {
  return {
    category: 'bot',
    score: 0.5,
    confidence: 0.5,
    reason: `Forged Web Bot Auth signature (crypto verification failed): ${agent}`,
    details: { signatureAgent: agent, verified: false, error: err && err.message },
  };
}

function presenceDetection(agent) {
  return {
    category: 'declared_ai',
    score: 0.4,
    confidence: 0.95,
    reason: `Signed agent request (Web Bot Auth, unverified): ${agent}`,
    details: { signatureAgent: agent, verified: false },
  };
}

// --- entry point --------------------------------------------------------------

// checkWebBotAuth verifies a Web Bot Auth signed request and returns detections
// (empty when the request carries no signature). Async because verification may
// fetch the signer's key directory. Give it the Express request so the signed
// URL is reconstructed accurately — a mis-derived authority would make a genuine
// signature fail crypto verification and false-positive a real agent.
async function checkWebBotAuth(req) {
  const headers = (req && req.headers) || {};
  if (!headers.signature || !headers['signature-input']) {
    return [];
  }

  const sigAgentRaw = headers['signature-agent'];
  const agent = displayAgent(sigAgentRaw);

  const host = headers.host;
  if (!host) {
    // Cannot reconstruct @authority → cannot verify. Fail open.
    return [presenceDetection(agent)];
  }
  const path = req.originalUrl || req.url || '/';
  const message = {
    method: (req.method || 'POST').toUpperCase(),
    url: `${forwardedScheme(req)}://${host}${path}`,
    headers,
  };

  let cryptoFailed = false;
  let resolvedKeyId = '';
  let resolvedAlg = '';

  try {
    await withTimeout(
      verify(message, async (data, signature, params) => {
        if (!sigAgentRaw) {
          throw new FetchFailure('no Signature-Agent to resolve key');
        }
        assertWebBotAuthParams(params);
        const jwk = await resolveKey(sigAgentRaw, params.keyid);
        resolvedKeyId = params.keyid;
        resolvedAlg = jwk.alg || (jwk.crv === 'Ed25519' ? 'ed25519' : '');
        const verifyFn = await verifierFromJWK(jwk);
        try {
          await verifyFn(data, signature, params);
        } catch (e) {
          if (e && e.message === CRYPTO_FAILURE_MESSAGE) {
            cryptoFailed = true;
          }
          throw e;
        }
      }),
      VERIFY_TIMEOUT_MS,
    );
    return [verifiedDetection(agent, resolvedKeyId, resolvedAlg)];
  } catch (e) {
    if (cryptoFailed) {
      return [forgedDetection(agent, e)];
    }
    // Fetch/structural/timeout/expiry failure: not proof of forgery. Fail open.
    return [presenceDetection(agent)];
  }
}

// toEpochSeconds normalizes a signature timestamp to epoch seconds. RFC 9421
// puts integer seconds on the wire, but web-bot-auth hands the verifier callback
// `Date` objects — so a naive Number() yields milliseconds and any duration
// comparison is off by 1000×. Accepts Date, seconds, or milliseconds.
function toEpochSeconds(value) {
  if (value instanceof Date) return Math.floor(value.getTime() / 1000);
  const n = Number(value);
  if (!Number.isFinite(n)) return NaN;
  // Epoch seconds are ~1.8e9 today; epoch milliseconds ~1.8e12.
  return n > 1e11 ? Math.floor(n / 1000) : n;
}

// assertWebBotAuthParams enforces the protocol-00 signature-parameter rules that
// the underlying library does not.
//
// web-bot-auth's own verify() already rejects a wrong `tag`, a `created` in the
// future, an expired `expires`, and a missing `keyid`. The tag check below is
// therefore belt-and-braces — kept because it is free and because it documents a
// MUST that our verdict depends on. What is genuinely additive is the lifetime
// ceiling: nothing upstream bounds how far out `expires` may sit, and a
// long-lived signature is a long-lived replay token.
//
// Throwing FetchFailure means "not a verifiable web-bot-auth signature", which
// the caller renders as presence-only — never as forgery, since neither a wrong
// tag nor a generous TTL is cryptographic proof that anyone spoofed anything.
function assertWebBotAuthParams(params) {
  const p = params || {};

  if (p.tag !== REQUIRED_TAG) {
    throw new FetchFailure(`signature tag is not ${REQUIRED_TAG}`);
  }

  // `expires` is what bounds replay; a signature without one is unbounded.
  const expires = toEpochSeconds(p.expires);
  if (!Number.isFinite(expires)) {
    throw new FetchFailure('signature has no expires parameter');
  }
  const created = Number.isFinite(toEpochSeconds(p.created))
    ? toEpochSeconds(p.created)
    : Math.floor(Date.now() / 1000);
  if (expires - created > MAX_SIGNATURE_LIFETIME_S) {
    throw new FetchFailure('signature lifetime exceeds 24h');
  }
}

// withTimeout bounds the whole verification, a backstop over the per-fetch
// timeout so a stalled directory can never hold the scoring path open.
function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new FetchFailure('verification timed out')), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

module.exports = {
  checkWebBotAuth,
  // Exported for unit tests only.
  _internal: {
    isPublicUnicast,
    parseSignatureAgent,
    keySourceFromHeader,
    assertWebBotAuthParams,
    displayAgent,
    verifiedDetection,
    forgedDetection,
    presenceDetection,
    REQUIRED_TAG,
    MAX_SIGNATURE_LIFETIME_S,
    // Seeds the key cache so an end-to-end verify can exercise resolveKey
    // without a network fetch (the SSRF guard refuses the loopback address a
    // local test server would listen on). Test-only.
    //
    // Seeds by *origin* for the default directory discovery. Pass a full URL as
    // `exactUrl` to seed a jwks_uri/cimd source instead.
    seedDirectoryCache(origin, keys, exactUrl) {
      const url = exactUrl || origin + HTTP_MESSAGE_SIGNATURES_DIRECTORY;
      directoryCache.set(url, { keys, fetchedAt: Date.now() });
    },
  },
};
