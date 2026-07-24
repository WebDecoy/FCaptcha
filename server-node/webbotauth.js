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
// servers agree on verdicts. Python has no maintained equivalent and stays
// presence-only.

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

function fetchDirectory(directoryUrl) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(directoryUrl);
    } catch {
      reject(new FetchFailure('invalid directory URL'));
      return;
    }
    if (url.protocol !== 'https:') {
      reject(new FetchFailure('directory URL is not https'));
      return;
    }

    const req = https.get(
      directoryUrl,
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
            const doc = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            resolve(Array.isArray(doc.keys) ? doc.keys : []);
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

async function getDirectory(directoryUrl) {
  const now = Date.now();
  const cached = directoryCache.get(directoryUrl);
  if (cached && now - cached.fetchedAt < DIRECTORY_CACHE_TTL_MS) {
    return cached.keys;
  }
  const keys = await fetchDirectory(directoryUrl);
  directoryCache.set(directoryUrl, { keys, fetchedAt: now });
  return keys;
}

// resolveKey fetches the directory named by the Signature-Agent header and
// returns the JWK whose RFC 7638 thumbprint matches keyid (the Web Bot Auth
// keyid IS the thumbprint, not the JWK's `kid`). A reachable directory that
// lacks the key throws a FetchFailure — treated as fail-open, matching the Go
// engine, which counts only a crypto failure as forgery.
async function resolveKey(signatureAgentHeader, keyid) {
  const origin = directoryOriginFromHeader(signatureAgentHeader);
  if (!origin) {
    throw new FetchFailure('no resolvable Signature-Agent directory');
  }
  const keys = await getDirectory(origin + HTTP_MESSAGE_SIGNATURES_DIRECTORY);
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

// unwrapSfString extracts the value from a Signature-Agent header, which is an
// RFC 8941 String — bare (`"https://a"`) or a dictionary member
// (`sig1="https://a"`) as some signers emit.
function unwrapSfString(raw) {
  if (!raw) return '';
  const s = String(raw).trim();
  const m = s.match(/^(?:[A-Za-z0-9_-]+=)?"(.*)"$/);
  return (m ? m[1] : s).trim();
}

function displayAgent(raw) {
  return unwrapSfString(raw) || 'unknown';
}

function directoryOriginFromHeader(raw) {
  const val = unwrapSfString(raw);
  if (!val) return null;
  let u;
  try {
    u = new URL(val);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:') return null;
  return u.origin;
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
    directoryOriginFromHeader,
    displayAgent,
    verifiedDetection,
    forgedDetection,
    presenceDetection,
    // Seeds the directory cache so an end-to-end verify can exercise resolveKey
    // without a network fetch (the SSRF guard refuses the loopback address a
    // local test server would listen on). Test-only.
    seedDirectoryCache(origin, keys) {
      directoryCache.set(origin + HTTP_MESSAGE_SIGNATURES_DIRECTORY, {
        keys,
        fetchedAt: Date.now(),
      });
    },
  },
};
