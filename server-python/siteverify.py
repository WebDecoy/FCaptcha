"""Drop-in compatibility with the Turnstile / reCAPTCHA / hCaptcha siteverify
contract.

Every one of those services validates a token the same way: a server-to-server
POST carrying ``secret`` and ``response``, answered with a small JSON object
whose shape has been stable for a decade. Every backend SDK, CMS plugin and
Stack Overflow snippet in circulation speaks it::

    POST /turnstile/v0/siteverify        (form-encoded or JSON)
      secret, response, remoteip, idempotency_key
    -> {success, challenge_ts, hostname, action, cdata, error-codes}

FCaptcha's native endpoint (``POST /api/token/verify`` -> ``{valid, score, ...}``)
is a different shape, which means none of that existing integration work
applies. Serving the familiar contract alongside the native one turns a
migration into a base-URL change, so this module is deliberately an *adapter*
over ``verify_token`` rather than a second verification path — there is one
implementation of token validity and this translates its vocabulary.

Three things the native endpoint did not do, which the contract requires:

- ``secret`` is checked. All three servers previously accepted the parameter and
  ignored it, so anyone who could reach the endpoint could verify tokens. The
  README documented sending it, which made the omission worse: integrators
  believed they were authenticated.
- ``hostname`` is reported, so the caller can confirm the token was minted on a
  page they actually serve. This is what stops a lifted site key from being used
  against someone else's deployment.
- ``idempotency_key`` makes retries safe. Tokens are single-use, so a network
  timeout on the first validation would otherwise burn the token and fail the
  user's request on the retry.

Mirrors server-node/siteverify.js and server-go/siteverify.go.
"""

import hashlib
import hmac
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from sitekeys import BoundedLRU

# How long a validation result stays replayable under its idempotency key.
# Matched to the token lifetime: past that the token is expired anyway, so a
# retry has nothing left to be idempotent about.
IDEMPOTENCY_TTL_SECONDS = 300

# Bounded because the key is caller-supplied. Same reasoning as sitekeys.py:
# anything keyed on a value the client chooses needs a ceiling.
MAX_IDEMPOTENCY_ENTRIES = 10000

# `action` and `cdata` are echoed back verbatim, so they are attacker-controlled
# output. Length-capped to keep them from bloating the token, and in cdata's case
# to keep it a label rather than a smuggling channel.
MAX_ACTION_LENGTH = 32
MAX_CDATA_LENGTH = 255

# The error-code vocabulary. These strings are the contract - integrators branch
# on them - so they match Cloudflare's spelling exactly, hyphens and all.
ERR_MISSING_SECRET = "missing-input-secret"
ERR_INVALID_SECRET = "invalid-input-secret"
ERR_MISSING_RESPONSE = "missing-input-response"
ERR_INVALID_RESPONSE = "invalid-input-response"
ERR_BAD_REQUEST = "bad-request"
ERR_TIMEOUT_OR_DUPLICATE = "timeout-or-duplicate"
ERR_INTERNAL_ERROR = "internal-error"

# How verify_token's internal reason maps onto that vocabulary.
#
# The collapse is lossy on purpose. A caller learning *why* a token failed learns
# something about the signing key or the replay window, so every structural
# failure reports the same invalid-input-response, and expiry and replay share
# timeout-or-duplicate exactly as Cloudflare's do.
_REASON_TO_ERROR_CODE = {
    "expired": ERR_TIMEOUT_OR_DUPLICATE,
    "token_already_used": ERR_TIMEOUT_OR_DUPLICATE,
    "invalid_signature": ERR_INVALID_RESPONSE,
    "invalid_encoding": ERR_INVALID_RESPONSE,
    "invalid_json": ERR_INVALID_RESPONSE,
    "missing_signature": ERR_INVALID_RESPONSE,
    "ip_mismatch": ERR_INVALID_RESPONSE,
    "hostname_not_allowed": ERR_INVALID_RESPONSE,
}


def reason_to_error_code(reason: Optional[str]) -> str:
    """Translate an internal failure reason into a contract error code."""
    return _REASON_TO_ERROR_CODE.get(reason or "", ERR_INVALID_RESPONSE)


def host_from_url(value: Any) -> str:
    """Pull the host out of a URL-shaped header value.

    Returns '' rather than raising on anything unparseable, including the literal
    ``null`` that browsers send as Origin from a sandboxed iframe or a file://
    page. An opaque origin is genuinely the absence of a hostname, not an error -
    the token simply carries no host binding.
    """
    if not value or not isinstance(value, str) or value == "null":
        return ""
    try:
        parsed = urlparse(value)
    except ValueError:
        return ""
    # A bare "example.com" parses with an empty netloc; without a scheme there is
    # no origin, so it is not a hostname we should bind to.
    if not parsed.scheme or not parsed.netloc:
        return ""
    hostname = parsed.hostname  # strips port, userinfo and IPv6 brackets
    return hostname.lower() if hostname else ""


def request_hostname(headers: Optional[Dict[str, str]]) -> str:
    """The hostname a token should be bound to, from the minting request.

    Origin first: the widget's verification call is a CORS POST, so browsers
    attach it, and unlike Referer it is not suppressed by referrer policy.
    Referer is the fallback for same-origin deployments where Origin may be
    absent on some request shapes. Neither is trustworthy against a non-browser
    caller - anything that can forge one can forge both - so this binds the
    *browser* case, which is the case that matters: it stops a site key lifted
    from your page from minting tokens that your own backend will accept.
    """
    if not headers:
        return ""
    return host_from_url(headers.get("origin")) or host_from_url(headers.get("referer"))


def _sanitize_label(value: Any, max_length: int) -> str:
    """Trim a caller-supplied label to something safe to sign and echo."""
    if not isinstance(value, str):
        return ""
    # Control characters would ride through into the JSON response and any log
    # line that records it.
    cleaned = "".join(c for c in value if ord(c) >= 0x20 and ord(c) != 0x7F)
    return cleaned[:max_length]


def sanitize_action(value: Any) -> str:
    return _sanitize_label(value, MAX_ACTION_LENGTH)


def sanitize_cdata(value: Any) -> str:
    return _sanitize_label(value, MAX_CDATA_LENGTH)


def secret_matches(provided: Any, expected: Any) -> bool:
    """Constant-time secret comparison.

    Both sides are hashed to a fixed width first so the comparison length does
    not itself depend on the secret.
    """
    if not isinstance(provided, str) or not isinstance(expected, str):
        return False
    a = hashlib.sha256(provided.encode()).digest()
    b = hashlib.sha256(expected.encode()).digest()
    return hmac.compare_digest(a, b)


class HostnameAllowlist:
    """Optionally restricts which page origins may mint tokens.

    Off by default so zero-config self-hosting keeps working, and permissive when
    a request carries no derivable Origin - a native mobile client or a
    server-side integration legitimately has none, and refusing those would break
    them for no security gain.
    """

    def __init__(self, hostnames: Optional[List[str]] = None):
        self.hostnames = {
            h.strip().lower() for h in (hostnames or []) if h and h.strip()
        }

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "HostnameAllowlist":
        source = env if env is not None else os.environ
        raw = source.get("FCAPTCHA_ALLOWED_HOSTNAMES", "")
        return cls(raw.split(","))

    @property
    def enabled(self) -> bool:
        return len(self.hostnames) > 0

    def permits(self, hostname: str) -> bool:
        """Whether a hostname may mint tokens.

        An empty hostname passes: see the class docstring - absence of an Origin
        is not evidence of a bad one.
        """
        if not self.enabled or not hostname:
            return True
        return hostname in self.hostnames

    def describe(self) -> str:
        return ", ".join(sorted(self.hostnames)) if self.enabled else "any (unrestricted)"


class IdempotencyStore:
    """Caches validation results so a retried siteverify returns the first answer
    instead of tripping the single-use guard.

    Keyed on the idempotency key *and* the token: reusing one key across
    different tokens is a caller bug, and answering the second one from the first
    one's cache entry would report success for a token nobody validated. Binding
    both degrades that case to an ordinary fresh verification.
    """

    def __init__(
        self,
        ttl_seconds: int = IDEMPOTENCY_TTL_SECONDS,
        max_entries: int = MAX_IDEMPOTENCY_ENTRIES,
    ):
        self.ttl_seconds = ttl_seconds
        self.entries = BoundedLRU(max_entries)

    @staticmethod
    def _key(idempotency_key: str, token: str) -> str:
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:32]
        return f"{idempotency_key}:{token_hash}"

    def get(self, idempotency_key: str, token: str) -> Optional[Dict[str, Any]]:
        if not idempotency_key:
            return None
        entry = self.entries.get(self._key(idempotency_key, token))
        if not entry:
            return None
        # >= so that a zero TTL means "never replay" rather than "replay once".
        if time.time() - entry["stored_at"] >= self.ttl_seconds:
            return None
        return entry["response"]

    def set(self, idempotency_key: str, token: str, response: Dict[str, Any]) -> None:
        if not idempotency_key:
            return
        self.entries.set(
            self._key(idempotency_key, token),
            {"stored_at": time.time(), "response": response},
        )


def failure(*codes: str) -> Dict[str, Any]:
    """A failing siteverify response carrying the given codes."""
    return {"success": False, "error-codes": list(codes)}


def read_params(body: Any) -> Dict[str, str]:
    """Read the siteverify parameters out of a decoded request body.

    Both encodings are accepted because the contract accepts both, and callers in
    the wild are split: PHP and Python examples overwhelmingly post form-encoded,
    Node and Go examples post JSON. The caller decodes; this normalises.
    """
    if not isinstance(body, dict):
        return {"secret": "", "response": "", "remoteip": "", "idempotency_key": ""}

    def as_str(value: Any) -> str:
        if isinstance(value, str):
            return value
        return "" if value is None else str(value)

    return {
        "secret": as_str(body.get("secret")),
        "response": as_str(body.get("response")),
        "remoteip": as_str(body.get("remoteip")),
        "idempotency_key": as_str(body.get("idempotency_key")),
    }


def siteverify(
    body: Any,
    verify_token,
    expected_secret: str,
    idempotency_store: Optional[IdempotencyStore] = None,
    require_secret: bool = True,
) -> Dict[str, Any]:
    """Run a siteverify request.

    ``verify_token`` is injected rather than imported so a caller can supply its
    own - the standalone server and any embedding hold separate token stores, and
    this module should not decide which one is authoritative.
    """
    params = read_params(body)
    secret = params["secret"]
    response = params["response"]
    remoteip = params["remoteip"]
    idempotency_key = params["idempotency_key"]

    if require_secret:
        if not secret:
            return failure(ERR_MISSING_SECRET)
        if not secret_matches(secret, expected_secret):
            return failure(ERR_INVALID_SECRET)

    if not response:
        return failure(ERR_MISSING_RESPONSE)

    if idempotency_store:
        cached = idempotency_store.get(idempotency_key, response)
        if cached is not None:
            return cached

    try:
        # remoteip is passed through to the IP-binding check. Empty means the
        # caller declined to assert one, which the token verifier treats as
        # "don't check".
        result = verify_token(response, remoteip or None)
    except Exception:
        # Never surface an exception's text: it can carry key material or
        # internals.
        return failure(ERR_INTERNAL_ERROR)

    if result and result.get("valid"):
        timestamp = result.get("timestamp") or 0
        out = {
            "success": True,
            "challenge_ts": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(timestamp)
            ) + ".000Z",
            "hostname": result.get("hostname") or "",
            "action": result.get("action") or "",
            "cdata": result.get("cdata") or "",
            "error-codes": [],
            # Not part of the upstream contract, but the whole reason to run
            # FCaptcha: a caller that only wants pass/fail can ignore it, and one
            # that wants to risk-band on the score has it without a second call.
            "score": result.get("score") if isinstance(result.get("score"), (int, float)) else None,
        }
    else:
        out = failure(reason_to_error_code(result.get("reason") if result else None))

    if idempotency_store:
        idempotency_store.set(idempotency_key, response, out)
    return out
