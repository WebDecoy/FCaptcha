"""
Tests for the siteverify compatibility layer. Run: python3 test_siteverify.py

Mirrors server-node/siteverify.test.js and server-go/siteverify_test.go - the
three servers must agree on hostname derivation, the error-code vocabulary and
the idempotency semantics, because an integrator switching between them should
not be able to tell which one answered.
"""

from testkit import TestRegistry

from siteverify import (
    ERR_INTERNAL_ERROR,
    ERR_INVALID_RESPONSE,
    ERR_INVALID_SECRET,
    ERR_MISSING_RESPONSE,
    ERR_MISSING_SECRET,
    ERR_TIMEOUT_OR_DUPLICATE,
    MAX_ACTION_LENGTH,
    MAX_CDATA_LENGTH,
    HostnameAllowlist,
    IdempotencyStore,
    host_from_url,
    reason_to_error_code,
    request_hostname,
    sanitize_action,
    sanitize_cdata,
    secret_matches,
    siteverify,
)

test = TestRegistry()

VALID = {
    "valid": True,
    "timestamp": 1770000000,
    "score": 0.12,
    "hostname": "example.com",
    "action": "login",
    "cdata": "session-1",
}

SECRET = "the-secret"


def fake_verifier(table):
    """A stand-in for verify_token that records its calls."""
    calls = []

    def verify(token, ip=None):
        calls.append({"token": token, "ip": ip})
        if token not in table:
            return {"valid": False, "reason": "invalid_signature"}
        entry = table[token]
        return entry() if callable(entry) else entry

    verify.calls = calls
    return verify


def run(body, verify_token=None, store=None, require_secret=True):
    return siteverify(
        body=body,
        verify_token=verify_token or fake_verifier({"good-token": VALID}),
        expected_secret=SECRET,
        idempotency_store=store,
        require_secret=require_secret,
    )


# ------------------------------------------------------------------ hostname


@test
def host_from_url_strips_scheme_port_and_case():
    assert host_from_url("https://Example.COM:8443/a/b?c=d") == "example.com"
    assert host_from_url("http://example.com") == "example.com"


@test
def host_from_url_treats_opaque_origin_as_no_hostname():
    """Sandboxed iframes and file:// pages send the literal string "null"."""
    assert host_from_url("null") == ""
    assert host_from_url("") == ""
    assert host_from_url(None) == ""
    assert host_from_url(12345) == ""
    # A bare host with no scheme is not an origin.
    assert host_from_url("example.com") == ""


@test
def host_from_url_unwraps_ipv6():
    assert host_from_url("https://[::1]:3000/") == "::1"


@test
def request_hostname_prefers_origin():
    assert (
        request_hostname(
            {"origin": "https://origin.example", "referer": "https://referer.example/p"}
        )
        == "origin.example"
    )


@test
def request_hostname_falls_back_then_empties():
    assert request_hostname({"referer": "https://referer.example/p"}) == "referer.example"
    # An opaque Origin must fall through to Referer rather than pinning "".
    assert request_hostname({"origin": "null", "referer": "https://r.example/"}) == "r.example"
    assert request_hostname({}) == ""
    assert request_hostname(None) == ""


# ----------------------------------------------------------------- allowlist


@test
def allowlist_is_permissive_when_unset():
    allowlist = HostnameAllowlist.from_env({})
    assert not allowlist.enabled
    assert allowlist.permits("anything.example")


@test
def allowlist_admits_listed_and_rejects_others():
    allowlist = HostnameAllowlist.from_env({"FCAPTCHA_ALLOWED_HOSTNAMES": "a.example, B.EXAMPLE"})
    assert allowlist.enabled
    assert allowlist.permits("a.example")
    assert allowlist.permits("b.example"), "matching is case-insensitive"
    assert not allowlist.permits("evil.example")


@test
def allowlist_admits_a_request_with_no_hostname():
    """A native mobile client or server-side integration has no Origin. Refusing
    those would break them without stopping anything: an attacker who can forge
    an Origin would just forge an allowed one."""
    allowlist = HostnameAllowlist.from_env({"FCAPTCHA_ALLOWED_HOSTNAMES": "a.example"})
    assert allowlist.permits("")


# ---------------------------------------------------------------- sanitizing


@test
def sanitizing_caps_length():
    assert len(sanitize_action("x" * 200)) == MAX_ACTION_LENGTH
    assert len(sanitize_cdata("x" * 9999)) == MAX_CDATA_LENGTH


@test
def sanitizing_strips_control_characters():
    """These are echoed back to the caller and into logs."""
    assert sanitize_action("log\nin") == "login"
    assert sanitize_cdata("a\r\nb") == "ab"


@test
def sanitizing_coerces_non_strings_to_empty():
    for value in (None, 42, {}, []):
        assert sanitize_action(value) == ""


# ------------------------------------------------------------------- secrets


@test
def secret_matches_compares_correctly():
    assert secret_matches("hunter2", "hunter2")
    assert not secret_matches("hunter2", "hunter3")


@test
def secret_matches_tolerates_unequal_lengths():
    """Hashing first is what keeps unequal lengths from being a special case."""
    assert not secret_matches("short", "a-much-longer-secret")
    assert not secret_matches("", "x")
    assert not secret_matches(None, "x")


# --------------------------------------------------------------- error codes


@test
def reason_mapping_collapses_to_the_turnstile_vocabulary():
    assert reason_to_error_code("expired") == ERR_TIMEOUT_OR_DUPLICATE
    assert reason_to_error_code("token_already_used") == ERR_TIMEOUT_OR_DUPLICATE
    assert reason_to_error_code("invalid_signature") == ERR_INVALID_RESPONSE
    assert reason_to_error_code("ip_mismatch") == ERR_INVALID_RESPONSE


@test
def an_unrecognised_reason_does_not_leak_through():
    """verify_token returns str(e) on an unexpected throw; that must not reach
    the caller as an error code."""
    assert reason_to_error_code("KeyError: 'signals'") == ERR_INVALID_RESPONSE
    assert reason_to_error_code(None) == ERR_INVALID_RESPONSE


# --------------------------------------------------------------- the adapter


@test
def a_valid_token_produces_the_documented_success_shape():
    out = run({"secret": SECRET, "response": "good-token"})
    assert out["success"] is True
    assert out["hostname"] == "example.com"
    assert out["action"] == "login"
    assert out["cdata"] == "session-1"
    assert out["error-codes"] == []
    assert out["challenge_ts"] == "2026-02-02T02:40:00.000Z"
    assert out["score"] == 0.12


@test
def a_missing_secret_is_refused_before_the_token_is_spent():
    verify = fake_verifier({"good-token": VALID})
    out = run({"response": "good-token"}, verify_token=verify)
    assert out["success"] is False
    assert out["error-codes"] == [ERR_MISSING_SECRET]
    assert len(verify.calls) == 0, "must not spend the token"


@test
def a_wrong_secret_is_refused_before_the_token_is_spent():
    verify = fake_verifier({"good-token": VALID})
    out = run({"secret": "nope", "response": "good-token"}, verify_token=verify)
    assert out["error-codes"] == [ERR_INVALID_SECRET]
    assert len(verify.calls) == 0, "must not spend the token"


@test
def a_missing_response_reports_missing_input_response():
    out = run({"secret": SECRET})
    assert out["error-codes"] == [ERR_MISSING_RESPONSE]


@test
def require_secret_false_restores_the_legacy_behaviour():
    out = run({"response": "good-token"}, require_secret=False)
    assert out["success"] is True


@test
def an_expired_token_reports_timeout_or_duplicate():
    out = run(
        {"secret": SECRET, "response": "stale"},
        verify_token=fake_verifier({"stale": {"valid": False, "reason": "expired"}}),
    )
    assert out["success"] is False
    assert out["error-codes"] == [ERR_TIMEOUT_OR_DUPLICATE]


@test
def a_raising_verifier_degrades_to_internal_error():
    def boom(token, ip=None):
        raise RuntimeError("secret key material: hunter2")

    out = run({"secret": SECRET, "response": "boom"}, verify_token=boom)
    assert out["success"] is False
    assert out["error-codes"] == [ERR_INTERNAL_ERROR]
    assert "hunter2" not in str(out)


@test
def remoteip_is_forwarded_and_absence_means_unchecked():
    verify = fake_verifier({"good-token": VALID})
    run({"secret": SECRET, "response": "good-token", "remoteip": "203.0.113.7"}, verify_token=verify)
    assert verify.calls[0]["ip"] == "203.0.113.7"

    verify2 = fake_verifier({"good-token": VALID})
    run({"secret": SECRET, "response": "good-token"}, verify_token=verify2)
    assert verify2.calls[0]["ip"] is None, "no remoteip means do not bind"


@test
def a_malformed_body_is_refused_rather_than_raising():
    for body in (None, "a string", 42, []):
        out = run(body)
        assert out["success"] is False
        assert out["error-codes"] == [ERR_MISSING_SECRET]


# --------------------------------------------------------------- idempotency


@test
def an_idempotency_key_replays_instead_of_burning_the_token():
    """Models the real single-use guard: the second call would fail on its own."""
    state = {"spent": False}

    def verify(token, ip=None):
        if state["spent"]:
            return {"valid": False, "reason": "token_already_used"}
        state["spent"] = True
        return VALID

    store = IdempotencyStore()
    body = {"secret": SECRET, "response": "tok", "idempotency_key": "k1"}
    first = run(body, verify_token=verify, store=store)
    second = run(body, verify_token=verify, store=store)

    assert first["success"] is True
    assert second["success"] is True, "retry under the same key must succeed"
    assert first == second


@test
def without_an_idempotency_key_the_single_use_guard_still_bites():
    state = {"spent": False}

    def verify(token, ip=None):
        if state["spent"]:
            return {"valid": False, "reason": "token_already_used"}
        state["spent"] = True
        return VALID

    store = IdempotencyStore()
    body = {"secret": SECRET, "response": "tok"}
    first = run(body, verify_token=verify, store=store)
    second = run(body, verify_token=verify, store=store)

    assert first["success"] is True
    assert second["success"] is False
    assert second["error-codes"] == [ERR_TIMEOUT_OR_DUPLICATE]


@test
def one_key_reused_across_tokens_does_not_cross_answer():
    """Reusing a key for a different token is a caller bug; answering the second
    from the first's cache would report success for a token nobody validated."""
    verify = fake_verifier(
        {"token-a": VALID, "token-b": {"valid": False, "reason": "invalid_signature"}}
    )
    store = IdempotencyStore()
    a = run({"secret": SECRET, "response": "token-a", "idempotency_key": "k"}, verify_token=verify, store=store)
    b = run({"secret": SECRET, "response": "token-b", "idempotency_key": "k"}, verify_token=verify, store=store)

    assert a["success"] is True
    assert b["success"] is False, "must be verified on its own merits"


@test
def a_failing_answer_is_replayable_too():
    """Otherwise a retried failure could turn into a different failure, and the
    caller cannot tell a stable rejection from a flaky one."""
    verify = fake_verifier({"bad": {"valid": False, "reason": "invalid_signature"}})
    store = IdempotencyStore()
    body = {"secret": SECRET, "response": "bad", "idempotency_key": "k"}
    first = run(body, verify_token=verify, store=store)
    second = run(body, verify_token=verify, store=store)
    assert first == second
    assert len(verify.calls) == 1, "second call served from cache"


@test
def an_expired_idempotency_entry_is_not_served():
    verify = fake_verifier({"tok": VALID})
    store = IdempotencyStore(ttl_seconds=0)
    body = {"secret": SECRET, "response": "tok", "idempotency_key": "k"}
    run(body, verify_token=verify, store=store)
    run(body, verify_token=verify, store=store)
    assert len(verify.calls) == 2, "a TTL of 0 means never replay"


@test
def the_idempotency_store_is_bounded():
    store = IdempotencyStore(max_entries=4)
    for i in range(50):
        store.set(f"key-{i}", "tok", {"success": True})
    assert len(store.entries) == 4


# ------------------------------------------- cross-language token format
#
# The three servers sign the same claims, so they must serialise them the same
# way. They did not: Go emitted padded base64url, Node unpadded, and Python
# signed a payload with a space after every ':' and ','. No two could verify
# each other's tokens, and nothing caught it because each server only ever
# verified its own. These fixtures pin the shared format so a future edit to any
# one implementation fails here instead of in a mixed fleet.
#
# Keep byte-identical across server-node/siteverify.test.js,
# server-go/siteverify_test.go and server-python/test_siteverify.py.

FIXTURE_CLAIMS = {
    "site_key": "s",
    "timestamp": 1700000000,
    "score": 0.11,
    "ip_hash": "abcd1234",
    "hostname": "example.com",
    "action": "login",
    "cdata": "c1",
}
FIXTURE_PAYLOAD = (
    '{"action":"login","cdata":"c1","hostname":"example.com",'
    '"ip_hash":"abcd1234","score":0.11,"site_key":"s","timestamp":1700000000}'
)
FIXTURE_SIG = "75bd31f5adfc85b1af1be4811ebe228995320a09b59bda3826ac9383bb1cb6b0"
FIXTURE_SECRET = "fixture-secret"


@test
def canonical_payload_is_sorted_and_unspaced():
    from server import _canonical_payload

    assert _canonical_payload(FIXTURE_CLAIMS) == FIXTURE_PAYLOAD


@test
def fixture_claims_produce_the_shared_signature():
    import hashlib
    import hmac as _hmac

    from server import _canonical_payload

    payload = _canonical_payload(FIXTURE_CLAIMS)
    sig = _hmac.new(FIXTURE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    assert sig == FIXTURE_SIG


@test
def tokens_are_unpadded_base64url():
    import base64

    from server import _decode_token_base64

    encoded = base64.urlsafe_b64encode(FIXTURE_PAYLOAD.encode()).decode().rstrip("=")
    assert "=" not in encoded and "+" not in encoded and "/" not in encoded
    # and the decoder must still accept the padded form other versions emitted
    padded = base64.urlsafe_b64encode(FIXTURE_PAYLOAD.encode()).decode()
    assert _decode_token_base64(padded).decode() == FIXTURE_PAYLOAD


SiteverifyTests = test.testcase("SiteverifyTests")

if __name__ == "__main__":
    test.main()
