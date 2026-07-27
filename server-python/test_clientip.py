"""
Tests for trusted-proxy client IP resolution.

Run: python3 test_clientip.py
"""

import sys

from clientip import MAX_PROXY_MISCONFIG_WARNINGS, ProxyTrust

DEFAULT_SPEC = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"


class _Headers(dict):
    """Case-insensitive lookup, matching Starlette's Headers."""

    def get(self, key, default=""):
        return super().get(key.lower(), default)


class _Client:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    """Minimal stand-in for a Starlette/FastAPI Request."""

    def __init__(self, host, headers=None):
        self.client = _Client(host) if host is not None else None
        self.headers = _Headers({k.lower(): v for k, v in (headers or {}).items()})


_tests = []


def test(fn):
    _tests.append(fn)
    return fn


@test
def headers_from_untrusted_peer_are_ignored():
    """The bypass this file exists to prevent: a caller reaching the server
    directly claims a residential IP and expects the datacenter/Tor/rate-limit
    checks to see it. 159.65.1.1 is a DigitalOcean range in detection.py."""
    trust = ProxyTrust(DEFAULT_SPEC)
    spoofs = [
        {"X-Real-IP": "73.15.22.100"},
        {"X-Forwarded-For": "73.15.22.100"},
        {"X-Real-IP": "73.15.22.100", "X-Forwarded-For": "8.8.8.8"},
        {"X-Forwarded-For": "73.15.22.100, 1.1.1.1, 2.2.2.2"},
    ]
    for headers in spoofs:
        got = trust.client_ip(FakeRequest("159.65.1.1", headers))
        assert got == "159.65.1.1", f"spoofed header honoured ({headers}): got {got}"


@test
def headers_from_trusted_proxy_are_honoured():
    trust = ProxyTrust(DEFAULT_SPEC)
    cases = [
        ("x-real-ip from loopback nginx", "127.0.0.1", {"X-Real-IP": "73.15.22.100"}, "73.15.22.100"),
        ("x-forwarded-for from private proxy", "10.0.1.5", {"X-Forwarded-For": "73.15.22.100"}, "73.15.22.100"),
        # The client prepended a fake hop; the rightmost untrusted entry is
        # still the address our edge actually accepted.
        ("client-prepended chain", "127.0.0.1", {"X-Forwarded-For": "1.2.3.4, 73.15.22.100"}, "73.15.22.100"),
        # Two real proxies in front of us: skip our own, keep the client.
        ("trusted hops skipped right to left", "10.0.1.5",
         {"X-Forwarded-For": "73.15.22.100, 10.0.1.9, 192.168.1.2"}, "73.15.22.100"),
        ("x-real-ip wins over x-forwarded-for", "127.0.0.1",
         {"X-Real-IP": "73.15.22.100", "X-Forwarded-For": "1.2.3.4"}, "73.15.22.100"),
        ("malformed hop falls back to peer", "127.0.0.1",
         {"X-Forwarded-For": "73.15.22.100, unknown"}, "127.0.0.1"),
        ("no headers falls back to peer", "127.0.0.1", {}, "127.0.0.1"),
        ("entirely trusted chain falls back to peer", "10.0.1.5",
         {"X-Forwarded-For": "10.0.1.9"}, "10.0.1.5"),
    ]
    for name, peer, headers, want in cases:
        got = trust.client_ip(FakeRequest(peer, headers))
        assert got == want, f"{name}: got {got}, want {want}"


@test
def addresses_are_normalized():
    """The value handed to is_datacenter_ip has to be a bare, dotted address or
    CIDR matching silently fails."""
    trust = ProxyTrust(DEFAULT_SPEC)
    assert trust.client_ip(FakeRequest("::ffff:159.65.1.1")) == "159.65.1.1"
    assert trust.client_ip(FakeRequest("2001:db8::1")) == "2001:db8::1"
    # An IPv4-mapped loopback peer must still be recognised as trusted.
    assert trust.client_ip(FakeRequest("::ffff:127.0.0.1", {"X-Real-IP": "73.15.22.100"})) == "73.15.22.100"
    # An IPv6 peer is not matched against IPv4 ranges (and must not raise).
    assert trust.client_ip(FakeRequest("2001:db8::1", {"X-Real-IP": "73.15.22.100"})) == "2001:db8::1"
    # No socket at all: nothing to trust, nothing to forward.
    assert trust.client_ip(FakeRequest(None, {"X-Real-IP": "73.15.22.100"})) == "127.0.0.1"


@test
def spec_forms():
    headers = {"X-Real-IP": "73.15.22.100"}

    assert ProxyTrust("*").client_ip(FakeRequest("159.65.1.1", headers)) == "73.15.22.100"
    assert ProxyTrust("none").client_ip(FakeRequest("127.0.0.1", headers)) == "127.0.0.1"
    assert ProxyTrust("").client_ip(FakeRequest("127.0.0.1", headers)) == "127.0.0.1"

    single = ProxyTrust("203.0.113.7")
    assert single.client_ip(FakeRequest("203.0.113.7", headers)) == "73.15.22.100"
    assert single.client_ip(FakeRequest("203.0.113.8", headers)) == "203.0.113.8"

    # A typo in one entry must not discard the valid ones.
    mixed = ProxyTrust("not-an-ip, 999.0.0.1/8, 127.0.0.0/8")
    assert mixed.client_ip(FakeRequest("127.0.0.1", headers)) == "73.15.22.100"


@test
def from_env_distinguishes_unset_from_empty():
    headers = {"X-Real-IP": "73.15.22.100"}

    # Unset: private/loopback defaults apply.
    unset = ProxyTrust.from_env({})
    assert unset.client_ip(FakeRequest("127.0.0.1", headers)) == "73.15.22.100"
    assert unset.client_ip(FakeRequest("159.65.1.1", headers)) == "159.65.1.1"

    # Explicitly empty: trust nothing.
    empty = ProxyTrust.from_env({"TRUSTED_PROXIES": ""})
    assert empty.client_ip(FakeRequest("127.0.0.1", headers)) == "127.0.0.1"


@test
def trusted_header_gates_ja3():
    """A client that can set its own JA3 presents a stock Chrome fingerprint and
    erases the signal, so the header is only read from a trusted proxy."""
    trust = ProxyTrust(DEFAULT_SPEC)
    ja3 = "cd08e31494f9531f560d64c695473da9"
    assert trust.trusted_header(FakeRequest("159.65.1.1", {"X-JA3-Hash": ja3}), "X-JA3-Hash") == ""
    assert trust.trusted_header(FakeRequest("127.0.0.1", {"X-JA3-Hash": ja3}), "X-JA3-Hash") == ja3


@test
def untrusted_forwarding_is_warned_about_boundedly():
    """The misconfiguration hint: an unlisted reverse proxy and a spoofing client
    look identical here, and the silent failure (every visitor collapsing onto
    one address) is the expensive one, so it must be logged and bounded."""
    import io
    import contextlib

    trust = ProxyTrust(DEFAULT_SPEC)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        # No forwarding headers, and the normal trusted path: both silent.
        trust.client_ip(FakeRequest("159.65.1.1"))
        trust.client_ip(FakeRequest("127.0.0.1", {"X-Real-IP": "73.15.22.100"}))
    assert buf.getvalue() == "", f"warned unexpectedly: {buf.getvalue()}"

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        # Untrusted peer sending forwarding headers: name the peer and the remedy.
        trust.client_ip(FakeRequest("159.65.1.1", {"X-Real-IP": "73.15.22.100"}))
    first = buf.getvalue()
    assert "159.65.1.1" in first, f"warning omits the peer: {first}"
    assert "TRUSTED_PROXIES" in first, f"warning omits the remedy: {first}"

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        # Bounded: a directly exposed server sees spoofing constantly.
        for _ in range(50):
            trust.client_ip(FakeRequest("159.65.1.1", {"X-Forwarded-For": "73.15.22.100"}))
    count = buf.getvalue().count("untrusted peer")
    assert count == MAX_PROXY_MISCONFIG_WARNINGS - 1, f"emitted {count} more warnings"
    assert "further warnings suppressed" in buf.getvalue()


if __name__ == "__main__":
    failures = 0
    for fn in _tests:
        try:
            fn()
            print(f"  ok  {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL {fn.__name__}\n       {exc}")
    print(f"\n{len(_tests) - failures}/{len(_tests)} passed")
    sys.exit(1 if failures else 0)
