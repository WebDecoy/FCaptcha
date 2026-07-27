"""
Tests for site_key state bounds. Run: python3 test_sitekeys.py
"""

import sys

from sitekeys import (
    MAX_TRACKED_IPS,
    OVERFLOW_SITE_KEY,
    BoundedLRU,
    SiteKeyGuard,
)

_tests = []


def test(fn):
    _tests.append(fn)
    return fn


@test
def bounded_lru_evicts_lru_not_everything():
    """The pattern being replaced (`if len > N: clear()`) discards every
    legitimate entry at once - the flush an attacker wants."""
    m = BoundedLRU(3)
    m.set("a", 1)
    m.set("b", 2)
    m.set("c", 3)
    assert m.get("a") == 1  # touch, so "b" becomes oldest
    m.set("d", 4)
    assert len(m) == 3
    assert "b" not in m, "LRU victim should be b"
    for k in ("a", "c", "d"):
        assert k in m, f"{k} should survive"
    assert m.evictions == 1

    big = BoundedLRU(100)
    for i in range(1000):
        big.set(f"k{i}", i)
    assert len(big) == 100
    assert "k999" in big and "k0" not in big


@test
def bounded_lru_prune_is_selective():
    m = BoundedLRU(10)
    m.set("keep1", {"exp": 100})
    m.set("drop", {"exp": 1})
    m.set("keep2", {"exp": 100})
    m.prune(lambda v, k: v["exp"] > 50)
    assert len(m) == 2 and "drop" not in m


@test
def guard_caps_distinct_keys_per_ip():
    g = SiteKeyGuard(max_per_ip=3)
    ip = "203.0.113.9"
    for k in ("a", "b", "c"):
        assert g.normalize(k, ip) == k
    for k in ("d", "e"):
        assert g.normalize(k, ip) == OVERFLOW_SITE_KEY
    # A key already seen keeps working - a real tenant is not punished.
    assert g.normalize("b", ip) == "b"
    # A different IP has its own budget.
    assert g.normalize("z", "198.51.100.4") == "z"


@test
def rotation_collapses_into_one_bucket():
    g = SiteKeyGuard(max_per_ip=4)
    ip = "203.0.113.10"
    buckets = {g.normalize(f"rotate-{i}", ip) for i in range(200)}
    assert len(buckets) == 5, f"expected 4 real + overflow, got {len(buckets)}"
    assert OVERFLOW_SITE_KEY in buckets


@test
def allowlist_is_opt_in():
    # Unset: any key accepted, preserving zero-config self-hosting.
    open_guard = SiteKeyGuard.from_env({})
    assert open_guard.allowlist is None
    assert open_guard.normalize("anything", "203.0.113.1") == "anything"

    closed = SiteKeyGuard.from_env({"FCAPTCHA_SITE_KEYS": "real-site, other-site"})
    assert closed.normalize("real-site", "203.0.113.2") == "real-site"
    assert closed.normalize("other-site", "203.0.113.2") == "other-site"
    assert closed.normalize("junk", "203.0.113.2") == OVERFLOW_SITE_KEY
    assert closed.rejected_by_allowlist == 1


@test
def guard_tracking_table_is_bounded():
    g = SiteKeyGuard(max_per_ip=2, max_tracked_ips=10)
    for i in range(500):
        g.normalize("site", f"198.51.100.{i}")
    assert len(g.seen) == 10, "the guard must not become the leak it prevents"


@test
def edge_cases_do_not_raise():
    g = SiteKeyGuard()
    assert g.normalize(None, "203.0.113.3") == "default"
    assert g.normalize("", "203.0.113.3") == "default"
    # No IP: nothing to bound against, pass through rather than punish.
    assert g.normalize("k", None) == "k"


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
