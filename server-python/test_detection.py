"""Tests for HTTP header analysis and score aggregation.

These cover false positives the bench human panel surfaced: forwarding headers
scored as suspicious unconditionally, so every visitor to every deployment
behind a reverse proxy carried a permanent bot detection; and corroborating
evidence weakening a verdict rather than strengthening it.

Run: python test_detection.py
"""

from testkit import TestRegistry

from detection import analyze_headers
from server import (
    Detection,
    ThreatCategory,
    apply_dispositive_floor,
    calculate_category_scores,
    DISPOSITIVE_FLOOR,
)

test = TestRegistry()


def browser_headers():
    return {
        "accept": "text/html,application/xhtml+xml",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0",
    }


def suspicious(dets):
    return [d["reason"] for d in dets if d["reason"].startswith("Suspicious header present")]


@test
def forwarding_headers_are_fine_from_a_trusted_proxy():
    h = {**browser_headers(), "x-forwarded-for": "203.0.113.9"}
    assert suspicious(analyze_headers(h, True)) == [], "a proxy adding XFF is doing its job"


@test
def forwarding_headers_are_suspicious_from_an_untrusted_peer():
    # Nothing legitimate about a direct client claiming to forward for someone.
    h = {**browser_headers(), "x-forwarded-for": "203.0.113.9"}
    hits = suspicious(analyze_headers(h, False))
    assert len(hits) == 1, hits


@test
def defaults_to_the_stricter_behaviour():
    h = {**browser_headers(), "x-real-ip": "203.0.113.9"}
    assert len(suspicious(analyze_headers(h))) == 1


@test
def a_full_cdn_header_set_is_clean_behind_a_trusted_proxy():
    # Cloudflare alone adds three of these.
    h = {
        **browser_headers(),
        "x-forwarded-for": "203.0.113.9",
        "cf-connecting-ip": "203.0.113.9",
        "true-client-ip": "203.0.113.9",
        "via": "1.1 cloudflare",
    }
    assert suspicious(analyze_headers(h, True)) == []


@test
def x_requested_with_ignores_peer_trust():
    # Set by XHR libraries, not by proxies, so trusting the peer says nothing.
    for peer_trusted in (True, False):
        h = {**browser_headers(), "x-requested-with": "XMLHttpRequest"}
        hits = suspicious(analyze_headers(h, peer_trusted))
        assert len(hits) == 1, f"peer_trusted={peer_trusted}: {hits}"


@test
def category_score_is_monotone_in_evidence():
    # Corroborating evidence must never weaken a verdict. Before noisy-OR,
    # adding automation tells to a WebDriver hit pulled the average down.
    webdriver = Detection(ThreatCategory.HEADLESS, 0.95, 0.95, "WebDriver detected")
    corroborating = [
        Detection(ThreatCategory.HEADLESS, 0.6, 0.6, "no plugins"),
        Detection(ThreatCategory.HEADLESS, 0.4, 0.5, "viewport equals window"),
        Detection(ThreatCategory.HEADLESS, 0.3, 0.4, "notifications denied"),
        Detection(ThreatCategory.HEADLESS, 0.8, 0.8, "software renderer"),
    ]

    prev = calculate_category_scores([webdriver])[ThreatCategory.HEADLESS.value]
    for i in range(len(corroborating)):
        got = calculate_category_scores([webdriver] + corroborating[: i + 1])[
            ThreatCategory.HEADLESS.value
        ]
        assert got >= prev, f"adding evidence lowered the score: {prev:.3f} -> {got:.3f}"
        prev = got


@test
def dispositive_floor():
    plain = [Detection(ThreatCategory.HEADLESS, 0.4, 0.4, "weak")]
    assert apply_dispositive_floor(0.2, plain) == 0.2, "ordinary evidence must not trigger it"

    declared = [Detection(ThreatCategory.HEADLESS, 0.95, 0.95, "WebDriver detected", dispositive=True)]
    assert apply_dispositive_floor(0.2, declared) == DISPOSITIVE_FLOOR

    # The floor raises, never lowers.
    assert apply_dispositive_floor(0.97, declared) == 0.97


DetectionTests = test.testcase("DetectionTests")


if __name__ == "__main__":
    test.main()
