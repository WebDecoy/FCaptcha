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
    calculate_final_score,
    detect_behavioral,
    detect_vision_ai,
    has_widget_interaction,
    run_verification,
    set_interaction_mode,
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


# ------------------------------------------------------------- PoW gating
#
# A proof of work is a precondition, not evidence. These guard the bypass found
# on 2026-08-19: a bare `curl` sending {"siteKey": "x", "signals": {}} - no
# browser, no PoW, a curl User-Agent - was issued a valid token, ten times out of
# ten, on every server. Every detector fired correctly; the aggregation threw the
# verdict away, because the final score is a weighted sum and the bot category
# contributes at most its 0.13 weight. All the PoW failures firing at once
# reached 0.1298 against a 0.5 threshold.


def _no_pow_verification(signals=None):
    """A verification the way the bypass ran it: no PoW solution at all."""
    return run_verification(
        signals if signals is not None else {},
        "203.0.113.4",
        "site",
        "curl/8.7.1",
    )


@test
def no_pow_solution_withholds_a_token():
    result = _no_pow_verification()
    assert result["success"] is False, "a request with no PoW must not succeed"
    assert not result["token"], "a request with no PoW must not be issued a token"


@test
def failed_pow_does_not_floor_the_score():
    """The v1.23.0 regression, found when the demo site refused its own author.

    Marking the PoW failures dispositive turned every benign cause into a hard
    block: a challenge expires after five minutes, challenges live only in memory
    so every deploy invalidates the outstanding ones, and a double-click replays
    a solution. The gate carries the security requirement; flooring on top of it
    asserts something false about the visitor."""
    human = {
        "behavioral": {
            "totalPoints": 180, "trajectoryLength": 2400, "approachPoints": 42,
            "mouseEvents": 180, "directionChanges": 22, "microTremorScore": 0.7,
        }
    }
    result = run_verification(human, "203.0.113.4", "site", "Mozilla/5.0")
    assert result["score"] < DISPOSITIVE_FLOOR, (
        f"a benign PoW failure floored the score to {result['score']}")
    assert result["success"] is False, "the gate must still withhold the token"
    assert not result["token"]


@test
def withheld_token_names_the_failed_precondition():
    result = _no_pow_verification()
    assert result.get("reason") == "pow_not_satisfied", result.get("reason")


@test
def bot_category_alone_cannot_reach_the_threshold():
    """Pins the reason the gate has to exist rather than trusting the score. If
    this ever fails because the weighted sum was replaced, revisit whether the
    gate is still the right mechanism - but do not remove it on the strength of a
    reweighting alone."""
    saturated = {ThreatCategory.BOT.value: 1.0}
    assert calculate_final_score(saturated) < 0.5, calculate_final_score(saturated)


def _click_derived_session():
    """A session with click-derived fields at the values an absent
    analyzeClick() produces server-side, plus a couple of minutes on the page."""
    return {"behavioral": {
        "totalPoints": 60, "trajectoryLength": 400,
        "microTremorScore": 0.4, "velocityVariance": 0.5,
        "touchEvents": 0, "keyEvents": 0,
        "approachPoints": 0, "explorationRatio": 0.0,
        "overshootCorrections": 0,
        "interactionDuration": 120000,
    }}


CLICK_DERIVED_REASONS = (
    "No approach trajectory to target",
    "No exploratory mouse movement before click",
    "No overshoot corrections on long trajectory",
    "Unusually long interaction time",
)


@test
def invisible_mode_skips_click_derived_checks():
    """approachPoints, explorationRatio and overshootCorrections come only from
    the client's analyzeClick(), which never runs without a widget, and
    interactionDuration means time-on-page there rather than time-to-solve.
    Production logs had the approach check firing on 100% of /api/score calls
    before this. One payload, so the mode is the only variable."""
    widget = set_interaction_mode(_click_derived_session(), True)
    widget_reasons = [d.reason for d in detect_vision_ai(widget) + detect_behavioral(widget)]
    for reason in CLICK_DERIVED_REASONS:
        assert reason in widget_reasons, (reason, widget_reasons)

    invisible = set_interaction_mode(_click_derived_session(), False)
    invisible_reasons = [d.reason for d in detect_vision_ai(invisible) + detect_behavioral(invisible)]
    for reason in CLICK_DERIVED_REASONS:
        assert reason not in invisible_reasons, (reason, invisible_reasons)


@test
def interaction_mode_defaults_to_widget():
    # Callers that never set it keep the pre-existing behaviour.
    assert has_widget_interaction(_click_derived_session()) is True


@test
def client_cannot_claim_invisible_mode():
    # The mode comes from the endpoint, so a client that puts serverContext in
    # its own signals must not switch the checks off.
    spoofed = _click_derived_session()
    spoofed["serverContext"] = {"widgetInteraction": False}
    set_interaction_mode(spoofed, True)
    assert has_widget_interaction(spoofed) is True


DetectionTests = test.testcase("DetectionTests")


if __name__ == "__main__":
    test.main()
