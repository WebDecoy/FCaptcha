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
    apply_corroboration_floor,
    detect_cdp,
    BEHAVIOURAL_CATEGORIES,
    CORROBORATION_AGREE_AT,
    CORROBORATION_FLOOR,
    keyboard_only_user,
    widget_instance,
    DEVICE_VERIFICATIONS_PER_MINUTE,
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


# ---------------------------------------------------------------------------
# Behavioural corroboration floor. Mirrors server-go/corroboration_test.go.
# ---------------------------------------------------------------------------

def views(cats):
    """One detection per category at exactly the given strength, so each
    category's noisy-OR score is the number written here."""
    return [Detection(ThreatCategory(c), s, 1.0, c) for c, s in cats.items()]


@test
def two_agreeing_behavioural_categories_floor_the_score():
    got = apply_corroboration_floor(0.234, views({"vision_ai": 0.652, "behavioral": 0.597, "automation": 0.36}))
    assert got == CORROBORATION_FLOOR, got


@test
def one_category_alone_never_floors_however_strong():
    for c in BEHAVIOURAL_CATEGORIES:
        assert apply_corroboration_floor(0.2, views({c: 1.0})) == 0.2, c


@test
def non_behavioural_categories_do_not_corroborate():
    assert apply_corroboration_floor(0.3, views({"headless": 1.0, "fingerprint": 1.0, "bot": 1.0})) == 0.3


@test
def the_floor_never_lowers_a_score():
    assert apply_corroboration_floor(0.95, views({"vision_ai": 0.9, "behavioral": 0.9})) == 0.95


@test
def agreement_starts_exactly_at_the_threshold():
    under = CORROBORATION_AGREE_AT - 0.01
    assert apply_corroboration_floor(0.2, views({"vision_ai": under, "behavioral": under})) == 0.2
    at = CORROBORATION_AGREE_AT
    assert apply_corroboration_floor(0.2, views({"vision_ai": at, "behavioral": at})) == CORROBORATION_FLOOR


@test
def a_non_corroborating_detection_cannot_be_the_second_view():
    console = Detection(ThreatCategory.CDP, 0.6, 1.0, "console attached", non_corroborating=True)
    movement = Detection(ThreatCategory.BEHAVIORAL, CORROBORATION_AGREE_AT, 1.0, "movement")
    assert apply_corroboration_floor(0.2, [console, movement]) == 0.2
    # Same evidence from an independent view does floor: provenance, not strength.
    independent = Detection(ThreatCategory.CDP, 0.6, 1.0, "independent view")
    assert apply_corroboration_floor(0.2, [independent, movement]) == CORROBORATION_FLOOR


@test
def a_non_corroborating_detection_still_scores_its_category():
    scores = calculate_category_scores([Detection(ThreatCategory.CDP, 0.6, 0.5, "console", non_corroborating=True)])
    assert abs(scores["cdp"] - 0.3) < 1e-9, scores


@test
def the_console_attach_probe_carries_the_mark_and_only_it():
    dets = detect_cdp({"behavioral": {"touchEvents": 0}, "environmental": {"cdpRuntime": {"consoleAttached": True}}})
    probe = [d for d in dets if "console consumer attached" in d.reason]
    assert probe and probe[0].non_corroborating, dets
    assert sum(1 for d in dets if d.non_corroborating) == 1, dets


@test
def the_extension_driven_click_that_passed_at_0_5_is_floored_at_0_4():
    # Live measurement, webdecoy.com demo 2026-09-09, v1.35.0: vision_ai 0.40
    # (0.3999999999999999 in floating point), behavioral 0.44, cdp 0.30 from the
    # console probe alone, weighted sum 0.189, allowed.
    dets = [
        Detection(ThreatCategory.VISION_AI, 0.5, 0.5, "path unnaturally direct"),
        Detection(ThreatCategory.VISION_AI, 0.4, 0.5, "click precision"),
        Detection(ThreatCategory.BEHAVIORAL, 0.6, 0.7, "insufficient movement"),
        Detection(ThreatCategory.BEHAVIORAL, 0.2, 0.2, "no scroll or keyboard"),
        Detection(ThreatCategory.CDP, 0.6, 0.5, "console attached", non_corroborating=True),
        Detection(ThreatCategory.FINGERPRINT, 0.4, 0.4, "canvas blocked"),
    ]
    assert apply_corroboration_floor(0.189, dets) >= 0.5


@test
def a_developer_with_devtools_open_and_a_quick_click_is_not_floored():
    dets = [
        Detection(ThreatCategory.BEHAVIORAL, 0.5, 0.5, "first interaction too soon"),
        Detection(ThreatCategory.BEHAVIORAL, 0.4, 0.4, "no overshoot corrections"),
        Detection(ThreatCategory.CDP, 0.6, 0.5, "console attached", non_corroborating=True),
        Detection(ThreatCategory.FINGERPRINT, 0.4, 0.4, "canvas blocked"),
    ]
    assert apply_corroboration_floor(0.115, dets) == 0.115


# ---------------------------------------------------------------------------
# Keyboard-only exemption and the per-device rate gate. Mirror the Go tests.
# ---------------------------------------------------------------------------

def kb(key_events, **extra):
    b = {"totalPoints": 0, "trajectoryLength": 0, "keyEvents": key_events, "touchEvents": 0}
    b.update(extra)
    return {"behavioral": b, "environmental": {"automationFlags": {}}}


def reasons(dets):
    return " | ".join(d.reason for d in dets)


@test
def keyboard_exemption_stands_without_hold_data():
    s = kb(8)
    assert keyboard_only_user(s, s["behavioral"]) is True


@test
def keyboard_exemption_stands_for_fingers():
    s = kb(12, keyHoldSamples=6, keyHoldAvg=85)
    assert keyboard_only_user(s, s["behavioral"]) is True


@test
def keyboard_exemption_denied_for_mechanical_holds():
    s = kb(12, keyHoldSamples=6, keyHoldAvg=4)
    assert keyboard_only_user(s, s["behavioral"]) is False


@test
def keyboard_exemption_pools_form_field_dwell():
    mechanical = dict(kb(9), formAnalysis={"textareaKeyboard": {"message": {"dwellTimes": [2, 3, 1, 2]}}})
    assert keyboard_only_user(mechanical, mechanical["behavioral"]) is False
    human = dict(kb(9), formAnalysis={"textareaKeyboard": {"message": {"dwellTimes": [60, 75, 90]}}})
    assert keyboard_only_user(human, human["behavioral"]) is True


@test
def keyboard_exemption_needs_enough_holds_to_judge():
    s = kb(4, keyHoldSamples=2, keyHoldAvg=3)
    assert keyboard_only_user(s, s["behavioral"]) is True


@test
def keyboard_exemption_requires_keys_and_no_pointer():
    one = kb(1)
    assert keyboard_only_user(one, one["behavioral"]) is False
    moved = kb(8, totalPoints=3)
    assert keyboard_only_user(moved, moved["behavioral"]) is False


@test
def keyboard_agent_is_scored_as_pointerless_and_corroborates():
    agent = kb(14, keyHoldSamples=14, keyHoldAvg=2)
    dets = detect_vision_ai(agent) + detect_behavioral(agent)
    assert "Zero mouse, touch, or keyboard events" in reasons(dets), reasons(dets)
    assert "No mouse movement detected before click" in reasons(dets), reasons(dets)
    assert apply_corroboration_floor(0.1, dets) >= CORROBORATION_FLOOR
    person = kb(14, keyHoldSamples=14, keyHoldAvg=80)
    dets = detect_vision_ai(person) + detect_behavioral(person)
    assert "Zero mouse" not in reasons(dets) and "No mouse movement" not in reasons(dets), reasons(dets)


def device_signals(instance):
    s = {"behavioral": {"totalPoints": 60, "trajectoryLength": 400, "approachPoints": 12,
                        "approachDirectness": 0.4, "microTremorScore": 0.5, "velocityVariance": 0.5},
         "environmental": {"automationFlags": {}}}
    if instance:
        s["meta"] = {"sessionId": instance}
    return s


@test
def the_eleventh_verification_from_one_page_instance_is_withheld():
    ip = "198.51.100.77"
    for i in range(DEVICE_VERIFICATIONS_PER_MINUTE):
        r = run_verification(device_signals("page-a"), ip, "site", "ua")
        assert r.get("reason") != "rate_limited", f"verification {i + 1} rate limited early"
    r = run_verification(device_signals("page-a"), ip, "site", "ua")
    assert r["success"] is False and r.get("reason") == "rate_limited", r
    assert any("for this device" in d["reason"] for d in r["detections"]), r["detections"]
    other = run_verification(device_signals("page-b"), ip, "site", "ua")
    assert other.get("reason") != "rate_limited", "a different widget instance must not inherit the budget"


@test
def no_widget_instance_means_no_device_gate():
    for _ in range(DEVICE_VERIFICATIONS_PER_MINUTE + 3):
        r = run_verification(device_signals(""), "198.51.100.78", "site", "ua")
        assert r.get("reason") != "rate_limited"


@test
def the_instance_id_is_bounded_before_it_becomes_a_key():
    assert len(widget_instance({"meta": {"widgetId": "x" * 500}})) == 64
    assert widget_instance({}) == ""
    assert widget_instance({"meta": {"sessionId": 42}}) == ""


DetectionTests = test.testcase("DetectionTests")


if __name__ == "__main__":
    test.main()
