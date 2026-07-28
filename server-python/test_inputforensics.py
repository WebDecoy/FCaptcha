"""Tests for input forensics v2 (run: python test_inputforensics.py).

The values here are the ones the bench corpus actually measured, not round
numbers: human typing at 226.9ms/4549 variance/82ms hold, a scripted agent at
7.9ms/8/7.8ms, human scrolling at 109px max step, an agent jump at 704px. A test
that passes on invented inputs proves nothing about real ones.
"""

from testkit import TestRegistry

from inputforensics import (
    check_font_platform_coherence,
    check_paste_platform_coherence,
    check_programmatic_fill,
    check_scroll_morphology,
    check_typing_cadence,
)

test = TestRegistry()


def field(interval, variance, dwell, key_count=43, paste_count=0):
    return {"message": {
        "keyCount": key_count, "pasteCount": paste_count,
        "avgKeyInterval": interval, "keyIntervalVariance": variance,
        "dwellTimes": dwell,
    }}


@test
def human_typing_not_flagged():
    assert check_typing_cadence(field(226.9, 4549, [82, 75, 91, 68]), {}) == []


@test
def scripted_cadence_flagged():
    got = check_typing_cadence(field(7.9, 8, [7.8, 8.1, 7.4, 8.0]), {})
    assert len(got) == 1, got
    assert "mechanical" in got[0]["reason"]


@test
def human_paste_never_flagged_as_machine_typing():
    # A paste is one or two keydowns microseconds apart - arithmetically
    # identical to very fast typing - and humans paste constantly.
    dwell = [2.6, 2.4]
    assert check_typing_cadence(field(0.8, 0, dwell, key_count=2), {}) == [], "n=2 is not a measurement"
    assert check_typing_cadence(field(0.8, 0, dwell), {"pasteEvents": 1}) == [], "page-level paste must exempt"
    assert check_typing_cadence(field(0.8, 0, dwell, paste_count=1), {}) == [], "field-level paste must exempt"


@test
def fast_but_variable_typing_not_flagged():
    # Below the interval floor on average, but with a human spread and human
    # holds. Both conditions must fail before we accuse anyone.
    assert check_typing_cadence(field(35, 900, [60, 45, 80]), {}) == []


@test
def paste_platform_contradiction():
    mac = {"pasteShortcutControl": 1, "pasteShortcutMeta": 0, "pasteEvents": 1}
    assert len(check_paste_platform_coherence(mac, "MacIntel")) == 1

    win = {"pasteShortcutMeta": 1, "pasteShortcutControl": 0, "pasteInputs": 1}
    assert len(check_paste_platform_coherence(win, "Win32")) == 1


@test
def coherent_paste_shortcut_not_flagged():
    assert check_paste_platform_coherence({"pasteShortcutMeta": 1, "pasteEvents": 1}, "MacIntel") == []
    assert check_paste_platform_coherence({"pasteShortcutControl": 1, "pasteEvents": 1}, "Win32") == []


@test
def wrong_shortcut_without_paste_is_fat_finger():
    # A Windows switcher on a new Mac really does reach for Ctrl+V. On macOS
    # nothing happens, so no paste follows - a habit, not a contradiction.
    m = {"pasteShortcutControl": 1, "pasteEvents": 0, "pasteInputs": 0}
    assert check_paste_platform_coherence(m, "MacIntel") == []


@test
def linux_claims_not_judged():
    m = {"pasteShortcutControl": 1, "pasteEvents": 1}
    assert check_paste_platform_coherence(m, "Linux x86_64") == []


@test
def programmatic_fill_is_contributory_only():
    got = check_programmatic_fill({"inputsWithoutInputType": 1, "inputsWithoutKeys": 1})
    assert len(got) == 1
    assert got[0]["confidence"] <= 0.5, "must stay contributory - autofill looks like this too"
    assert check_programmatic_fill(
        {"inputsWithoutInputType": 1, "inputsWithoutKeys": 1, "pasteEvents": 1}
    ) == [], "a paste is not a programmatic fill"


@test
def scroll_morphology():
    human = {"keyEvents": 0, "scrollMorphology": {"samples": 59, "maxStep": 109}}
    assert check_scroll_morphology(human) == []

    jump = {"keyEvents": 0, "scrollMorphology": {"samples": 3, "maxStep": 704}}
    assert len(check_scroll_morphology(jump)) == 1

    # PageDown and End move roughly a viewport in one event. That is a hand.
    kbd = {"keyEvents": 4, "scrollMorphology": {"samples": 6, "maxStep": 900}}
    assert check_scroll_morphology(kbd) == []


@test
def font_platform_coherence():
    win_under_mac = {"supported": True, "count": 12, "hasSegoeUI": True,
                     "hasCalibri": True, "hasSFPro": False, "hasMenlo": False}
    assert len(check_font_platform_coherence(win_under_mac, "MacIntel")) == 1

    coherent = {"supported": True, "count": 12, "hasSFPro": True, "hasMenlo": True, "hasSegoeUI": False}
    assert check_font_platform_coherence(coherent, "MacIntel") == []


@test
def blocked_font_list_never_flagged():
    # Score the contradiction, never the enumeration: a blocked or minimal font
    # list is a privacy extension or a lean Linux box, not an agent.
    for fonts in ({"supported": False},
                  {"supported": True, "count": 0},
                  {"supported": True, "count": 2, "hasSegoeUI": True}):
        assert check_font_platform_coherence(fonts, "MacIntel") == [], fonts


InputForensicsTests = test.testcase("InputForensicsTests")


if __name__ == "__main__":
    test.main()
