package main

import "testing"

// Tests for input forensics v2.
//
// The values here are the ones the bench corpus actually measured, not round
// numbers: human typing at 226.9ms/4549 variance/82ms hold, a scripted agent at
// 7.9ms/8/7.8ms, human scrolling at 109px max step, an agent jump at 704px. A
// test that passes on invented inputs proves nothing about real ones.

func typingField(interval, variance float64, dwell []interface{}, keyCount, pasteCount float64) map[string]interface{} {
	return map[string]interface{}{
		"message": map[string]interface{}{
			"keyCount":            keyCount,
			"pasteCount":          pasteCount,
			"avgKeyInterval":      interval,
			"keyIntervalVariance": variance,
			"dwellTimes":          dwell,
		},
	}
}

func TestHumanTypingCadenceNotFlagged(t *testing.T) {
	f := typingField(226.9, 4549, []interface{}{82.0, 75.0, 91.0, 68.0}, 43, 0)
	if got := checkTypingCadence(f, map[string]interface{}{}); len(got) != 0 {
		t.Errorf("human typing should not be flagged, got %v", got)
	}
}

func TestScriptedCadenceFlagged(t *testing.T) {
	f := typingField(7.9, 8, []interface{}{7.8, 8.1, 7.4, 8.0}, 43, 0)
	if got := checkTypingCadence(f, map[string]interface{}{}); len(got) != 1 {
		t.Errorf("scripted cadence should be flagged, got %v", got)
	}
}

// The failure mode this check has to avoid. A paste is one or two keydowns
// microseconds apart — arithmetically identical to very fast typing — and humans
// paste constantly.
func TestHumanPasteNeverFlaggedAsMachineTyping(t *testing.T) {
	pasteDwell := []interface{}{2.6, 2.4}

	if got := checkTypingCadence(typingField(0.8, 0, pasteDwell, 2, 0), map[string]interface{}{}); len(got) != 0 {
		t.Errorf("n=2 is not a cadence measurement, got %v", got)
	}
	if got := checkTypingCadence(typingField(0.8, 0, pasteDwell, 43, 0),
		map[string]interface{}{"pasteEvents": 1.0}); len(got) != 0 {
		t.Errorf("page-level paste must exempt, got %v", got)
	}
	if got := checkTypingCadence(typingField(0.8, 0, pasteDwell, 43, 1), map[string]interface{}{}); len(got) != 0 {
		t.Errorf("field-level paste must exempt, got %v", got)
	}
}

func TestFastButVariableTypingNotFlagged(t *testing.T) {
	// Below the interval floor on average, but with a human spread and human
	// holds. Both conditions must fail before we accuse anyone.
	f := typingField(35, 900, []interface{}{60.0, 45.0, 80.0}, 43, 0)
	if got := checkTypingCadence(f, map[string]interface{}{}); len(got) != 0 {
		t.Errorf("a quick typist should not be flagged, got %v", got)
	}
}

func TestPastePlatformContradiction(t *testing.T) {
	mac := map[string]interface{}{"pasteShortcutControl": 1.0, "pasteShortcutMeta": 0.0, "pasteEvents": 1.0}
	if got := checkPastePlatformCoherence(mac, "MacIntel"); len(got) != 1 {
		t.Errorf("Control+V under a Mac claim is a contradiction, got %v", got)
	}

	win := map[string]interface{}{"pasteShortcutMeta": 1.0, "pasteShortcutControl": 0.0, "pasteInputs": 1.0}
	if got := checkPastePlatformCoherence(win, "Win32"); len(got) != 1 {
		t.Errorf("Meta+V under a Windows claim is a contradiction, got %v", got)
	}
}

func TestCoherentPasteShortcutNotFlagged(t *testing.T) {
	ok := map[string]interface{}{"pasteShortcutMeta": 1.0, "pasteEvents": 1.0}
	if got := checkPastePlatformCoherence(ok, "MacIntel"); len(got) != 0 {
		t.Errorf("Meta+V on a Mac is correct, got %v", got)
	}
}

// A Windows switcher on a new Mac really does reach for Ctrl+V. On macOS that
// does nothing, so no paste follows — and without a completed paste there is no
// contradiction to report, only a habit.
func TestWrongShortcutWithoutPasteIsFatFinger(t *testing.T) {
	m := map[string]interface{}{"pasteShortcutControl": 1.0, "pasteEvents": 0.0, "pasteInputs": 0.0}
	if got := checkPastePlatformCoherence(m, "MacIntel"); len(got) != 0 {
		t.Errorf("no completed paste means no contradiction, got %v", got)
	}
}

func TestLinuxClaimsNotJudged(t *testing.T) {
	// Linux pastes with Control+V like Windows, but "Linux" is also what every
	// cloud VM claims, so neither modifier yields a contradiction.
	m := map[string]interface{}{"pasteShortcutControl": 1.0, "pasteEvents": 1.0}
	if got := checkPastePlatformCoherence(m, "Linux x86_64"); len(got) != 0 {
		t.Errorf("Linux should not be judged, got %v", got)
	}
}

func TestProgrammaticFillIsContributoryOnly(t *testing.T) {
	m := map[string]interface{}{"inputsWithoutInputType": 1.0, "inputsWithoutKeys": 1.0}
	got := checkProgrammaticFill(m)
	if len(got) != 1 {
		t.Fatalf("synthetic input should be flagged, got %v", got)
	}
	if got[0].Confidence > 0.5 {
		t.Errorf("must stay contributory — autofill looks like this too, got %v", got[0].Confidence)
	}

	withPaste := map[string]interface{}{"inputsWithoutInputType": 1.0, "inputsWithoutKeys": 1.0, "pasteEvents": 1.0}
	if got := checkProgrammaticFill(withPaste); len(got) != 0 {
		t.Errorf("a paste is not a programmatic fill, got %v", got)
	}
}

func TestScrollMorphology(t *testing.T) {
	human := map[string]interface{}{
		"keyEvents":        0.0,
		"scrollMorphology": map[string]interface{}{"samples": 59.0, "maxStep": 109.0},
	}
	if got := checkScrollMorphology(human); len(got) != 0 {
		t.Errorf("human scrolling should not be flagged, got %v", got)
	}

	jump := map[string]interface{}{
		"keyEvents":        0.0,
		"scrollMorphology": map[string]interface{}{"samples": 3.0, "maxStep": 704.0},
	}
	if got := checkScrollMorphology(jump); len(got) != 1 {
		t.Errorf("a single-event page jump should be flagged, got %v", got)
	}

	// PageDown and End move roughly a viewport in one event. That is a hand.
	kbd := map[string]interface{}{
		"keyEvents":        4.0,
		"scrollMorphology": map[string]interface{}{"samples": 6.0, "maxStep": 900.0},
	}
	if got := checkScrollMorphology(kbd); len(got) != 0 {
		t.Errorf("a keyboard user paging down should not be flagged, got %v", got)
	}
}

func TestFontPlatformCoherence(t *testing.T) {
	winFontsMacClaim := map[string]interface{}{
		"supported": true, "count": 12.0,
		"hasSegoeUI": true, "hasCalibri": true, "hasSFPro": false, "hasMenlo": false,
	}
	if got := checkFontPlatformCoherence(winFontsMacClaim, "MacIntel"); len(got) != 1 {
		t.Errorf("Windows faces under a Mac claim is a contradiction, got %v", got)
	}

	coherent := map[string]interface{}{
		"supported": true, "count": 12.0, "hasSFPro": true, "hasMenlo": true, "hasSegoeUI": false,
	}
	if got := checkFontPlatformCoherence(coherent, "MacIntel"); len(got) != 0 {
		t.Errorf("a coherent font set should not be flagged, got %v", got)
	}
}

// The rule the PRD is emphatic about: score the contradiction, never the
// enumeration. A blocked or minimal font list is a privacy extension or a lean
// Linux box, not an agent.
func TestBlockedFontListNeverFlagged(t *testing.T) {
	for _, fonts := range []map[string]interface{}{
		{"supported": false},
		{"supported": true, "count": 0.0},
		{"supported": true, "count": 2.0, "hasSegoeUI": true},
	} {
		if got := checkFontPlatformCoherence(fonts, "MacIntel"); len(got) != 0 {
			t.Errorf("blocked/minimal enumeration must not be flagged: %v -> %v", fonts, got)
		}
	}
}
