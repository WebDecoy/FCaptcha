package main

import "testing"

// The keyboard-only accessibility exemption and the key-hold check that keeps a
// keyboard-driven agent from claiming it. See keyboardOnlyUser in scoring.go.

func keyboardSignals(keyEvents float64, extra map[string]interface{}) map[string]interface{} {
	b := map[string]interface{}{"totalPoints": 0.0, "trajectoryLength": 0.0, "keyEvents": keyEvents, "touchEvents": 0.0}
	for k, v := range extra {
		b[k] = v
	}
	return map[string]interface{}{
		"behavioral":    b,
		"environmental": map[string]interface{}{"automationFlags": map[string]interface{}{}},
	}
}

func TestKeyboardExemptionStandsWithoutHoldData(t *testing.T) {
	// An older widget, or a visitor who tabbed to the checkbox and pressed
	// Space without typing into a field, reports counts and nothing else.
	sig := keyboardSignals(8, nil)
	if !keyboardOnlyUser(sig, getMap(sig, "behavioral")) {
		t.Error("counts alone must keep the exemption")
	}
}

func TestKeyboardExemptionStandsForFingers(t *testing.T) {
	sig := keyboardSignals(12, map[string]interface{}{"keyHoldSamples": 6.0, "keyHoldAvg": 85.0})
	if !keyboardOnlyUser(sig, getMap(sig, "behavioral")) {
		t.Error("85ms holds are a hand on a key")
	}
}

func TestKeyboardExemptionDeniedForMechanicalHolds(t *testing.T) {
	sig := keyboardSignals(12, map[string]interface{}{"keyHoldSamples": 6.0, "keyHoldAvg": 4.0})
	if keyboardOnlyUser(sig, getMap(sig, "behavioral")) {
		t.Error("4ms holds are an automation protocol, not a keyboard user")
	}
}

func TestKeyboardExemptionPoolsFormFieldDwell(t *testing.T) {
	// The form analyser's per-field dwell times count too, so a widget that
	// typed into a field is judged even without the session-level summary.
	mechanical := keyboardSignals(9, nil)
	mechanical["formAnalysis"] = map[string]interface{}{"textareaKeyboard": map[string]interface{}{
		"message": map[string]interface{}{"dwellTimes": []interface{}{2.0, 3.0, 1.0, 2.0}},
	}}
	if keyboardOnlyUser(mechanical, getMap(mechanical, "behavioral")) {
		t.Error("mechanical field dwell must deny the exemption")
	}
	human := keyboardSignals(9, nil)
	human["formAnalysis"] = map[string]interface{}{"textareaKeyboard": map[string]interface{}{
		"message": map[string]interface{}{"dwellTimes": []interface{}{60.0, 75.0, 90.0}},
	}}
	if !keyboardOnlyUser(human, getMap(human, "behavioral")) {
		t.Error("human field dwell must keep the exemption")
	}
}

func TestKeyboardExemptionNeedsEnoughHoldsToJudge(t *testing.T) {
	sig := keyboardSignals(4, map[string]interface{}{"keyHoldSamples": 2.0, "keyHoldAvg": 3.0})
	if !keyboardOnlyUser(sig, getMap(sig, "behavioral")) {
		t.Error("two holds are too few to take an exemption away on")
	}
}

func TestKeyboardExemptionRequiresKeysAndNoPointer(t *testing.T) {
	one := keyboardSignals(1, nil)
	if keyboardOnlyUser(one, getMap(one, "behavioral")) {
		t.Error("one key event is not keyboard use")
	}
	moved := keyboardSignals(8, map[string]interface{}{"totalPoints": 3.0})
	if keyboardOnlyUser(moved, getMap(moved, "behavioral")) {
		t.Error("a visitor who moved the pointer is not keyboard-only")
	}
}

// End to end: a keyboard-driven agent is scored as pointerless — both movement
// views fire and corroborate — while a keyboard-only person is not.
func TestKeyboardAgentIsScoredAsPointerless(t *testing.T) {
	e := NewScoringEngine("test-secret")
	agent := keyboardSignals(14, map[string]interface{}{"keyHoldSamples": 14.0, "keyHoldAvg": 2.0})
	dets := append(e.detectVisionAI(agent), e.detectBehavioral(agent)...)
	if !hasReasonContaining(dets, "Zero mouse, touch, or keyboard events") {
		t.Errorf("agent should lose the exemption and score as pointerless, got %+v", dets)
	}
	if !hasReasonContaining(dets, "No mouse movement detected before click") {
		t.Errorf("agent should trip the vision_ai movement check, got %+v", dets)
	}
	if got := applyCorroborationFloor(0.1, dets); got < corroborationFloor {
		t.Errorf("two movement views should corroborate to %v, got %v", corroborationFloor, got)
	}

	person := keyboardSignals(14, map[string]interface{}{"keyHoldSamples": 14.0, "keyHoldAvg": 80.0})
	dets = append(e.detectVisionAI(person), e.detectBehavioral(person)...)
	if hasReasonContaining(dets, "Zero mouse") || hasReasonContaining(dets, "No mouse movement") {
		t.Errorf("a keyboard-only person must keep the exemption, got %+v", dets)
	}
}
