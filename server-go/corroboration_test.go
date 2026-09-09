package main

import (
	"math"
	"strings"
	"testing"
)

// The behavioural corroboration floor. See scoring.go for the measurement that
// chose its constants; these pin the behaviour and the invariants that keep it
// honest.

// views builds one detection per category at exactly the given strength, so
// each category's noisy-OR score is the number written here.
func views(cats map[string]float64) []DetectionResult {
	out := make([]DetectionResult, 0, len(cats))
	for cat, strength := range cats {
		out = append(out, DetectionResult{Category: ThreatCategory(cat), Score: strength, Confidence: 1})
	}
	return out
}

func TestCorroborationFiresOnTwoAgreeingCategories(t *testing.T) {
	// The shape of the source-patched corpus sample: strong behavioural
	// evidence, a completely clean environment.
	cats := map[string]float64{
		string(CategoryVisionAI):   0.652,
		string(CategoryBehavioral): 0.597,
		string(CategoryAutomation): 0.360,
	}
	base := 0.234 // what the weighted sum produces for exactly this input

	got := applyCorroborationFloor(base, views(cats))
	if got < corroborationFloor {
		t.Errorf("two agreeing categories should floor at %v, got %v", corroborationFloor, got)
	}
	if base >= 0.5 {
		t.Fatal("precondition: this sample must be under the success threshold without the floor")
	}
	if got < 0.5 {
		t.Errorf("the floor must carry it past the success threshold, got %v", got)
	}
}

func TestCorroborationIgnoresASingleStrongCategory(t *testing.T) {
	// One category alone is not corroboration, however strong. This is the
	// guard against the rule becoming "any behavioural detection blocks".
	for _, cat := range behaviouralCategories {
		cats := map[string]float64{string(cat): 1.0}
		if got := applyCorroborationFloor(0.2, views(cats)); got != 0.2 {
			t.Errorf("%s alone at 1.0 must not floor, got %v", cat, got)
		}
	}
}

func TestCorroborationIgnoresNonBehaviouralCategories(t *testing.T) {
	// Environmental categories carry their own weight and have the dispositive
	// floor above them; they must not also trigger this one.
	cats := map[string]float64{
		string(CategoryHeadless):    1.0,
		string(CategoryFingerprint): 1.0,
		string(CategoryDatacenter):  1.0,
		string(CategoryBot):         1.0,
	}
	if got := applyCorroborationFloor(0.3, views(cats)); got != 0.3 {
		t.Errorf("non-behavioural categories must not corroborate, got %v", got)
	}
}

func TestCorroborationNeverLowersAScore(t *testing.T) {
	// A floor raises or does nothing. An agent already above it must not be
	// pulled down to it.
	cats := map[string]float64{
		string(CategoryVisionAI):   0.9,
		string(CategoryBehavioral): 0.9,
	}
	if got := applyCorroborationFloor(0.95, views(cats)); got != 0.95 {
		t.Errorf("floor lowered a higher score to %v", got)
	}
}

func TestCorroborationRespectsTheAgreementThreshold(t *testing.T) {
	justUnder := corroborationAgreeAt - 0.01
	cats := map[string]float64{
		string(CategoryVisionAI):   justUnder,
		string(CategoryBehavioral): justUnder,
	}
	if got := applyCorroborationFloor(0.2, views(cats)); got != 0.2 {
		t.Errorf("categories below the threshold must not agree, got %v", got)
	}

	cats[string(CategoryVisionAI)] = corroborationAgreeAt
	cats[string(CategoryBehavioral)] = corroborationAgreeAt
	if got := applyCorroborationFloor(0.2, views(cats)); got != corroborationFloor {
		t.Errorf("categories at the threshold should agree, got %v", got)
	}
}

// A signal that a developer's own tooling produces cannot be one of the two
// agreeing views, however it scores. The console-attach probe is the case in
// point: DevTools open trips it, so counting it would turn "developer with a
// slightly odd click" into a block.
func TestCorroborationIgnoresNonCorroboratingDetections(t *testing.T) {
	consoleAttached := DetectionResult{Category: CategoryCDP, Score: 0.6, Confidence: 1,
		Reason: "console attached", NonCorroborating: true}
	movement := DetectionResult{Category: CategoryBehavioral, Score: corroborationAgreeAt, Confidence: 1}

	if got := applyCorroborationFloor(0.2, []DetectionResult{consoleAttached, movement}); got != 0.2 {
		t.Errorf("a non-corroborating signal must not be the second view, got %v", got)
	}

	// The same evidence from a signal that is an independent view does floor:
	// the exclusion is about provenance, not strength.
	independent := consoleAttached
	independent.NonCorroborating = false
	if got := applyCorroborationFloor(0.2, []DetectionResult{independent, movement}); got != corroborationFloor {
		t.Errorf("an independent cdp view at %v should floor, got %v", independent.Score, got)
	}
}

// Excluded from agreement, not from the score: the category noisy-OR and the
// weighted sum still see a non-corroborating detection.
func TestNonCorroboratingDetectionsStillScore(t *testing.T) {
	e := NewScoringEngine("test-secret")
	marked := []DetectionResult{{Category: CategoryCDP, Score: 0.6, Confidence: 0.5, NonCorroborating: true}}
	if got := e.calculateCategoryScores(marked)[string(CategoryCDP)]; math.Abs(got-0.3) > 1e-9 {
		t.Errorf("non-corroborating detection should still score its category at 0.3, got %v", got)
	}
}

// The mark has to be on the literal the engine emits, or the exclusion above
// protects nobody.
func TestConsoleAttachedIsNonCorroborating(t *testing.T) {
	e := NewScoringEngine("test-secret")
	got := e.detectCDP(map[string]interface{}{
		"behavioral":    map[string]interface{}{"touchEvents": 0.0},
		"environmental": map[string]interface{}{"cdpRuntime": map[string]interface{}{"consoleAttached": true}},
	})
	found := false
	for _, d := range got {
		if strings.Contains(d.Reason, "console consumer attached") {
			found = true
			if !d.NonCorroborating {
				t.Errorf("console-attach probe must be marked NonCorroborating: %+v", d)
			}
		} else if d.NonCorroborating {
			t.Errorf("only the console-attach probe should carry the mark, got %+v", d)
		}
	}
	if !found {
		t.Fatal("expected the console-attach detection to fire")
	}
}

// Live measurements from the webdecoy.com demo, 2026-09-09, v1.35.0. An
// extension-driven click in a real Chrome: every environmental category clean,
// vision_ai 0.40, behavioral 0.44, cdp 0.30 from the console probe alone,
// weighted sum 0.189, allowed. Two independent views at 0.4 must now floor it.
// Note vision_ai lands at 0.3999999999999999 — the epsilon is not decoration.
func TestCorroborationCatchesTheExtensionDriver(t *testing.T) {
	dets := []DetectionResult{
		{Category: CategoryVisionAI, Score: 0.5, Confidence: 0.5},   // path unnaturally direct
		{Category: CategoryVisionAI, Score: 0.4, Confidence: 0.5},   // click precision
		{Category: CategoryBehavioral, Score: 0.6, Confidence: 0.7}, // insufficient movement
		{Category: CategoryBehavioral, Score: 0.2, Confidence: 0.2}, // no scroll or keyboard
		{Category: CategoryCDP, Score: 0.6, Confidence: 0.5, NonCorroborating: true},
		{Category: CategoryFingerprint, Score: 0.4, Confidence: 0.4},
	}
	if got := applyCorroborationFloor(0.189, dets); got < 0.5 {
		t.Errorf("two independent behavioural views at >=0.4 should floor the extension driver, got %v", got)
	}
}

// The human-looking sessions logged beside it: "first interaction too soon"
// and "no overshoot corrections" (behavioral 0.37) with the console probe
// (cdp 0.30). One view plus a non-corroborating signal is not agreement.
func TestCorroborationSparesADeveloperWithDevToolsOpen(t *testing.T) {
	dets := []DetectionResult{
		{Category: CategoryBehavioral, Score: 0.5, Confidence: 0.5},
		{Category: CategoryBehavioral, Score: 0.4, Confidence: 0.4},
		{Category: CategoryCDP, Score: 0.6, Confidence: 0.5, NonCorroborating: true},
		{Category: CategoryFingerprint, Score: 0.4, Confidence: 0.4},
	}
	if got := applyCorroborationFloor(0.115, dets); got != 0.115 {
		t.Errorf("a developer with DevTools open must not be floored, got %v", got)
	}
}

// The two floors express different claims and must stay distinguishable: 0.9
// means the browser declared its own automation, 0.6 means several independent
// behavioural views agreed. Collapsing them would lose that.
func TestCorroborationFloorSitsBelowTheDispositiveFloor(t *testing.T) {
	if corroborationFloor >= dispositiveFloor {
		t.Errorf("corroborationFloor %v must stay below dispositiveFloor %v",
			corroborationFloor, dispositiveFloor)
	}
}

// The floor is only worth anything if it clears the bar for withholding a token.
func TestCorroborationFloorBlocks(t *testing.T) {
	if corroborationFloor < 0.5 {
		t.Errorf("corroborationFloor %v is below the success threshold; a caught "+
			"agent would still be issued a token", corroborationFloor)
	}
}

// Three never fires on the measured adversary — see the sweep in scoring.go.
// If someone raises this, the rule silently stops working.
func TestCorroborationRequiresTwoNotThree(t *testing.T) {
	if corroborationMinAgree != 2 {
		t.Errorf("corroborationMinAgree is %d; the sweep showed every 3-of-4 "+
			"combination leaves the adversary allowed", corroborationMinAgree)
	}
}
