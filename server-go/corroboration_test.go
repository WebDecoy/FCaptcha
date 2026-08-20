package main

import "testing"

// The behavioural corroboration floor. See scoring.go for the measurement that
// chose its constants; these pin the behaviour and the invariants that keep it
// honest.

func TestCorroborationFiresOnTwoAgreeingCategories(t *testing.T) {
	// The shape of the source-patched corpus sample: strong behavioural
	// evidence, a completely clean environment.
	cats := map[string]float64{
		string(CategoryVisionAI):   0.652,
		string(CategoryBehavioral): 0.597,
		string(CategoryAutomation): 0.360,
	}
	base := 0.234 // what the weighted sum produces for exactly this input

	got := applyCorroborationFloor(base, cats)
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
		if got := applyCorroborationFloor(0.2, cats); got != 0.2 {
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
	if got := applyCorroborationFloor(0.3, cats); got != 0.3 {
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
	if got := applyCorroborationFloor(0.95, cats); got != 0.95 {
		t.Errorf("floor lowered a higher score to %v", got)
	}
}

func TestCorroborationRespectsTheAgreementThreshold(t *testing.T) {
	just_under := corroborationAgreeAt - 0.01
	cats := map[string]float64{
		string(CategoryVisionAI):   just_under,
		string(CategoryBehavioral): just_under,
	}
	if got := applyCorroborationFloor(0.2, cats); got != 0.2 {
		t.Errorf("categories below the threshold must not agree, got %v", got)
	}

	cats[string(CategoryVisionAI)] = corroborationAgreeAt
	cats[string(CategoryBehavioral)] = corroborationAgreeAt
	if got := applyCorroborationFloor(0.2, cats); got != corroborationFloor {
		t.Errorf("categories at the threshold should agree, got %v", got)
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
