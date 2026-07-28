package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Input forensics v2 — PRD workstream C.
//
// Four checks on *how* input arrived rather than how much of it there was:
// typing cadence, typing modality, the paste-shortcut/platform contradiction,
// and scroll morphology.
//
// # Every threshold here was measured, not assumed
//
// The PRD quotes FP-Agent's observations (Manus 1.39ms inter-key, Browser Use
// 5.31ms, Skyvern 9.52ms) and then warns, correctly, that they are *not*
// constants: the paper found Browser Use programs an 18ms delay yet is observed
// at 5.31ms, because the renderer batches events. The numbers are a function of
// browser version and machine load. Hardcoding them would be copying someone
// else's laboratory conditions.
//
// So the values below come from the bench corpus (bench/README.md), captured on
// real hardware through a real browser:
//
//	signal                 human                     scripted agent
//	---------------------  ------------------------  --------------------
//	inter-key interval     min 114.6ms, med 226.9ms  max 25.9ms, med 7.9ms
//	interval variance      4549                      8
//	key hold (dwell)       min 41.4ms, med 82.0ms    max 25.5ms, med 7.8ms
//	scroll max step        109px                     704px
//
// The distributions do not overlap, so the thresholds sit in the empty space
// between them with a wide margin on both sides rather than hugging either.
//
// # What is deliberately NOT here
//
// Keystroke overlap — the claim that humans press the next key before releasing
// the current one and agents never do. An earlier PRD draft attributed it to
// FP-Agent; the paper does not say it. It defines a keystroke as "a keydown
// event followed by a keyup event" and its only overlap language is about
// modifier keys in shortcuts. The hypothesis may well hold, but it has no source
// and no measurement here, so it earns no weight.
//
// # Weighting
//
// All contributory, not decisive, per §7.4: the coalesced-events signal FCaptcha
// already ships is under active attack from stealth tooling that synthesises it,
// and behavioural signals have a shelf life. The platform contradiction scores
// higher because it is not a threshold at all — it is the client disagreeing
// with itself.
//
// Mirrors server-node/inputforensics.js.

const (
	// 2.9x below the slowest human keystroke observed, 1.5x above the fastest agent one.
	maxMachineInterkeyMS = 40.0
	// Human variance was 4549; the scripted agent's was 8.
	maxMachineIntervalVariance = 200.0
	// Human holds bottomed out at 41ms; the agent never exceeded 25.5ms.
	maxMachineDwellMS = 35.0
	// Enough keystrokes to be a typing sample at all. A paste registers as one
	// or two keydowns, and at n=2 any cadence statistic is noise.
	minKeysForCadence = 10.0
	// Human scrolling never stepped more than 109px between events;
	// scrollIntoView covered 704px in one.
	maxHumanScrollStepPx = 400.0
)

var (
	macPlatforms     = regexp.MustCompile(`(?i)^(mac|iphone|ipad|ipod)`)
	windowsPlatforms = regexp.MustCompile(`(?i)^win`)
)

// checkTypingCadence flags a rhythm no hand produces.
//
// Gated hard, because the failure mode is punishing people who paste. Humans
// paste constantly — password managers, copied addresses, one-time codes — and a
// paste arrives as one or two keydowns microseconds apart, arithmetically
// indistinguishable from very fast typing. The bench's paste-by-human persona is
// exactly that shape: 2 keys, 0.8ms apart, variance 0.
//
// Hence three preconditions before the cadence is looked at: enough keys to be a
// sample, no paste anywhere on the page, and no paste into this field.
func checkTypingCadence(fields map[string]interface{}, typing map[string]interface{}) []DetectionResult {
	if fields == nil {
		return nil
	}
	if getFloat(typing, "pasteEvents") > 0 || getFloat(typing, "pasteInputs") > 0 {
		return nil
	}

	for _, raw := range fields {
		stats, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if getFloat(stats, "pasteCount") > 0 {
			continue
		}
		if getFloat(stats, "keyCount") < minKeysForCadence {
			continue
		}

		interval := getFloatDefault(stats, "avgKeyInterval", 1e9)
		variance := getFloatDefault(stats, "keyIntervalVariance", 1e9)

		dwells := getFloatSlice(stats, "dwellTimes")
		avgDwell := 1e9
		if len(dwells) > 0 {
			sum := 0.0
			for _, d := range dwells {
				sum += d
			}
			avgDwell = sum / float64(len(dwells))
		}

		// Both the rhythm and the hold have to be inhuman. Either alone is a
		// machine that happens to be slow, or a fast typist on a bad keyboard.
		machineRhythm := interval < maxMachineInterkeyMS && variance < maxMachineIntervalVariance
		machineHold := avgDwell < maxMachineDwellMS

		if machineRhythm && machineHold {
			// One detection per request, however many fields were filled.
			return []DetectionResult{{
				Category:   CategoryBehavioral,
				Score:      0.6,
				Confidence: 0.6,
				Reason:     "Typing cadence is mechanical (inter-key and hold both below human range)",
			}}
		}
	}
	return nil
}

// checkPastePlatformCoherence flags a paste shortcut that disagrees with the
// platform the client claims.
//
// macOS pastes with Meta+V; Windows and Linux paste with Control+V. These are
// not conventions a user can be halfway between — the other combination does
// nothing at all on that OS. So a client reporting MacIntel whose visitor pasted
// with Control+V has told us two incompatible things about itself.
//
// Requiring that the paste *landed* is what makes this safe. A Windows switcher
// on a new Mac really does fat-finger Ctrl+V — and on macOS nothing happens, so
// no paste event follows. Only a client whose real platform differs from its
// claimed one gets both the wrong shortcut and a completed paste.
func checkPastePlatformCoherence(typing map[string]interface{}, platform string) []DetectionResult {
	if platform == "" {
		return nil
	}
	if getFloat(typing, "pasteEvents") <= 0 && getFloat(typing, "pasteInputs") <= 0 {
		return nil
	}

	ctrl := getFloat(typing, "pasteShortcutControl")
	meta := getFloat(typing, "pasteShortcutMeta")

	switch {
	case macPlatforms.MatchString(platform) && ctrl > 0 && meta == 0:
		return []DetectionResult{{
			Category:   CategoryAutomation,
			Score:      0.7,
			Confidence: 0.8,
			Reason:     fmt.Sprintf("Paste shortcut contradicts platform (Control+V while claiming %s)", platform),
		}}
	case windowsPlatforms.MatchString(platform) && meta > 0 && ctrl == 0:
		return []DetectionResult{{
			Category:   CategoryAutomation,
			Score:      0.7,
			Confidence: 0.8,
			Reason:     fmt.Sprintf("Paste shortcut contradicts platform (Meta+V while claiming %s)", platform),
		}}
	}
	return nil
}

// checkProgrammaticFill flags text that appeared without being typed or pasted.
//
// A genuine input event carries an inputType describing what the browser did; a
// synthetic one dispatched by script does not. Combined with no keystrokes and
// no paste, that is a value assigned straight into the DOM.
//
// Deliberately low confidence: browser autofill and some password managers also
// produce input events with no keystrokes behind them, and a check that punishes
// password-manager users is worse than no check. It contributes; it never
// decides.
func checkProgrammaticFill(typing map[string]interface{}) []DetectionResult {
	pasted := getFloat(typing, "pasteEvents") > 0 || getFloat(typing, "pasteInputs") > 0
	if getFloat(typing, "inputsWithoutInputType") > 0 && getFloat(typing, "inputsWithoutKeys") > 0 && !pasted {
		return []DetectionResult{{
			Category:   CategoryAutomation,
			Score:      0.5,
			Confidence: 0.4,
			Reason:     "Field populated without keystrokes or paste (synthetic input event)",
		}}
	}
	return nil
}

// checkScrollMorphology flags a page that moved further in one event than a hand
// can move it.
//
// A wheel notch or trackpad flick advances tens of pixels and emits an event
// each time, so covering a long page takes dozens of them. scrollIntoView covers
// the same distance in one, because it is aiming at an element rather than
// turning a wheel. Measured: human scrolling never exceeded 109px between
// consecutive events; the agent's jump was 704px.
//
// Gated on there being no keyboard activity, because PageDown, End and Space are
// legitimate one-event jumps of roughly a viewport. A visitor using the keyboard
// to scroll is doing something a hand does; a DOM agent has no keys.
func checkScrollMorphology(behavioral map[string]interface{}) []DetectionResult {
	m := getMap(behavioral, "scrollMorphology")
	if m == nil {
		return nil
	}
	if getFloat(behavioral, "keyEvents") > 0 {
		return nil
	}
	if getFloat(m, "samples") < 2 {
		return nil
	}
	if getFloat(m, "maxStep") > maxHumanScrollStepPx {
		return []DetectionResult{{
			Category:   CategoryAutomation,
			Score:      0.5,
			Confidence: 0.5,
			Reason:     "Page scrolled by API rather than by gesture (single-event jump)",
		}}
	}
	return nil
}

// checkFontPlatformCoherence flags a font list that contradicts the claimed OS.
//
// Scores the *contradiction*, never the enumeration. A short font list means a
// privacy extension, a minimal Linux install or a locked-down corporate image —
// all ordinary. A list full of Windows-only faces under a macOS claim is not
// ordinary, it is two different machines' worth of evidence in one payload.
func checkFontPlatformCoherence(fonts map[string]interface{}, platform string) []DetectionResult {
	if fonts == nil || platform == "" {
		return nil
	}
	if supported, ok := fonts["supported"].(bool); ok && !supported {
		return nil
	}
	// An empty or near-empty list is a blocked enumeration, not a contradiction.
	if getFloat(fonts, "count") < 3 {
		return nil
	}

	boolOf := func(k string) bool {
		v, _ := fonts[k].(bool)
		return v
	}
	macFonts := boolOf("hasSFPro") || boolOf("hasMenlo")
	winFonts := boolOf("hasSegoeUI") || boolOf("hasCalibri")

	switch {
	case macPlatforms.MatchString(platform) && winFonts && !macFonts:
		return []DetectionResult{{
			Category:   CategoryAutomation,
			Score:      0.5,
			Confidence: 0.5,
			Reason:     fmt.Sprintf("Font set contradicts platform (Windows faces while claiming %s)", platform),
		}}
	case windowsPlatforms.MatchString(platform) && macFonts && !winFonts:
		return []DetectionResult{{
			Category:   CategoryAutomation,
			Score:      0.5,
			Confidence: 0.5,
			Reason:     fmt.Sprintf("Font set contradicts platform (macOS faces while claiming %s)", platform),
		}}
	}
	return nil
}

// detectInputForensics runs every workstream-C check.
func (e *ScoringEngine) detectInputForensics(signals map[string]interface{}) []DetectionResult {
	behavioral := getMap(signals, "behavioral")
	form := getMap(signals, "formAnalysis")
	env := getMap(signals, "environmental")

	typing := getMap(form, "typing")
	if typing == nil {
		typing = map[string]interface{}{}
	}

	platform := strings.TrimSpace(getString(getMap(env, "navigator"), "platform"))

	results := make([]DetectionResult, 0)
	results = append(results, checkTypingCadence(getMap(form, "textareaKeyboard"), typing)...)
	results = append(results, checkPastePlatformCoherence(typing, platform)...)
	results = append(results, checkProgrammaticFill(typing)...)
	results = append(results, checkScrollMorphology(behavioral)...)
	results = append(results, checkFontPlatformCoherence(getMap(env, "fontsInfo"), platform)...)
	return results
}
