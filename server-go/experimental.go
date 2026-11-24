package main

import (
	"math"
	"os"
	"strings"
)

// Change the ID when evidence, thresholds, or scoring semantics change so an
// existing selector cannot silently opt an operator into a different policy.
const experimentalPolicy = "stealth-corroboration-v1"
const externalCDPInputPolicy = "external-cdp-input-shape-v1"

func experimentalBlockingEnabled() bool {
	return strings.TrimSpace(os.Getenv("FCAPTCHA_EXPERIMENTAL_BLOCKING")) == experimentalPolicy
}

// ExperimentalResult is observed by default; opt-in enforcement can withhold a
// token. It never updates suspicion or rate limits. Its strings are fixed diagnostics,
// safe to include in verdict logs without raw visitor data.
type ExperimentalResult struct {
	Mode                    string                             `json:"mode"`
	Policy                  string                             `json:"policy"`
	Score                   float64                            `json:"score"`
	WouldBlock              bool                               `json:"wouldBlock"`
	Detections              []ExperimentalDetection            `json:"detections"`
	CorroboratingCategories []string                           `json:"corroboratingCategories"`
	Observations            map[string]ExperimentalObservation `json:"observations"`
}

type ExperimentalObservation struct {
	Mode       string                  `json:"mode"`
	Status     string                  `json:"status"`
	Detections []ExperimentalDetection `json:"detections"`
}

func finiteNumber(value interface{}) (float64, bool) {
	var number float64
	switch n := value.(type) {
	case float64:
		number = n
	case float32:
		number = float64(n)
	case int:
		number = float64(n)
	case int64:
		number = float64(n)
	default:
		return 0, false
	}
	return number, !math.IsNaN(number) && !math.IsInf(number, 0)
}

// externalCDPInputObservation observes the complete Browser Harness 0.1.13
// form-input shape. None of its components is safe alone: assistive input,
// dictation, autofill, password managers, keyboard shortcuts, anchor
// navigation, and reduced-motion interfaces can overlap parts of it.
func externalCDPInputObservation(signals map[string]interface{}) ExperimentalObservation {
	result := ExperimentalObservation{Mode: "observe", Status: "unknown", Detections: []ExperimentalDetection{}}
	typing := getMap(getMap(signals, "formAnalysis"), "typing")
	scroll := getMap(getMap(signals, "behavioral"), "scrollMorphology")
	inputEvents, inputEventsOK := finiteNumber(typing["inputEvents"])
	inputsWithoutKeys, inputsWithoutKeysOK := finiteNumber(typing["inputsWithoutKeys"])
	inputsWithoutInputType, inputsWithoutInputTypeOK := finiteNumber(typing["inputsWithoutInputType"])
	selectAllShortcuts, selectAllShortcutsOK := finiteNumber(typing["selectAllShortcuts"])
	pasteEvents, pasteEventsOK := finiteNumber(typing["pasteEvents"])
	pasteInputs, pasteInputsOK := finiteNumber(typing["pasteInputs"])
	gestures, gesturesOK := finiteNumber(scroll["gestures"])
	instantRatio, instantRatioOK := finiteNumber(scroll["instantRatio"])
	if !(inputEventsOK && inputsWithoutKeysOK && inputsWithoutInputTypeOK && selectAllShortcutsOK &&
		pasteEventsOK && pasteInputsOK && gesturesOK && instantRatioOK) {
		return result
	}

	syntheticFill := inputEvents > 0 && inputsWithoutKeys > 0 && inputsWithoutInputType > 0 &&
		pasteEvents == 0 && pasteInputs == 0
	selectAll := selectAllShortcuts > 0
	repeatedInstantScroll := gestures >= 2 && instantRatio > 0.5
	result.Status = "clear"
	if syntheticFill && selectAll && repeatedInstantScroll {
		result.Status = "detected"
		result.Detections = append(result.Detections, ExperimentalDetection{
			ID:     "external-cdp-form-input-shape",
			Reason: "External-CDP form-input shape; observe only because assistive input, autofill, shortcuts, and navigation can overlap",
		})
	}
	return result
}

func animationRealm(value interface{}) (bool, bool) {
	realm, ok := value.(map[string]interface{})
	if !ok || realm["status"] != "ok" {
		return false, false
	}
	specified, ok := realm["specified"].([]interface{})
	if !ok || len(specified) != 3 {
		return false, false
	}
	for _, raw := range specified {
		if n, ok := raw.(float64); !ok || n != 1000 {
			return false, false
		}
	}
	durations, ok := realm["durations"].([]interface{})
	if !ok || len(durations) != 3 {
		return false, false
	}
	match := true
	for i, raw := range durations {
		row, ok := raw.([]interface{})
		if !ok || len(row) != 4 {
			return false, false
		}
		want := float64(0)
		if i == 2 {
			want = 1000
		}
		for _, raw := range row {
			n, ok := raw.(float64)
			if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1e9 {
				return false, false
			}
			match = match && n == want
		}
	}
	return match, true
}

func animationObservation(signals map[string]interface{}) ExperimentalObservation {
	result := ExperimentalObservation{Mode: "observe", Status: "unknown", Detections: []ExperimentalDetection{}}
	probe := getMap(getMap(signals, "environmental"), "animationConsistency")
	if version, ok := probe["version"].(float64); !ok || version != 1 {
		return result
	}
	main, mainOK := animationRealm(probe["main"])
	frame, frameOK := animationRealm(probe["iframe"])
	if !mainOK || !frameOK {
		return result
	}
	result.Status = "clear"
	if main && frame {
		result.Status = "detected"
		result.Detections = append(result.Detections, ExperimentalDetection{
			ID:     "animation-timing-inconsistency",
			Reason: "Browser API timing inconsistency; experimental observation, not proof of automation",
		})
	}
	return result
}

type ExperimentalDetection struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// evaluateExperimental measures a known-ambiguous hypothesis: #87's stealth
// session and a DevTools hardware override can look identical. Never merge its
// evidence into production scoring. Missing/unsupported probes add no evidence.
func evaluateExperimental(signals map[string]interface{}, productionScore float64, detections []DetectionResult, blocking bool) ExperimentalResult {
	result := ExperimentalResult{
		Mode: "observe", Policy: experimentalPolicy, Score: productionScore,
		Detections: []ExperimentalDetection{}, CorroboratingCategories: []string{},
		Observations: map[string]ExperimentalObservation{
			"animation-consistency-v1": animationObservation(signals),
			identityPolicy:             identityObservation(signals),
			externalCDPInputPolicy:     externalCDPInputObservation(signals),
		},
	}
	if blocking {
		result.Mode = "block"
	}
	worker := getMap(getMap(signals, "environmental"), "workerConsistency")
	if worker["supported"] == true && worker["consistent"] == false {
		if mismatches, ok := worker["mismatches"].([]interface{}); ok {
			for _, value := range mismatches {
				if name, ok := value.(string); ok && name == "hardwareConcurrency" {
					result.Detections = append(result.Detections, ExperimentalDetection{
						ID:     "worker-hardware-concurrency-mismatch",
						Reason: "Page and Worker disagree on hardwareConcurrency; also possible with DevTools or privacy tools",
					})
					break
				}
			}
		}
	}
	independent := make([]DetectionResult, 0, len(detections))
	for _, d := range detections {
		if !d.NonCorroborating {
			independent = append(independent, d)
		}
	}
	categoryScores := noisyOrByCategory(independent)
	for _, category := range behaviouralCategories {
		if categoryScores[string(category)] >= corroborationAgreeAt-corroborationEpsilon {
			result.CorroboratingCategories = append(result.CorroboratingCategories, string(category))
		}
	}
	if len(result.Detections) > 0 && len(result.CorroboratingCategories) > 0 {
		result.Score = math.Max(productionScore, corroborationFloor)
	}
	// Score threshold only, not a hypothetical PoW/hostname/rate verdict.
	result.WouldBlock = result.Score >= 0.5
	return result
}
