package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestExperimentalSharedFixtures(t *testing.T) {
	data, err := os.ReadFile("../test/fixtures/experimental-scoring.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Name            string
			Signals         map[string]interface{}
			Detections      []DetectionResult
			ProductionScore float64
			Expected        ExperimentalResult
		}
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures.Cases {
		t.Run(f.Name, func(t *testing.T) {
			before, _ := json.Marshal(f)
			got := evaluateExperimental(f.Signals, f.ProductionScore, f.Detections, false)
			if observation := got.Observations[externalCDPInputPolicy]; observation.Mode != "observe" {
				t.Fatalf("external CDP observation mode = %q, want observe", observation.Mode)
			}
			delete(got.Observations, externalCDPInputPolicy)
			if !reflect.DeepEqual(got, f.Expected) {
				t.Fatalf("got %+v, want %+v", got, f.Expected)
			}
			blocked := evaluateExperimental(f.Signals, f.ProductionScore, f.Detections, true)
			delete(blocked.Observations, externalCDPInputPolicy)
			expectedBlock := f.Expected
			expectedBlock.Mode = "block"
			if !reflect.DeepEqual(blocked, expectedBlock) {
				t.Fatalf("blocking mode got %+v, want %+v", blocked, expectedBlock)
			}
			after, _ := json.Marshal(f)
			if string(before) != string(after) {
				t.Fatal("experimental evaluation mutated production inputs")
			}
		})
	}
}

func externalCDPInputShape() map[string]interface{} {
	return map[string]interface{}{
		"formAnalysis": map[string]interface{}{"typing": map[string]interface{}{
			"inputEvents": 13.0, "inputsWithoutKeys": 1.0, "inputsWithoutInputType": 1.0,
			"selectAllShortcuts": 1.0, "pasteEvents": 0.0, "pasteInputs": 0.0,
		}},
		"behavioral": map[string]interface{}{"scrollMorphology": map[string]interface{}{
			"gestures": 2.0, "instantRatio": 1.0,
		}},
	}
}

func TestExternalCDPInputObservationAccessibilityBoundaries(t *testing.T) {
	shape := externalCDPInputShape()
	got := externalCDPInputObservation(shape)
	if got.Mode != "observe" || got.Status != "detected" || len(got.Detections) != 1 || got.Detections[0].ID != "external-cdp-form-input-shape" {
		t.Fatalf("full shape = %+v, want observe-only detection", got)
	}

	tests := []struct {
		name  string
		field string
		value float64
		part  string
	}{
		{"dictation-autofill-password-manager", "selectAllShortcuts", 0, "typing"},
		{"keyboard-screen-reader-select-all", "inputsWithoutKeys", 0, "typing"},
		{"ordinary-or-assistive-paste", "pasteEvents", 1, "typing"},
		{"anchor-switch-reduced-motion", "gestures", 1, "scroll"},
		{"paired-manual-ceiling", "instantRatio", 0.5, "scroll"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			control := externalCDPInputShape()
			if tc.part == "typing" {
				getMap(getMap(control, "formAnalysis"), "typing")[tc.field] = tc.value
			} else {
				getMap(getMap(control, "behavioral"), "scrollMorphology")[tc.field] = tc.value
			}
			if observation := externalCDPInputObservation(control); observation.Status != "clear" {
				t.Fatalf("observation = %+v, want clear", observation)
			}
		})
	}
	if observation := externalCDPInputObservation(map[string]interface{}{}); observation.Status != "unknown" {
		t.Fatalf("missing telemetry = %+v, want unknown", observation)
	}
	result := evaluateExperimental(shape, 0.1, nil, false)
	if result.Score != 0.1 || result.WouldBlock || len(result.Detections) != 0 {
		t.Fatalf("observation affected enforcement fields: %+v", result)
	}
}

func TestExperimentalBlockingConfig(t *testing.T) {
	for _, flag := range []string{"", "0", "false", "no", "off", "garbage", "1", "true", "yes", "on", " TRUE ",
		"stealth-corroboration-v1", " stealth-corroboration-v1 ", "stealth-corroboration-v0",
		"stealth-corroboration-v2", "animation-consistency-v1", "STEALTH-CORROBORATION-V1", "*", "stealth-corroboration-v1,other"} {
		t.Run(flag, func(t *testing.T) {
			t.Setenv("FCAPTCHA_EXPERIMENTAL_BLOCKING", flag)
			want := flag == "stealth-corroboration-v1" || flag == " stealth-corroboration-v1 "
			if got := NewScoringEngine("test-secret").experimentalBlocking; got != want {
				t.Fatalf("flag %q: got %v, want %v", flag, got, want)
			}
		})
	}
}
