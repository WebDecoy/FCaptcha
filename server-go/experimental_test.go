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
			if !reflect.DeepEqual(got, f.Expected) {
				t.Fatalf("got %+v, want %+v", got, f.Expected)
			}
			blocked := evaluateExperimental(f.Signals, f.ProductionScore, f.Detections, true)
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

func TestExperimentalBlockingConfig(t *testing.T) {
	for _, flag := range []string{"", "0", "false", "no", "off", "garbage", "1", "true", "yes", "on", " TRUE ",
		"stealth-corroboration-v1", " stealth-corroboration-v1 ", "stealth-corroboration-v0",
		"stealth-corroboration-v2", "STEALTH-CORROBORATION-V1", "*", "stealth-corroboration-v1,other"} {
		t.Run(flag, func(t *testing.T) {
			t.Setenv("FCAPTCHA_EXPERIMENTAL_BLOCKING", flag)
			want := flag == "stealth-corroboration-v1" || flag == " stealth-corroboration-v1 "
			if got := NewScoringEngine("test-secret").experimentalBlocking; got != want {
				t.Fatalf("flag %q: got %v, want %v", flag, got, want)
			}
		})
	}
}
