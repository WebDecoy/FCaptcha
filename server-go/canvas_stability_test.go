package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanvasStabilitySharedFixtures(t *testing.T) {
	data, err := os.ReadFile("../test/fixtures/canvas-stability.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Name     string                 `json:"name"`
			Signals  map[string]interface{} `json:"signals"`
			Expected *struct {
				Category   string                 `json:"category"`
				Score      float64                `json:"score"`
				Confidence float64                `json:"confidence"`
				Reason     string                 `json:"reason"`
				Details    map[string]interface{} `json:"details"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}

	for _, fixture := range fixtures.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			got := detectCanvasStability(fixture.Signals)
			if fixture.Expected == nil {
				if len(got) != 0 {
					t.Fatalf("got %+v, want no detection", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d detections, want 1", len(got))
			}
			detection := got[0]
			if string(detection.Category) != fixture.Expected.Category ||
				detection.Score != fixture.Expected.Score ||
				detection.Confidence != fixture.Expected.Confidence ||
				detection.Reason != fixture.Expected.Reason ||
				detection.Details["signal"] != fixture.Expected.Details["signal"] {
				t.Fatalf("got %+v, want %+v", detection, fixture.Expected)
			}
			if detection.Dispositive {
				t.Fatal("privacy-ambiguous evidence must not be dispositive")
			}
		})
	}
}

func TestCanvasInstabilityAloneRemainsAllow(t *testing.T) {
	e := NewScoringEngine("test-secret")
	detections := detectCanvasStability(map[string]interface{}{
		"environmental": map[string]interface{}{
			"canvasHash": map[string]interface{}{"canvasStable": false},
		},
	})
	score := e.calculateFinalScore(e.calculateCategoryScores(detections))
	if score < 0.0112-1e-9 || score > 0.0112+1e-9 {
		t.Fatalf("canvas instability alone scored %.6f, want 0.0112", score)
	}
}
