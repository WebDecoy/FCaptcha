package main

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestIdentitySharedFixtures(t *testing.T) {
	data, err := os.ReadFile("../test/fixtures/identity-coherence.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Name     string
			JA4      string
			Signals  map[string]interface{}
			Expected ExperimentalObservation
		}
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures.Cases {
		t.Run(f.Name, func(t *testing.T) {
			if got := identityObservation(f.Signals, f.JA4); !reflect.DeepEqual(got, f.Expected) {
				t.Fatalf("got %+v, want %+v", got, f.Expected)
			}
			if got := evaluateExperimental(f.Signals, 0.1, nil, true, f.JA4).Observations[identityPolicy]; !reflect.DeepEqual(got, f.Expected) {
				t.Fatalf("experimental wiring got %+v, want %+v", got, f.Expected)
			}
		})
	}
}

func TestIdentityJA4HeaderRequiresTrustedPeer(t *testing.T) {
	t.Setenv("TRUSTED_JA4_HEADERS", "x-test-ja4")
	const firefoxJA4 = "t13d1715h2_5b57614c22b0_7121afd63204"
	signals := map[string]interface{}{
		"environmental": map[string]interface{}{
			"navigator": map[string]interface{}{
				"userAgent":      "Mozilla/5.0 AppleWebKit/537.36 Chrome/156.0.0.0 Safari/537.36",
				"maxTouchPoints": float64(0),
			},
		},
	}
	headers := map[string]string{"x-test-ja4": firefoxJA4}
	engine := NewScoringEngine("identity-ja4-test-secret")

	observation := func(native string, peerTrusted bool) ExperimentalObservation {
		result := engine.VerifyWithHeaders(
			signals, "203.0.113.1", "identity-ja4", "", headers, "", native,
			peerTrusted, nil, TokenBinding{})
		return result.Experimental.Observations[identityPolicy]
	}

	if got := observation("", false); got.Status != "unknown" || len(got.Detections) != 0 {
		t.Fatalf("untrusted client-supplied JA4 was observed: %+v", got)
	}
	if got := observation("", true); got.Status != "detected" || len(got.Detections) != 1 || got.Detections[0].ID != "tls-family-mismatch" {
		t.Fatalf("trusted proxy JA4 was not observed: %+v", got)
	}
	if got := observation(firefoxJA4, false); got.Status != "detected" || len(got.Detections) != 1 || got.Detections[0].ID != "tls-family-mismatch" {
		t.Fatalf("native JA4 should not depend on proxy trust: %+v", got)
	}
}
