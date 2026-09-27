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
			Signals  map[string]interface{}
			Expected ExperimentalObservation
		}
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures.Cases {
		t.Run(f.Name, func(t *testing.T) {
			if got := identityObservation(f.Signals); !reflect.DeepEqual(got, f.Expected) {
				t.Fatalf("got %+v, want %+v", got, f.Expected)
			}
			if got := evaluateExperimental(f.Signals, 0.1, nil, true).Observations[identityPolicy]; got.Mode != "observe" {
				t.Fatalf("identity observation must stay observe-only under a blocking policy, got %q", got.Mode)
			}
		})
	}
}
