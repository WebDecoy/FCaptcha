package main

import "testing"

// The per-device verification rate gate. A precondition on token issuance, not
// weighted evidence: see deviceVerificationsPerMinute in scoring.go.

func deviceSignals(instance string) map[string]interface{} {
	sig := map[string]interface{}{
		"behavioral": map[string]interface{}{
			"totalPoints": 60.0, "trajectoryLength": 400.0, "approachPoints": 12.0,
			"approachDirectness": 0.4, "microTremorScore": 0.5, "velocityVariance": 0.5,
		},
		"environmental": map[string]interface{}{"automationFlags": map[string]interface{}{}},
	}
	if instance != "" {
		sig["meta"] = map[string]interface{}{"sessionId": instance}
	}
	return sig
}

func TestDeviceRateGateWithholdsTheEleventhVerification(t *testing.T) {
	e := NewScoringEngine("test-secret")
	const ip = "203.0.113.77"
	for i := 0; i < deviceVerificationsPerMinute; i++ {
		r := e.VerifyWithHeaders(deviceSignals("page-a"), ip, "site", "ua", nil, "", "", false, nil, TokenBinding{})
		if r.Reason == "rate_limited" {
			t.Fatalf("verification %d of %d was rate limited early", i+1, deviceVerificationsPerMinute)
		}
	}
	r := e.VerifyWithHeaders(deviceSignals("page-a"), ip, "site", "ua", nil, "", "", false, nil, TokenBinding{})
	if r.Success || r.Reason != "rate_limited" {
		t.Errorf("verification %d should be withheld as rate_limited, got success=%v reason=%q",
			deviceVerificationsPerMinute+1, r.Success, r.Reason)
	}
	if !hasReasonContaining(r.Detections, "for this device") {
		t.Errorf("expected the per-device rate detection to be recorded, got %+v", r.Detections)
	}

	// Another page instance on the same address and device has its own budget:
	// identical machines behind one NAT must not share one.
	other := e.VerifyWithHeaders(deviceSignals("page-b"), ip, "site", "ua", nil, "", "", false, nil, TokenBinding{})
	if other.Reason == "rate_limited" {
		t.Errorf("a different widget instance must not inherit the exhausted budget")
	}
}

func TestDeviceRateGateNeedsAWidgetInstance(t *testing.T) {
	// A client that reports no instance id — an older widget — is not gated,
	// because the alternative key (address + fingerprint) is shared by every
	// identical machine behind one address.
	e := NewScoringEngine("test-secret")
	for i := 0; i <= deviceVerificationsPerMinute+2; i++ {
		r := e.VerifyWithHeaders(deviceSignals(""), "203.0.113.78", "site", "ua", nil, "", "", false, nil, TokenBinding{})
		if r.Reason == "rate_limited" {
			t.Fatalf("no instance id must mean no device gate, got rate_limited on call %d", i+1)
		}
	}
}

func TestWidgetInstanceIsBounded(t *testing.T) {
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	sig := map[string]interface{}{"meta": map[string]interface{}{"widgetId": string(long)}}
	if got := widgetInstance(sig); len(got) != 64 {
		t.Errorf("client-supplied id must be bounded before it becomes a key, got length %d", len(got))
	}
	if widgetInstance(map[string]interface{}{}) != "" {
		t.Error("no meta means no instance")
	}
}
