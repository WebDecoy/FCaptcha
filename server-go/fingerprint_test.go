package main

import "testing"

func hasDetectionReason(results []DetectionResult, reason string) bool {
	for _, result := range results {
		if result.Reason == reason {
			return true
		}
	}
	return false
}

func canvasSignals(hash string, supported, failed bool) map[string]interface{} {
	return map[string]interface{}{
		"environmental": map[string]interface{}{
			"canvasHash": map[string]interface{}{
				"hash":      hash,
				"supported": supported,
				"error":     failed,
			},
		},
	}
}

func TestCanvasFingerprintObjectIsParsedLikeOtherServers(t *testing.T) {
	engine := NewScoringEngine("test-secret")
	const blocked = "Canvas fingerprinting blocked or failed"

	valid := engine.detectFingerprint(canvasSignals("abc123", true, false), "192.0.2.1", "site")
	if hasDetectionReason(valid, blocked) {
		t.Fatalf("supported canvas object was treated as blocked")
	}

	failed := engine.detectFingerprint(canvasSignals("", false, true), "192.0.2.2", "site")
	if !hasDetectionReason(failed, blocked) {
		t.Fatalf("failed canvas object was not detected")
	}
}

func TestDeviceFingerprintIncludesNestedCanvasHash(t *testing.T) {
	first := deviceFingerprint(canvasSignals("canvas-a", true, false))
	second := deviceFingerprint(canvasSignals("canvas-b", true, false))
	if first == second {
		t.Fatalf("different nested canvas hashes produced the same device fingerprint")
	}
	if first != deviceFingerprint(canvasSignals("canvas-a", true, false)) {
		t.Fatalf("device fingerprint is not stable for the same canvas hash")
	}
}
