package main

import "testing"

// Tests for HTTP header analysis.
//
// These cover a false positive the bench human panel surfaced: forwarding
// headers were scored as suspicious unconditionally, so every visitor to every
// deployment behind a reverse proxy carried a permanent bot detection.

func browserHeaders() map[string]string {
	return map[string]string{
		"accept":          "text/html,application/xhtml+xml",
		"accept-language": "en-US,en;q=0.9",
		"accept-encoding": "gzip, deflate, br",
		"user-agent":      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0",
	}
}

func suspiciousHeaderHits(results []DetectionResult) []string {
	var out []string
	for _, d := range results {
		if len(d.Reason) > 26 && d.Reason[:26] == "Suspicious header present:" {
			out = append(out, d.Reason)
		}
	}
	return out
}

func TestForwardingHeadersTrustedPeer(t *testing.T) {
	e := NewScoringEngine("test-secret")
	h := browserHeaders()
	h["x-forwarded-for"] = "203.0.113.9"

	if hits := suspiciousHeaderHits(e.AnalyzeHeaders(h, true)); len(hits) != 0 {
		t.Errorf("a proxy adding XFF is doing its job, got %v", hits)
	}
}

func TestForwardingHeadersUntrustedPeer(t *testing.T) {
	// Nothing legitimate about a direct client claiming to forward for someone.
	e := NewScoringEngine("test-secret")
	h := browserHeaders()
	h["x-forwarded-for"] = "203.0.113.9"

	if hits := suspiciousHeaderHits(e.AnalyzeHeaders(h, false)); len(hits) != 1 {
		t.Errorf("expected 1 suspicious-header detection, got %v", hits)
	}
}

// Cloudflare alone adds three of these. Unconditionally scoring them meant a
// Cloudflare-fronted deployment scored three bot detections on every request.
func TestCDNHeaderSetIsCleanBehindTrustedProxy(t *testing.T) {
	e := NewScoringEngine("test-secret")
	h := browserHeaders()
	h["x-forwarded-for"] = "203.0.113.9"
	h["cf-connecting-ip"] = "203.0.113.9"
	h["true-client-ip"] = "203.0.113.9"
	h["via"] = "1.1 cloudflare"

	if hits := suspiciousHeaderHits(e.AnalyzeHeaders(h, true)); len(hits) != 0 {
		t.Errorf("CDN headers behind a trusted proxy should be clean, got %v", hits)
	}
}

// Set by XHR libraries, not by proxies — trusting the peer says nothing about
// it, so the trust gate must not cover it.
func TestXRequestedWithIgnoresPeerTrust(t *testing.T) {
	e := NewScoringEngine("test-secret")
	for _, trusted := range []bool{true, false} {
		h := browserHeaders()
		h["x-requested-with"] = "XMLHttpRequest"
		if hits := suspiciousHeaderHits(e.AnalyzeHeaders(h, trusted)); len(hits) != 1 {
			t.Errorf("peerTrusted=%v: expected x-requested-with flagged, got %v", trusted, hits)
		}
	}
}

// Corroborating evidence must never weaken a verdict. Before noisy-OR, adding
// automation tells to a WebDriver hit pulled the category average down.
func TestCategoryScoreIsMonotoneInEvidence(t *testing.T) {
	e := NewScoringEngine("test-secret")

	webdriver := DetectionResult{Category: CategoryHeadless, Score: 0.95, Confidence: 0.95}
	corroborating := []DetectionResult{
		{Category: CategoryHeadless, Score: 0.6, Confidence: 0.6},
		{Category: CategoryHeadless, Score: 0.4, Confidence: 0.5},
		{Category: CategoryHeadless, Score: 0.3, Confidence: 0.4},
		{Category: CategoryHeadless, Score: 0.8, Confidence: 0.8},
	}

	prev := e.calculateCategoryScores([]DetectionResult{webdriver})[string(CategoryHeadless)]
	for i := range corroborating {
		set := append([]DetectionResult{webdriver}, corroborating[:i+1]...)
		got := e.calculateCategoryScores(set)[string(CategoryHeadless)]
		if got < prev {
			t.Errorf("adding evidence lowered the category score: %d signals gave %.3f, %d gave %.3f",
				i+1, prev, i+2, got)
		}
		prev = got
	}
}

func TestDispositiveFloor(t *testing.T) {
	plain := []DetectionResult{{Category: CategoryHeadless, Score: 0.4, Confidence: 0.4}}
	if got := applyDispositiveFloor(0.2, plain); got != 0.2 {
		t.Errorf("ordinary evidence must not trigger the floor, got %.3f", got)
	}

	declared := []DetectionResult{{Category: CategoryHeadless, Score: 0.95, Confidence: 0.95, Dispositive: true}}
	if got := applyDispositiveFloor(0.2, declared); got != dispositiveFloor {
		t.Errorf("a self-declared automated browser should be floored at %.2f, got %.3f", dispositiveFloor, got)
	}

	// The floor raises, never lowers.
	if got := applyDispositiveFloor(0.97, declared); got != 0.97 {
		t.Errorf("the floor must not lower an already-higher score, got %.3f", got)
	}
}

// getFloat's zero default conflated "reported 0" with "reported nothing", which
// for a low-means-suspicious signal turned an absent field into an accusation.
func TestGetFloatDefault(t *testing.T) {
	m := map[string]interface{}{"present": 0.0}
	if got := getFloatDefault(m, "present", 0.5); got != 0.0 {
		t.Errorf("an explicit 0 must be preserved, got %v", got)
	}
	if got := getFloatDefault(m, "absent", 0.5); got != 0.5 {
		t.Errorf("an absent key must fall back to the default, got %v", got)
	}
	if got := getFloatDefault(nil, "absent", 0.5); got != 0.5 {
		t.Errorf("a nil map must fall back to the default, got %v", got)
	}
}
