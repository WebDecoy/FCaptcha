package main

import (
	"fmt"
	"testing"
)

// The demonstrated behavior this bounds: 22 requests from one IP escalate PoW
// difficulty with a fixed siteKey but stay pinned when the siteKey varies,
// because each new key allocated a fresh bucket. Past the cap, rotation stops
// buying fresh state.
func TestSiteKeyGuardCapsPerIP(t *testing.T) {
	g := NewSiteKeyGuard(nil, 3)
	const ip = "203.0.113.9"

	for _, k := range []string{"a", "b", "c"} {
		if got := g.Normalize(k, ip); got != k {
			t.Errorf("Normalize(%q) = %q, want the key itself", k, got)
		}
	}
	// Beyond the cap everything collapses into one bucket.
	for _, k := range []string{"d", "e"} {
		if got := g.Normalize(k, ip); got != overflowSiteKey {
			t.Errorf("Normalize(%q) = %q, want overflow", k, got)
		}
	}
	// A key already seen keeps working — a real tenant is not punished.
	if got := g.Normalize("b", ip); got != "b" {
		t.Errorf("known key regressed to %q", got)
	}
	// A different IP has its own budget.
	if got := g.Normalize("z", "198.51.100.4"); got != "z" {
		t.Errorf("second IP got %q, want its own budget", got)
	}
}

func TestSiteKeyGuardRotationCollapses(t *testing.T) {
	g := NewSiteKeyGuard(nil, 4)
	const ip = "203.0.113.10"
	buckets := map[string]struct{}{}
	for i := 0; i < 200; i++ {
		buckets[g.Normalize(fmt.Sprintf("rotate-%d", i), ip)] = struct{}{}
	}
	// 4 real buckets + overflow, not 200.
	if len(buckets) != 5 {
		t.Errorf("got %d distinct buckets, want 5", len(buckets))
	}
	if _, ok := buckets[overflowSiteKey]; !ok {
		t.Error("overflow bucket missing")
	}
}

func TestSiteKeyGuardAllowlistOptIn(t *testing.T) {
	// No allowlist: any key accepted, preserving zero-config self-hosting.
	open := NewSiteKeyGuard(nil, 8)
	if got := open.Normalize("anything", "203.0.113.1"); got != "anything" {
		t.Errorf("open guard rejected %q", got)
	}

	closed := NewSiteKeyGuard([]string{"real-site", " other-site "}, 8)
	if got := closed.Normalize("real-site", "203.0.113.2"); got != "real-site" {
		t.Errorf("allowlisted key got %q", got)
	}
	if got := closed.Normalize("other-site", "203.0.113.2"); got != "other-site" {
		t.Errorf("allowlist entries must be trimmed; got %q", got)
	}
	if got := closed.Normalize("junk", "203.0.113.2"); got != overflowSiteKey {
		t.Errorf("unlisted key got %q, want overflow", got)
	}
}

func TestSiteKeyGuardEdgeCases(t *testing.T) {
	g := NewSiteKeyGuard(nil, 8)
	if got := g.Normalize("", "203.0.113.3"); got != "default" {
		t.Errorf("empty siteKey = %q, want default", got)
	}
	// No IP: nothing to bound against, pass through rather than punish.
	if got := g.Normalize("k", ""); got != "k" {
		t.Errorf("no-IP case = %q, want passthrough", got)
	}
	// The guard's own tracking table must be bounded.
	for i := 0; i < maxTrackedSiteKeyIPs+1000; i++ {
		g.Normalize("site", fmt.Sprintf("198.51.100.%d", i))
	}
	if g.seen.Len() > maxTrackedSiteKeyIPs {
		t.Errorf("tracking table grew to %d, cap is %d", g.seen.Len(), maxTrackedSiteKeyIPs)
	}
}
