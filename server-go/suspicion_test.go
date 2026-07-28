package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// The property that matters most: a visitor who has done nothing wrong pays
// exactly what everyone paid before adaptive cost existed. If this drifts, the
// feature has started taxing the people it was designed not to touch.
func TestCleanSourcePaysTheBaseline(t *testing.T) {
	cost := ComputeChallengeCost(0, false, 0, false)
	if cost.Difficulty != baseDifficulty || cost.MinAgeMs != baseMinAgeMs {
		t.Errorf("a clean source must pay the baseline, got difficulty %d / minAge %dms (want %d / %dms)",
			cost.Difficulty, cost.MinAgeMs, baseDifficulty, baseMinAgeMs)
	}
}

func TestCostEscalatesWithStrongVerdicts(t *testing.T) {
	cases := []struct {
		hits           int
		wantDifficulty int
		wantMinAge     int64
	}{
		{0, 4, 1500},
		{1, 4, 4000},
		{2, 4, 4000},
		{3, 5, 8000},
		{5, 5, 8000},
		{6, 5, 15000},
		{50, 5, 15000},
	}
	for _, c := range cases {
		got := ComputeChallengeCost(c.hits, false, 0, false)
		if got.Difficulty != c.wantDifficulty || got.MinAgeMs != c.wantMinAge {
			t.Errorf("%d strong verdicts: got difficulty %d / minAge %dms, want %d / %dms",
				c.hits, got.Difficulty, got.MinAgeMs, c.wantDifficulty, c.wantMinAge)
		}
	}
}

// The escalation must stay on the knob an attacker cannot buy their way out of.
// Difficulty 6 costs a native solver about a millisecond and a budget phone
// about sixteen seconds, so reaching it would be a tax on slow devices and
// nothing else.
func TestDifficultyNeverExceedsFive(t *testing.T) {
	for hits := 0; hits < 100; hits++ {
		for _, dc := range []bool{false, true} {
			for _, ex := range []bool{false, true} {
				got := ComputeChallengeCost(hits, dc, 1000, ex)
				if got.Difficulty > 5 {
					t.Fatalf("difficulty reached %d (hits=%d datacenter=%v exceeded=%v); the escalation belongs in MinAgeMs",
						got.Difficulty, hits, dc, ex)
				}
				if got.MinAgeMs > maxMinAgeMs {
					t.Fatalf("minAge reached %dms, above the %dms cap", got.MinAgeMs, maxMinAgeMs)
				}
			}
		}
	}
}

// A datacenter address used to jump straight to difficulty 5, which charges a
// real person on a corporate VPN or iCloud Private Relay several seconds of
// blocked hashing for having a shared IP. It must now move only the time floor.
func TestDatacenterMovesTimeNotDifficulty(t *testing.T) {
	cost := ComputeChallengeCost(0, true, 0, false)
	if cost.Difficulty != baseDifficulty {
		t.Errorf("a datacenter address must not raise difficulty, got %d", cost.Difficulty)
	}
	if cost.MinAgeMs <= baseMinAgeMs {
		t.Errorf("a datacenter address should raise the time floor, got %dms", cost.MinAgeMs)
	}
}

func TestRateSignalsRaiseOnlyTheTimeFloor(t *testing.T) {
	busy := ComputeChallengeCost(0, false, 50, false)
	if busy.Difficulty != baseDifficulty {
		t.Errorf("a high request count must not raise difficulty, got %d", busy.Difficulty)
	}
	if busy.MinAgeMs <= baseMinAgeMs {
		t.Errorf("a high request count should raise the time floor, got %dms", busy.MinAgeMs)
	}

	limited := ComputeChallengeCost(0, false, 50, true)
	if limited.MinAgeMs <= busy.MinAgeMs {
		t.Errorf("an exceeded rate limit should cost more than a merely busy one: %dms vs %dms",
			limited.MinAgeMs, busy.MinAgeMs)
	}
	if limited.Difficulty != baseDifficulty {
		t.Errorf("an exceeded rate limit must not raise difficulty, got %d", limited.Difficulty)
	}
}

// Marginal verdicts are exactly the case where the scoring might be wrong about
// a real person. Recording them would make the next visitor from that address
// wait for a guess.
func TestOnlyStrongVerdictsAreRecorded(t *testing.T) {
	l := NewSuspicionLedger()
	for _, score := range []float64{0.0, 0.3, 0.5, 0.7, 0.79} {
		l.Record("site", "203.0.113.7", score)
	}
	if n := l.Count("site", "203.0.113.7"); n != 0 {
		t.Errorf("scores below %.2f must not accumulate, counted %d", suspicionStrongScore, n)
	}

	l.Record("site", "203.0.113.7", 0.8)
	l.Record("site", "203.0.113.7", 0.95)
	if n := l.Count("site", "203.0.113.7"); n != 2 {
		t.Errorf("expected 2 strong verdicts, counted %d", n)
	}
}

// Suspicion is per site key as well as per address, so one site's abusers do
// not price another site's visitors.
func TestLedgerIsScopedPerSiteAndAddress(t *testing.T) {
	l := NewSuspicionLedger()
	for i := 0; i < 6; i++ {
		l.Record("site-a", "203.0.113.7", 0.95)
	}

	if n := l.Count("site-b", "203.0.113.7"); n != 0 {
		t.Errorf("a different site key must not inherit suspicion, counted %d", n)
	}
	if n := l.Count("site-a", "203.0.113.8"); n != 0 {
		t.Errorf("a different address must not inherit suspicion, counted %d", n)
	}
	if n := l.Count("site-a", "203.0.113.7"); n != 6 {
		t.Errorf("expected 6 for the recorded source, counted %d", n)
	}
}

func TestLedgerIgnoresAnEmptyAddress(t *testing.T) {
	l := NewSuspicionLedger()
	l.Record("site", "", 0.99)
	if n := l.Count("site", ""); n != 0 {
		t.Errorf("an empty address must not accumulate, counted %d", n)
	}
}

// The hit slice is bounded, and the bound must not corrupt the count for the
// tiers that actually exist.
func TestLedgerBoundsRetainedHits(t *testing.T) {
	l := NewSuspicionLedger()
	for i := 0; i < suspicionMaxHits*3; i++ {
		l.Record("site", "203.0.113.7", 0.99)
	}
	n := l.Count("site", "203.0.113.7")
	if n != suspicionMaxHits {
		t.Errorf("expected the count to saturate at %d, got %d", suspicionMaxHits, n)
	}
	if got := ComputeChallengeCost(n, false, 0, false); got.MinAgeMs != maxMinAgeMs {
		t.Errorf("a saturated source should reach the top tier, got %dms", got.MinAgeMs)
	}
}

// A challenge whose minAgeMs could be lowered on the way back to the server
// would let a client price its own delay.
func TestChallengeSignatureCoversMinAge(t *testing.T) {
	e := NewScoringEngine("test-secret")

	clean := e.GeneratePoWChallenge("site", "203.0.113.20", false)
	if clean.MinAgeMs != baseMinAgeMs {
		t.Fatalf("clean source got minAge %dms, want %d", clean.MinAgeMs, baseMinAgeMs)
	}

	for i := 0; i < 6; i++ {
		e.suspicion.Record("site", "203.0.113.21", 0.95)
	}
	suspicious := e.GeneratePoWChallenge("site", "203.0.113.21", false)
	if suspicious.MinAgeMs <= clean.MinAgeMs {
		t.Errorf("a suspicious source should be charged more time: %dms vs %dms",
			suspicious.MinAgeMs, clean.MinAgeMs)
	}

	// Signing the same challenge with the delay talked down must not reproduce
	// the signature it was issued with.
	sign := func(minAge int64) string {
		payload, _ := json.Marshal(map[string]interface{}{
			"id":         suspicious.ID,
			"siteKey":    suspicious.SiteKey,
			"timestamp":  suspicious.Timestamp,
			"expiresAt":  suspicious.ExpiresAt,
			"difficulty": suspicious.Difficulty,
			"prefix":     suspicious.Prefix,
			"minAgeMs":   minAge,
		})
		h := hmac.New(sha256.New, []byte("test-secret"))
		h.Write(payload)
		return hex.EncodeToString(h.Sum(nil))
	}

	if sign(suspicious.MinAgeMs) != suspicious.Sig {
		t.Fatal("the test is not reproducing the server's signing input; fix the test before trusting the assertion below")
	}
	if sign(baseMinAgeMs) == suspicious.Sig {
		t.Error("minAgeMs is not covered by the challenge signature — a client could talk its own delay down")
	}
}

// A challenge issued before adaptive cost existed carries no minAgeMs. It must
// fall back to the baseline rather than to zero, which would disable the timing
// gate entirely for anything still holding an old challenge.
func TestChallengeWithoutMinAgeFallsBackToBaseline(t *testing.T) {
	e := NewScoringEngine("test-secret")
	challenge := e.GeneratePoWChallenge("site", "203.0.113.30", false)

	e.powStore.mu.Lock()
	e.powStore.challenges[challenge.ID].MinAgeMs = 0
	e.powStore.mu.Unlock()

	solution := solvePoW(t, challenge)
	res := e.VerifyPoWSolution(solution, "site")
	if !res.Valid {
		t.Fatalf("solution should verify: %s", res.Reason)
	}
	if res.MinAgeMs != baseMinAgeMs {
		t.Errorf("a challenge without minAge should fall back to %dms, got %dms", baseMinAgeMs, res.MinAgeMs)
	}
}
