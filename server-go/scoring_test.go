package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// solvePoW brute-forces a nonce whose hash satisfies the challenge difficulty,
// mirroring how VerifyPoWSolution recomputes the hash (prefix:nonce).
func solvePoW(t *testing.T, c *PoWChallenge) *PoWSolution {
	t.Helper()
	target := strings.Repeat("0", c.Difficulty)
	for nonce := 0; nonce < 1<<24; nonce++ {
		sum := sha256.Sum256([]byte(c.Prefix + ":" + formatInt(nonce)))
		h := hex.EncodeToString(sum[:])
		if strings.HasPrefix(h, target) {
			return &PoWSolution{ChallengeID: c.ID, Nonce: nonce, Hash: h}
		}
	}
	t.Fatalf("failed to solve PoW within nonce budget")
	return nil
}

// TestPoWStore_NoMassWipe verifies the regression that motivated this change:
// the old store wiped usedSolutions wholesale once it crossed 10K entries,
// briefly opening a replay window. The LRU-backed version evicts the
// least-recently-used entries instead, so a recent entry is still rejected
// after sustained churn.
func TestPoWStore_NoMassWipe(t *testing.T) {
	s := newPoWChallengeStore()

	// Mark a known-recent solution.
	const recent = "recent:1"
	if !s.MarkSolutionUsed(recent) {
		t.Fatalf("first MarkSolutionUsed should succeed")
	}

	// Push enough churn to trigger the old wipe threshold.
	for i := 0; i < 20_000; i++ {
		s.MarkSolutionUsed(fmt.Sprintf("churn:%d", i))
	}

	// The recent solution must still be considered used. Old code would have
	// returned false here (wiped map -> replay accepted).
	if !s.IsSolutionUsed(recent) {
		t.Fatalf("recent solution wiped after churn — LRU regression")
	}
	if s.MarkSolutionUsed(recent) {
		t.Fatalf("recent solution accepted as new after churn — replay window")
	}
}

// TestPoWStore_LRUEviction verifies that under sustained pressure the cap is
// honored and old entries are evicted (not new ones).
func TestPoWStore_LRUEviction(t *testing.T) {
	// Override the package-level cap with a small one for the test by
	// constructing a store directly.
	s := &PoWChallengeStore{
		challenges:    make(map[string]*PoWChallenge),
		usedSolutions: expirable.NewLRU[string, struct{}](16, nil, time.Hour),
	}

	const oldKey = "old:1"
	if !s.MarkSolutionUsed(oldKey) {
		t.Fatalf("first insert failed")
	}

	for i := 0; i < 100; i++ {
		s.MarkSolutionUsed(fmt.Sprintf("k:%d", i))
	}

	if s.IsSolutionUsed(oldKey) {
		t.Fatalf("oldest entry not evicted under cap pressure")
	}

	// Most recent entry must still be present.
	if !s.IsSolutionUsed("k:99") {
		t.Fatalf("most-recent entry evicted — LRU policy inverted")
	}
}

// TestTokenStore_TTLExpiry verifies that entries naturally expire and free
// their cap slot rather than living forever as the old impl did until the
// inline cleanup happened to fire.
func TestTokenStore_TTLExpiry(t *testing.T) {
	s := &TokenStore{
		cache: expirable.NewLRU[string, struct{}](100, nil, 50*time.Millisecond),
	}

	const sig = "tok:abc"
	if !s.MarkUsed(sig) {
		t.Fatalf("first MarkUsed should succeed")
	}
	if !s.IsUsed(sig) {
		t.Fatalf("token immediately reported as unused")
	}

	time.Sleep(120 * time.Millisecond)

	if s.IsUsed(sig) {
		t.Fatalf("token still reported used after TTL")
	}
	if !s.MarkUsed(sig) {
		t.Fatalf("post-expiry MarkUsed should succeed (slot freed)")
	}
}

// TestTokenStore_ConcurrentMarkUsed exercises the test-and-set under
// contention. Exactly one of N goroutines hammering the same signature must
// see the "newly inserted" return; the rest must see "replay".
func TestTokenStore_ConcurrentMarkUsed(t *testing.T) {
	s := newTokenStore()
	const goroutines = 64
	const sig = "race:tok"

	var wg sync.WaitGroup
	wg.Add(goroutines)

	winners := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if s.MarkUsed(sig) {
				winners <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(winners)

	count := 0
	for range winners {
		count++
	}
	if count != 1 {
		t.Fatalf("MarkUsed not atomic under contention: %d winners (want 1)", count)
	}
}

// TestPoWStore_DeleteChallenge verifies the now-locked DeleteChallenge no
// longer races with cleanup or other writers.
func TestPoWStore_DeleteChallenge(t *testing.T) {
	s := newPoWChallengeStore()
	id := "ch-1"
	s.mu.Lock()
	s.challenges[id] = &PoWChallenge{ID: id, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()}
	s.mu.Unlock()

	s.DeleteChallenge(id)

	s.mu.RLock()
	_, exists := s.challenges[id]
	s.mu.RUnlock()
	if exists {
		t.Fatalf("DeleteChallenge did not remove entry")
	}
}

// TestVerifyPoWSolution_ValidThenReplay drives a genuine, valid solution all the
// way through VerifyPoWSolution. This path holds powStore.mu for its full
// duration and previously called MarkSolutionUsed/DeleteChallenge, which
// re-acquire the same non-reentrant mutex — a self-deadlock that no existing
// test reached. The test runs verification under a deadline so a regression
// fails fast instead of hanging the suite. It also asserts the solution is
// replay-protected and the one-time challenge is consumed.
func TestVerifyPoWSolution_ValidThenReplay(t *testing.T) {
	e := NewScoringEngine("test-secret")
	challenge := e.GeneratePoWChallenge("site-1", "203.0.113.5", false)
	solution := solvePoW(t, challenge)

	type outcome struct {
		first  PoWVerifyResult
		replay PoWVerifyResult
	}
	done := make(chan outcome, 1)
	go func() {
		first := e.VerifyPoWSolution(solution, "site-1")
		replay := e.VerifyPoWSolution(solution, "site-1")
		done <- outcome{first: first, replay: replay}
	}()

	select {
	case res := <-done:
		if !res.first.Valid {
			t.Fatalf("expected first verification to be valid, got reason %q", res.first.Reason)
		}
		// A successful verify consumes the one-time challenge, so a sequential
		// replay is rejected with challenge_not_found (the solution_already_used
		// path only wins a concurrent race before deletion). Either way it must
		// not be accepted again.
		if res.replay.Valid {
			t.Fatalf("expected replay to be rejected, but it was accepted")
		}
		if res.replay.Reason != "challenge_not_found" {
			t.Fatalf("expected replay reason challenge_not_found, got %q", res.replay.Reason)
		}
		// One-time challenge must be consumed after a successful verify.
		e.powStore.mu.RLock()
		_, exists := e.powStore.challenges[challenge.ID]
		e.powStore.mu.RUnlock()
		if exists {
			t.Fatalf("challenge was not deleted after successful verification")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("VerifyPoWSolution deadlocked (re-acquiring powStore.mu while already held)")
	}
}

// TestCheckDeclaredAIAgent verifies self-identifying AI agents are flagged under
// the declared_ai category, that ordinary browsers are not, and that Web Bot Auth
// signed requests are detected.
func TestCheckDeclaredAIAgent(t *testing.T) {
	e := NewScoringEngine("test-secret")

	agentUAs := []string{
		"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot",
		"Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/bot)",
		"ChatGPT-User/1.0; +https://openai.com/bot",
		"CCBot/2.0 (https://commoncrawl.org/faq/)",
	}
	for _, ua := range agentUAs {
		got := e.CheckDeclaredAIAgent(ua, nil)
		if len(got) == 0 || got[0].Category != CategoryDeclaredAI {
			t.Errorf("expected declared_ai detection for UA %q, got %+v", ua, got)
		}
	}

	humanUAs := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile/15E148 Safari/604.1",
	}
	for _, ua := range humanUAs {
		if got := e.CheckDeclaredAIAgent(ua, nil); len(got) != 0 {
			t.Errorf("expected no declared_ai detection for human UA %q, got %+v", ua, got)
		}
	}

	// Web Bot Auth signed request (RFC 9421) on an otherwise-normal UA.
	headers := map[string]string{
		"signature":       "sig1=:abc123:",
		"signature-input": `sig1=("@authority" "signature-agent");keyid="k1";tag="web-bot-auth"`,
		"signature-agent": `"https://agent.example"`,
	}
	got := e.CheckDeclaredAIAgent(humanUAs[0], headers)
	foundWebBotAuth := false
	for _, d := range got {
		if d.Category == CategoryDeclaredAI && strings.Contains(d.Reason, "Web Bot Auth") {
			foundWebBotAuth = true
		}
	}
	if !foundWebBotAuth {
		t.Errorf("expected Web Bot Auth detection from signature headers, got %+v", got)
	}
}

// TestWeightsSumToOne guards the invariant that category weights sum to 1.0 so the
// final score stays normalized when categories are added or rebalanced.
func TestWeightsSumToOne(t *testing.T) {
	e := NewScoringEngine("test-secret")
	var sum float64
	for _, w := range e.weights {
		sum += w
	}
	if diff := sum - 1.0; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("category weights must sum to 1.0, got %.6f", sum)
	}
}

// hasReasonContaining reports whether any detection's Reason contains sub.
func hasReasonContaining(results []DetectionResult, sub string) bool {
	for _, r := range results {
		if strings.Contains(r.Reason, sub) {
			return true
		}
	}
	return false
}

// TestDetectCDP_InputForensics covers the phase-2 synthetic-input signals:
// coalesced-event absence, movement incoherence, and an attached CDP console.
func TestDetectCDP_InputForensics(t *testing.T) {
	e := NewScoringEngine("test-secret")

	// Synthetic: 30 pointermoves that never coalesced + incoherent movement.
	synthetic := map[string]interface{}{
		"behavioral": map[string]interface{}{
			"touchEvents": 0.0,
			"inputForensics": map[string]interface{}{
				"coalescedSamples":     30.0,
				"coalescedMax":         1.0,
				"pointerMoveSamples":   30.0,
				"pointerMoveZeroRatio": 0.95,
			},
		},
		"environmental": map[string]interface{}{
			"cdpRuntime": map[string]interface{}{"consoleAttached": true},
		},
	}
	got := e.detectCDP(synthetic)
	if !hasReasonContaining(got, "never coalesced") {
		t.Errorf("expected coalesced-absence detection, got %+v", got)
	}
	if !hasReasonContaining(got, "incoherent with position") {
		t.Errorf("expected movement-incoherence detection, got %+v", got)
	}
	if !hasReasonContaining(got, "console consumer attached") {
		t.Errorf("expected CDP console detection, got %+v", got)
	}

	// Real mouse: moves coalesced normally, movement coherent, no console.
	human := map[string]interface{}{
		"behavioral": map[string]interface{}{
			"touchEvents": 0.0,
			"inputForensics": map[string]interface{}{
				"coalescedSamples":     40.0,
				"coalescedMax":         6.0,
				"pointerMoveSamples":   40.0,
				"pointerMoveZeroRatio": 0.02,
			},
		},
		"environmental": map[string]interface{}{
			"cdpRuntime": map[string]interface{}{"consoleAttached": false},
		},
	}
	if got := e.detectCDP(human); len(got) != 0 {
		t.Errorf("expected no CDP detections for human-like input, got %+v", got)
	}

	// Touch user must be exempt from the mouse-pointer signals.
	touch := map[string]interface{}{
		"behavioral": map[string]interface{}{
			"touchEvents": 12.0,
			"inputForensics": map[string]interface{}{
				"coalescedSamples": 30.0,
				"coalescedMax":     1.0,
			},
		},
	}
	if got := e.detectCDP(touch); hasReasonContaining(got, "never coalesced") {
		t.Errorf("touch user should be exempt from coalesced check, got %+v", got)
	}
}

// TestDetectVisionAI_InputForensics covers teleport clicks and agent think-time
// cadence, including the touch/keyboard exemptions.
func TestDetectVisionAI_InputForensics(t *testing.T) {
	e := NewScoringEngine("test-secret")

	teleport := map[string]interface{}{
		"behavioral": map[string]interface{}{
			"totalPoints": 40.0, "trajectoryLength": 300.0, "approachPoints": 12.0,
			"microTremorScore": 0.4, "touchEvents": 0.0, "keyEvents": 0.0,
			"inputForensics": map[string]interface{}{"teleportClicks": 2.0},
		},
	}
	if got := e.detectVisionAI(teleport); !hasReasonContaining(got, "teleport clicks") {
		t.Errorf("expected teleport-click detection, got %+v", got)
	}

	cadence := map[string]interface{}{
		"behavioral": map[string]interface{}{
			"totalPoints": 40.0, "trajectoryLength": 300.0, "approachPoints": 12.0,
			"microTremorScore": 0.4, "touchEvents": 0.0, "keyEvents": 0.0,
			"inputForensics": map[string]interface{}{
				"cadenceEvents": 15.0, "cadenceSilentGaps": 4.0,
				"cadenceGapCV": 3.0, "cadenceSilentRatio": 0.72,
			},
		},
	}
	if got := e.detectVisionAI(cadence); !hasReasonContaining(got, "act/think loop") {
		t.Errorf("expected think-time cadence detection, got %+v", got)
	}

	// Human: one teleport-free click, continuous cadence — neither should fire.
	human := map[string]interface{}{
		"behavioral": map[string]interface{}{
			"totalPoints": 40.0, "trajectoryLength": 300.0, "approachPoints": 12.0,
			"microTremorScore": 0.4, "touchEvents": 0.0, "keyEvents": 0.0,
			"inputForensics": map[string]interface{}{
				"teleportClicks": 0.0, "cadenceEvents": 30.0, "cadenceSilentGaps": 1.0,
				"cadenceGapCV": 1.2, "cadenceSilentRatio": 0.1,
			},
		},
	}
	got := e.detectVisionAI(human)
	if hasReasonContaining(got, "teleport clicks") || hasReasonContaining(got, "act/think loop") {
		t.Errorf("human-like input should not trip input-forensics signals, got %+v", got)
	}
}

// TestAnalyzeFormInteraction_ProgrammaticFill covers the fill()-style insertion
// signal: content with zero keystrokes and zero pastes.
func TestAnalyzeFormInteraction_ProgrammaticFill(t *testing.T) {
	e := NewScoringEngine("test-secret")

	filled := map[string]interface{}{
		"textareaKeyboard": map[string]interface{}{
			"comment": map[string]interface{}{
				"contentLength": 50.0, "keyCount": 0.0, "pasteCount": 0.0,
			},
		},
	}
	if got := e.AnalyzeFormInteraction(filled); !hasReasonContaining(got, "filled programmatically") {
		t.Errorf("expected programmatic-fill detection, got %+v", got)
	}

	// Genuinely typed content must not trip it.
	typed := map[string]interface{}{
		"textareaKeyboard": map[string]interface{}{
			"comment": map[string]interface{}{
				"contentLength": 50.0, "keyCount": 48.0, "pasteCount": 0.0,
				"avgKeyInterval": 180.0, "keyIntervalVariance": 4000.0, "keydownUpRatio": 1.0,
			},
		},
	}
	if got := e.AnalyzeFormInteraction(typed); hasReasonContaining(got, "filled programmatically") {
		t.Errorf("typed content should not trip programmatic-fill, got %+v", got)
	}
}
