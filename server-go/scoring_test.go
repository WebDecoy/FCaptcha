package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	webbotauth "github.com/WebDecoy/web-bot-auth"
	"github.com/WebDecoy/web-bot-auth/httpsig"
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
// the declared_ai category and that ordinary browsers are not. Web Bot Auth
// signature handling moved to CheckWebBotAuth; see TestWebBotAuth* below.
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
}

// TestClassifyWebBotAuth pins the verdict policy that maps a verification
// outcome to detections. Pure mapping — no live directory needed.
func TestClassifyWebBotAuth(t *testing.T) {
	// Verified → declared_ai, verified:true, high confidence.
	verified := classifyWebBotAuth(&webbotauth.Result{
		Status:    webbotauth.StatusVerified,
		Agent:     "https://agent.example",
		KeyID:     "thumb123",
		Algorithm: "ed25519",
	}, "https://agent.example")
	if len(verified) != 1 || verified[0].Category != CategoryDeclaredAI {
		t.Fatalf("verified: expected one declared_ai detection, got %+v", verified)
	}
	if verified[0].Details["verified"] != true {
		t.Errorf("verified: expected verified:true, got %+v", verified[0].Details)
	}

	// Invalid due to a genuine crypto failure → bot, contributory, verified:false.
	forged := classifyWebBotAuth(&webbotauth.Result{
		Status: webbotauth.StatusInvalid,
		Errors: []error{errors.New("sig1: httpsig: ed25519 signature verification failed")},
	}, "https://agent.example")
	if len(forged) != 1 || forged[0].Category != CategoryBot {
		t.Fatalf("forged: expected one bot detection, got %+v", forged)
	}
	if forged[0].Confidence >= 0.9 {
		t.Errorf("forged: expected low (contributory) confidence, got %v", forged[0].Confidence)
	}

	// Invalid due to a directory we could not reach → fail open to presence-only,
	// NOT a bot accusation. This is the false-positive guard.
	failOpen := classifyWebBotAuth(&webbotauth.Result{
		Status: webbotauth.StatusInvalid,
		Errors: []error{errors.New(`sig1: webbotauth: directory "https://agent.example" returned 503`)},
	}, "https://agent.example")
	if len(failOpen) != 1 || failOpen[0].Category != CategoryDeclaredAI {
		t.Fatalf("fail-open: expected one declared_ai detection, got %+v", failOpen)
	}
	if failOpen[0].Details["verified"] != false {
		t.Errorf("fail-open: expected verified:false, got %+v", failOpen[0].Details)
	}

	// No signature → no detection.
	if got := classifyWebBotAuth(&webbotauth.Result{Status: webbotauth.StatusNoSignature}, ""); len(got) != 0 {
		t.Errorf("no-signature: expected no detection, got %+v", got)
	}
}

// TestWebBotAuthForged pins the tight, FP-safe forgery classifier: only a
// cryptographic verification failure counts; fetch/structural failures do not.
func TestWebBotAuthForged(t *testing.T) {
	forged := [][]error{
		{errors.New("sig1: httpsig: ed25519 signature verification failed")},
		{errors.New("sig1: httpsig: rsa-pss signature verification failed: crypto/rsa: verification error")},
	}
	for _, errs := range forged {
		if !webBotAuthForged(errs) {
			t.Errorf("expected forged=true for %v", errs)
		}
	}

	notForged := [][]error{
		nil,
		{errors.New(`sig1: webbotauth: directory "https://a.example" returned 404`)},
		{errors.New("sig1: webbotauth: refusing to dial non-global address 10.0.0.1")},
		{errors.New(`sig1: keyid "abc" not found in directory https://a.example`)},
		{errors.New("sig1: signature expired")},
	}
	for _, errs := range notForged {
		if webBotAuthForged(errs) {
			t.Errorf("expected forged=false for %v", errs)
		}
	}
}

// TestCheckWebBotAuthNilVerifier verifies the fallback: with no verifier wired,
// a signed request degrades to the presence-only detection rather than vanishing.
func TestCheckWebBotAuthNilVerifier(t *testing.T) {
	e := NewScoringEngine("test-secret")
	e.webBotAuth = nil

	req := &httpsig.Request{
		Method:    "POST",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/api/verify",
		Header: http.Header{
			"Signature":       {"sig1=:abc123:"},
			"Signature-Input": {`sig1=("@authority" "signature-agent");keyid="k1";tag="web-bot-auth"`},
			"Signature-Agent": {`"https://agent.example"`},
		},
	}
	got := e.CheckWebBotAuth(context.Background(), req)
	if len(got) != 1 || got[0].Category != CategoryDeclaredAI || got[0].Details["verified"] != false {
		t.Errorf("nil verifier: expected presence-only declared_ai (verified:false), got %+v", got)
	}
	if !strings.Contains(got[0].Reason, "agent.example") {
		t.Errorf("nil verifier: expected agent in reason, got %q", got[0].Reason)
	}
}

// TestCheckWebBotAuthEndToEnd drives a real signature through the actual
// verifier (no mocks), proving the RequestFromHTTP → Verify → classify wiring.
// Uses a pinned static key so no directory fetch is needed — the SSRF-guarded
// dialer would otherwise refuse an httptest loopback address anyway.
func TestCheckWebBotAuthEndToEnd(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := webbotauth.NewSigner(priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	e := NewScoringEngine("test-secret")
	e.webBotAuth = webbotauth.NewVerifier(webbotauth.WithKeys(signer.PublicJWK()))

	// A genuine signed request: sign over Host example.com.
	r, err := http.NewRequest("POST", "https://example.com/api/verify", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Host = "example.com" // RequestFromHTTP reads r.Host; keep it == URL.Host
	if err := signer.SignRequest(r); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	verified := e.CheckWebBotAuth(context.Background(), webbotauth.RequestFromHTTP(r))
	if len(verified) != 1 || verified[0].Category != CategoryDeclaredAI || verified[0].Details["verified"] != true {
		t.Fatalf("expected verified declared_ai (verified:true), got %+v", verified)
	}

	// Same signature, but the authority the client presents no longer matches
	// what was signed → @authority differs → ed25519 verification fails. This is
	// the forgery path: a real crypto failure must score as a bot signal.
	r.Host = "attacker.example"
	forged := e.CheckWebBotAuth(context.Background(), webbotauth.RequestFromHTTP(r))
	if len(forged) != 1 || forged[0].Category != CategoryBot {
		t.Fatalf("expected forged bot detection on authority mismatch, got %+v", forged)
	}
}

// TestVerifyWithHeadersScoresPreDetections guards that caller-supplied
// detections (Web Bot Auth verdicts) participate in scoring rather than being
// cosmetic — the property that makes this feature meaningful. Uses the
// declared_ai category, which no other detector populates here, so the effect
// is unambiguous (calculateCategoryScores is a confidence-weighted average, so
// a detection added to an already-populated category can move it either way).
func TestVerifyWithHeadersScoresPreDetections(t *testing.T) {
	e := NewScoringEngine("test-secret")
	pre := []DetectionResult{webBotAuthVerified("https://agent.example", "thumb", "ed25519")}

	base := e.VerifyWithHeaders(map[string]interface{}{}, "1.2.3.4", "site", "ua", nil, "", nil)
	withPre := e.VerifyWithHeaders(map[string]interface{}{}, "1.2.3.4", "site", "ua", nil, "", pre)

	if base.CategoryScores["declared_ai"] != 0 {
		t.Fatalf("precondition: expected no declared_ai in base, got %v", base.CategoryScores["declared_ai"])
	}
	if withPre.CategoryScores["declared_ai"] <= 0 {
		t.Errorf("expected preDetection to populate the declared_ai category score, got %v", withPre.CategoryScores["declared_ai"])
	}
	if withPre.Score <= base.Score {
		t.Errorf("expected preDetection to raise the final score: base=%v withPre=%v", base.Score, withPre.Score)
	}
	found := false
	for _, d := range withPre.Detections {
		if strings.Contains(d.Reason, "Verified AI agent (Web Bot Auth)") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the preDetection to be reported in Detections")
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

// Web Bot Auth protocol-00 parity with server-node/webbotauth.js.
//
// The Go module (WebDecoy/web-bot-auth v0.2.0) already parses the protocol-00
// Signature-Agent dictionary and honors the `type` parameter, so Go never had
// the parse regression Node did. What Go lacked was the signature-lifetime
// ceiling, which lives here in the scoring layer because it is verdict policy,
// not parsing.
func TestWebBotAuthLifetimeCeiling(t *testing.T) {
	created := time.Now().Add(-time.Minute)

	verifiedWithLifetime := func(d time.Duration) []DetectionResult {
		return classifyWebBotAuth(&webbotauth.Result{
			Status:    webbotauth.StatusVerified,
			Agent:     "https://agent.example",
			KeyID:     "thumb123",
			Algorithm: "ed25519",
			Created:   created,
			Expires:   created.Add(d),
		}, "https://agent.example")
	}

	// A normal short-lived signature still earns the verified verdict.
	if got := verifiedWithLifetime(5 * time.Minute); got[0].Details["verified"] != true {
		t.Errorf("5m signature should verify, got %+v", got[0].Details)
	}

	// Exactly at the ceiling is still acceptable.
	if got := verifiedWithLifetime(maxWebBotAuthLifetime); got[0].Details["verified"] != true {
		t.Errorf("24h signature should verify, got %+v", got[0].Details)
	}

	// Past the ceiling: drops to presence-only. Not forged — an over-long TTL is
	// not proof of spoofing, and the draft says RECOMMENDED, not MUST.
	over := verifiedWithLifetime(maxWebBotAuthLifetime + time.Second)
	if len(over) != 1 {
		t.Fatalf("expected one detection, got %+v", over)
	}
	if over[0].Details["verified"] == true {
		t.Errorf("48h+ signature must not earn verified, got %+v", over[0].Details)
	}
	if over[0].Category != CategoryDeclaredAI {
		t.Errorf("over-long signature should stay declared_ai (presence), got %s", over[0].Category)
	}

	// Zero timestamps (library did not populate them) must not be read as a
	// zero-length lifetime or as an infinite one — leave the verdict alone.
	noTimes := classifyWebBotAuth(&webbotauth.Result{
		Status: webbotauth.StatusVerified, Agent: "https://agent.example",
	}, "https://agent.example")
	if noTimes[0].Details["verified"] != true {
		t.Errorf("absent timestamps should not suppress verification, got %+v", noTimes[0].Details)
	}
}
