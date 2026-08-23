package main

import (
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
)

func TestRedisPoWChallengeCrossesInstancesAndIsSingleUse(t *testing.T) {
	redisServer := miniredis.RunT(t)
	redisURL := "redis://" + redisServer.Addr()
	issuer := NewScoringEngineWithRedis("shared-test-secret", redisURL)
	verifier := NewScoringEngineWithRedis("shared-test-secret", redisURL)

	challenge := issuer.GeneratePoWChallenge("site-1", "203.0.113.5", false)
	if challenge == nil {
		t.Fatal("issuer did not persist a challenge")
	}
	solution := solvePoW(t, challenge)

	first := verifier.VerifyPoWSolutionFromIP(solution, "site-1", "203.0.113.8")
	if !first.Valid {
		t.Fatalf("another instance could not verify the challenge: %s", first.Reason)
	}
	second := issuer.VerifyPoWSolutionFromIP(solution, "site-1", "203.0.113.8")
	if second.Valid || second.Reason != "challenge_not_found" {
		t.Fatalf("spent challenge was reusable: valid=%v reason=%q", second.Valid, second.Reason)
	}
}

func TestRedisPoWFailureIsClosed(t *testing.T) {
	redisServer := miniredis.RunT(t)
	engine := NewScoringEngineWithRedis("shared-test-secret", "redis://"+redisServer.Addr())
	redisServer.Close()

	if challenge := engine.GeneratePoWChallenge("site-1", "203.0.113.5", false); challenge != nil {
		t.Fatal("challenge generation must fail closed when shared state is unavailable")
	}
}

func TestRedisTokenReplayProtectionCrossesInstances(t *testing.T) {
	redisServer := miniredis.RunT(t)
	redisURL := "redis://" + redisServer.Addr()
	issuer := NewScoringEngineWithRedis("shared-test-secret", redisURL)
	verifier := NewScoringEngineWithRedis("shared-test-secret", redisURL)
	token := issuer.generateToken("203.0.113.5", "site-1", 0.1, TokenBinding{})

	if valid, _ := verifier.VerifyToken(token)["valid"].(bool); !valid {
		t.Fatal("another instance could not validate the token")
	}
	replayed := issuer.VerifyToken(token)
	if valid, _ := replayed["valid"].(bool); valid || replayed["reason"] != "token_already_used" {
		t.Fatalf("spent token was reusable: %#v", replayed)
	}
}

func TestRedisTokenClaimFailsClosed(t *testing.T) {
	redisServer := miniredis.RunT(t)
	engine := NewScoringEngineWithRedis("shared-test-secret", "redis://"+redisServer.Addr())
	token := engine.generateToken("203.0.113.5", "site-1", 0.1, TokenBinding{})
	redisServer.Close()

	result := engine.VerifyToken(token)
	if valid, _ := result["valid"].(bool); valid || result["reason"] != "state_unavailable" {
		t.Fatalf("verification did not fail closed: %#v", result)
	}
}

func TestRedisIdempotencyResultsCrossInstances(t *testing.T) {
	redisServer := miniredis.RunT(t)
	client := NewScoringEngineWithRedis("shared-test-secret", "redis://"+redisServer.Addr()).redisClient
	first := NewRedisIdempotencyStore(client)
	second := NewRedisIdempotencyStore(client)
	want := siteverifySuccess("2026-08-23T00:00:00.000Z", "example.com", "login", "request-1", 0.1)

	first.Set("retry-key", "token-value", want)
	got, ok := second.Get("retry-key", "token-value")
	if !ok || got["hostname"] != want["hostname"] || got["action"] != want["action"] {
		t.Fatalf("another instance did not read the idempotency result: %#v", got)
	}
}

func TestRedisDetectionStateCrossesInstances(t *testing.T) {
	redisServer := miniredis.RunT(t)
	redisURL := "redis://" + redisServer.Addr()
	first := NewScoringEngineWithRedis("shared-test-secret", redisURL)
	second := NewScoringEngineWithRedis("shared-test-secret", redisURL)

	for i := 0; i < 3; i++ {
		exceeded, _ := first.rateLimiter.Check("site|203.0.113.5", 60, 3)
		if exceeded {
			t.Fatalf("request %d was limited before the configured ceiling", i+1)
		}
	}
	if exceeded, count := second.rateLimiter.Check("site|203.0.113.5", 60, 3); !exceeded || count != 3 {
		t.Fatalf("another instance did not enforce the shared rate limit: exceeded=%v count=%d", exceeded, count)
	}

	first.suspicion.Record("site", "203.0.113.5", 0.95)
	if count := second.suspicion.Count("site", "203.0.113.5"); count != 1 {
		t.Fatalf("another instance saw %d shared suspicion hits, want 1", count)
	}

	first.fingerprintStore.Record("fp-a", "203.0.113.5", "site")
	second.fingerprintStore.Record("fp-b", "203.0.113.5", "site")
	if count := first.fingerprintStore.GetIPFingerprintCount("203.0.113.5"); count != 2 {
		t.Fatalf("shared address fingerprint count=%d, want 2", count)
	}
	second.fingerprintStore.Record("fp-a", "198.51.100.8", "site")
	if count := first.fingerprintStore.GetFingerprintIPCount("fp-a", "site"); count != 2 {
		t.Fatalf("shared fingerprint address count=%d, want 2", count)
	}
}

func TestRedisSiteKeyRotationLimitCrossesInstances(t *testing.T) {
	redisServer := miniredis.RunT(t)
	client := NewScoringEngineWithRedis("shared-test-secret", "redis://"+redisServer.Addr()).redisClient
	first := NewSiteKeyGuard(nil, 2)
	first.redis = client
	second := NewSiteKeyGuard(nil, 2)
	second.redis = client

	if got := first.Normalize("site-a", "203.0.113.5"); got != "site-a" {
		t.Fatalf("first key normalized to %q", got)
	}
	if got := second.Normalize("site-b", "203.0.113.5"); got != "site-b" {
		t.Fatalf("second key normalized to %q", got)
	}
	if got := first.Normalize("site-c", "203.0.113.5"); got != overflowSiteKey {
		t.Fatalf("cross-instance rotation was not folded into overflow: %q", got)
	}
}
