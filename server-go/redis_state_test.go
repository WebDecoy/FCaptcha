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
