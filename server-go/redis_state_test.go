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
