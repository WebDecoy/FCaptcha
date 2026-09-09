package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

func TestHTTPCommitmentFailureConsumesProofAndScoresTampering(t *testing.T) {
	for _, endpoint := range []string{"verify", "score"} {
		for _, tampered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tampered=%t", endpoint, tampered), func(t *testing.T) {
				engine := NewScoringEngine("test-secret")
				challenge := engine.GeneratePoWChallenge("site", "203.0.113.1", false)
				challenge.Difficulty = 1
				challenge.Timestamp = time.Now().UnixMilli() - 2000
				if err := engine.powStore.putChallenge(challenge); err != nil {
					t.Fatal(err)
				}
				signals := map[string]interface{}{
					"behavioral": map[string]interface{}{"totalPoints": 60.0, "trajectoryLength": 400.0,
						"microTremorScore": 0.5, "velocityVariance": 0.5, "approachPoints": 12.0,
						"approachDirectness": 0.4, "explorationRatio": 0.35, "overshootCorrections": 2.0,
						"interactionDuration": 4200.0},
					"meta": map[string]interface{}{"challengeNonce": challenge.Nonce},
				}
				raw, err := json.Marshal(signals)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(raw)
				signalsHash := hex.EncodeToString(digest[:])
				boundChallenge := *challenge
				boundChallenge.Prefix += ":" + signalsHash
				proof := solvePoW(t, &boundChallenge)
				proof.SignalsHash = signalsHash
				if tampered {
					// Equivalent JSON with different bytes must still fail the commitment.
					raw = append(raw, ' ')
				}
				body, err := json.Marshal(map[string]interface{}{
					"siteKey": "site", "signals": signals, "signalsJson": string(raw), "powSolution": proof,
				})
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodPost, "/api/"+endpoint, bytes.NewReader(body))
				req.RemoteAddr = "203.0.113.1:1234"
				for key, value := range map[string]string{"Content-Type": "application/json", "User-Agent": "Mozilla/5.0",
					"Accept": "text/html", "Accept-Language": "en-US", "Accept-Encoding": "gzip", "Connection": "keep-alive"} {
					req.Header.Set(key, value)
				}
				trust, siteKeys, ja4s := NewProxyTrust("none"), NewSiteKeyGuard(nil, 8), newJA4Store(32)
				handler := verifyHandler(engine, trust, siteKeys, ja4s)
				if endpoint == "score" {
					handler = invisibleScoreHandler(engine, trust, siteKeys, ja4s)
				}
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, req)
				var result VerifyResponse
				if recorder.Code != http.StatusOK {
					t.Fatalf("unexpected response: %d %s", recorder.Code, recorder.Body.String())
				}
				if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Success == tampered || (result.Token == "") != tampered {
					t.Fatalf("unexpected verdict: %+v", result)
				}
				if stored, err := engine.powStore.getChallenge(challenge.ID); err != nil || stored != nil {
					t.Fatalf("proof was not consumed: %v %v", stored, err)
				}
				if tampered {
					if result.Reason != "pow_not_satisfied" {
						t.Fatalf("unexpected denial reason: %s", result.Reason)
					}
					if endpoint == "verify" {
						found := false
						for _, detection := range result.Detections {
							if detection.Reason == "No PoW solution provided" {
								t.Fatal("valid proof incorrectly reported missing")
							}
							found = found || detection.Reason == commitmentFailureDetection().Reason
						}
						if !found || result.CategoryScores["bot"] < 0.9025 {
							t.Fatalf("tampering was not scored: %+v", result)
						}
					}
				}
			})
		}
	}
}

func TestIndependentTokenIssuances(t *testing.T) {
	engine := NewScoringEngine("test-secret")
	a := engine.generateToken("ip", "site", 0.1, TokenBinding{})
	b := engine.generateToken("ip", "site", 0.1, TokenBinding{})
	if a == b {
		t.Fatal("independent tokens collide")
	}
	if engine.VerifyToken(a)["valid"] != true || engine.VerifyToken(b)["valid"] != true {
		t.Fatal("independent tokens must both verify")
	}
	if engine.VerifyToken(a)["valid"] != false {
		t.Fatal("spent token replayed")
	}
}

func TestCommitmentDoesNotMergeUncommittedFields(t *testing.T) {
	raw := `{"meta":{"challengeNonce":"binding"}}`
	digest := sha256.Sum256([]byte(raw))
	proof := &PoWSolution{SignalsHash: hex.EncodeToString(digest[:])}
	parsed, valid, err := resolveCommittedSignals(map[string]interface{}{"uncommitted": true}, raw, proof)
	if err != nil || !valid || parsed["uncommitted"] != nil {
		t.Fatalf("bad resolution: %v %v %v", parsed, valid, err)
	}
	_, valid, _ = resolveCommittedSignals(parsed, raw+" ", proof)
	if valid {
		t.Fatal("changed bytes accepted")
	}
	_, valid, _ = resolveCommittedSignals(parsed, "", proof)
	if valid {
		t.Fatal("missing committed bytes accepted")
	}
	proof.SignalsHash = "hash"
	if _, _, err := resolveCommittedSignals(parsed, "null", proof); err == nil {
		t.Fatal("null accepted")
	}
}

func TestChallengeMinimumAgeGatesTokens(t *testing.T) {
	for _, test := range []struct {
		name         string
		age, minimum int64
		success      bool
	}{
		{"valid", 2000, 1500, true}, {"early", 0, 1500, false}, {"elevated", 2000, 60000, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := NewScoringEngine("test-secret")
			challenge := engine.GeneratePoWChallenge("site", "203.0.113.1", false)
			challenge.Difficulty = 1
			challenge.Timestamp = time.Now().UnixMilli() - test.age
			challenge.MinAgeMs = test.minimum
			if err := engine.powStore.putChallenge(challenge); err != nil {
				t.Fatal(err)
			}
			proof := solvePoW(t, challenge)
			signals := map[string]interface{}{
				"behavioral": map[string]interface{}{"totalPoints": 60.0, "trajectoryLength": 400.0,
					"microTremorScore": 0.5, "velocityVariance": 0.5, "approachPoints": 12.0,
					"approachDirectness": 0.4, "explorationRatio": 0.35, "overshootCorrections": 2.0,
					"interactionDuration": 4200.0},
				"meta": map[string]interface{}{"challengeNonce": challenge.Nonce},
			}
			headers := map[string]string{"accept": "text/html", "accept-language": "en-US", "accept-encoding": "gzip", "connection": "keep-alive"}
			result := engine.VerifyWithHeaders(signals, "203.0.113.1", "site", "Mozilla/5.0", headers, "", "", false, nil, TokenBinding{}, proof)
			if result.Success != test.success {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
}

func TestFingerprintBoundsAndRedisExpiry(t *testing.T) {
	redisServer := miniredis.RunT(t)
	shared := NewScoringEngineWithRedis("test-secret", "redis://"+redisServer.Addr()).fingerprintStore
	local := newFingerprintStore()
	local.fingerprints = expirable.NewLRU[string, map[string]bool](32, nil, fingerprintTTL)
	local.ipFingerprints = expirable.NewLRU[string, map[string]bool](32, nil, fingerprintTTL)
	for _, store := range []*FingerprintStore{local, shared} {
		for i := 0; i < 100; i++ {
			store.Record(fmt.Sprint(i), "ip", "site")
		}
		if got := store.GetIPFingerprintCount("ip"); got != 16 {
			t.Fatalf("unbounded cardinality: %d", got)
		}
		for i := 0; i < 100; i++ {
			store.Record("shared", fmt.Sprint(i), "site")
		}
		if got := store.GetFingerprintIPCount("shared", "site"); got != 16 {
			t.Fatalf("unbounded IPs: %d", got)
		}
	}
	if local.fingerprints.Len() > 32 || local.ipFingerprints.Len() > 32 {
		t.Fatal("outer store unbounded")
	}
	redisServer.FastForward(fingerprintTTL - time.Second)
	shared.Record("shared", "new-ip", "site")
	redisServer.FastForward(2 * time.Second)
	if got := shared.GetFingerprintIPCount("shared", "site"); got != 0 {
		t.Fatalf("traffic extended retention: %d", got)
	}
}
