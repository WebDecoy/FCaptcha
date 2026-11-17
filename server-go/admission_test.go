package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
)

func TestChallengeProtocolNegotiationAndCaching(t *testing.T) {
	handler := powChallengeHandler(NewScoringEngine("test"), NewProxyTrust("none"), NewSiteKeyGuard(nil, 8))

	for _, rawURL := range []string{
		"/api/pow/challenge?siteKey=protocol-test",
		"/api/pow/challenge?siteKey=protocol-test&protocolVersions=2,1",
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, rawURL, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", rawURL, w.Code)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s: Cache-Control = %q, want no-store", rawURL, got)
		}
		var response PoWChallengeResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.ProtocolVersion != 1 {
			t.Fatalf("%s: protocol version %d, want 1", rawURL, response.ProtocolVersion)
		}
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/api/pow/challenge?siteKey=protocol-test&protocolVersions=2", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsupported protocol status %d, want 400", w.Code)
	}
}

func TestAdmissionAndRedisQuotaAreAtomic(t *testing.T) {
	redisServer := miniredis.RunT(t)
	engine := NewScoringEngineWithRedis("test", "redis://"+redisServer.Addr())
	a, b := newAdmissionLimiter(engine.redisClient), newAdmissionLimiter(engine.redisClient)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			limiter := a
			if i%2 == 0 {
				limiter = b
			}
			ok, err := limiter.Allow("same-source", 10, 60)
			if err != nil {
				t.Error(err)
			}
			if ok {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 10 {
		t.Fatalf("accepted %d, want 10", accepted.Load())
	}
	redisServer.FastForward(61 * time.Second)
	if ok, err := a.Allow("same-source", 10, 60); err != nil || !ok {
		t.Fatalf("quota did not expire: %v", err)
	}
}

func TestChallengeQuotaSurvivesSiteKeyRotation(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(fmt.Sprint(shared), func(t *testing.T) {
			engine := NewScoringEngine("test")
			if shared {
				r := miniredis.RunT(t)
				engine = NewScoringEngineWithRedis("test", "redis://"+r.Addr())
			}
			first := engine.GeneratePoWChallenge("first", "192.0.2.50", false)
			for i := 0; i < 127; i++ {
				if engine.GeneratePoWChallenge(fmt.Sprint(i), "192.0.2.50", false) == nil {
					t.Fatal("quota refused too early")
				}
			}
			if engine.GeneratePoWChallenge("rotated", "192.0.2.50", false) != nil {
				t.Fatal("quota bypassed")
			}
			if retained, err := engine.powStore.getChallenge(first.ID); err != nil || retained == nil {
				t.Fatal("live challenge was evicted")
			}
		})
	}
}

func TestTokenCapacityNeverReopensReplay(t *testing.T) {
	store := newTokenStore()
	for i := 0; i < usedTokensCap; i++ {
		if !store.MarkUsed(fmt.Sprint(i)) {
			t.Fatal("unexpected full store")
		}
	}
	if ok, err := store.Claim("overflow"); ok || err == nil {
		t.Fatal("full store must fail closed")
	}
	if store.MarkUsed("0") {
		t.Fatal("old spent token replayed")
	}
}

func TestBoundedDirectoryVerifierRefusesMultipleAgents(t *testing.T) {
	for _, header := range []string{`"https://one.example", "https://two.example"`, `a="https://one.example", b="https://two.example"`} {
		if singleAgent(header) {
			t.Fatal("multiple directories accepted")
		}
	}
	if !singleAgent(`a="https://one.example/keys";type="jwks_uri"`) {
		t.Fatal("single typed directory refused")
	}
}

func TestIPBindingCanonicalAndKeyed(t *testing.T) {
	e := NewScoringEngine("first")
	if e.ipBinding("::ffff:192.0.2.1") != e.ipBinding("192.0.2.1") {
		t.Fatal("mapped IPv4 mismatch")
	}
	if e.ipBinding("2001:0db8:0:0::1") != e.ipBinding("2001:db8::1") {
		t.Fatal("IPv6 mismatch")
	}
	if len(e.ipBinding("192.0.2.1")) != 64 {
		t.Fatal("truncated binding")
	}
	if e.ipBinding("192.0.2.1") == NewScoringEngine("second").ipBinding("192.0.2.1") {
		t.Fatal("unkeyed binding")
	}
}

type directoryRoundTripFunc func(*http.Request) (*http.Response, error)

func (f directoryRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDirectoryBodyLimitAndPrivateAddressGuard(t *testing.T) {
	transport := directoryTransport{base: directoryRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 256*1024+1)))}, nil
	})}
	request, _ := http.NewRequest("GET", "https://agent.example", nil)
	if response, err := transport.RoundTrip(request); err == nil || response != nil {
		t.Fatal("oversized response was accepted")
	}
	client := newBoundedBotAuth().client
	for _, address := range []string{"127.0.0.1", "100.100.100.200", "0.0.0.1"} {
		if _, err := client.Get("https://" + address + "/keys"); err == nil || !strings.Contains(err.Error(), "non-public") {
			t.Fatalf("private address was not guarded: %v", err)
		}
	}
}
