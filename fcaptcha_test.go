package fcaptcha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSecret = "verify-secret"

// fakeServer answers /api/token/verify the way server-go does: 401 on a bad
// secret, then a verdict per token from tokens. Each token is single use.
type fakeServer struct {
	mu     sync.Mutex
	tokens map[string]map[string]any
	used   map[string]bool
	last   verifyRequest
}

func newFakeServer(t *testing.T, tokens map[string]map[string]any) (*fakeServer, *httptest.Server) {
	t.Helper()
	f := &fakeServer{tokens: tokens, used: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/token/verify" {
			http.NotFound(w, r)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var req verifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.last = req

		w.Header().Set("Content-Type", "application/json")
		if req.Secret != testSecret {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "reason": "invalid_secret"})
			return
		}
		data, ok := f.tokens[req.Token]
		switch {
		case !ok:
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "reason": "invalid_signature"})
		case f.used[req.Token]:
			json.NewEncoder(w).Encode(map[string]any{"valid": false, "reason": "token_already_used"})
		default:
			f.used[req.Token] = true
			json.NewEncoder(w).Encode(data)
		}
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func validToken(action string, score float64) map[string]any {
	return map[string]any{
		"valid":     true,
		"site_key":  "site-1",
		"timestamp": 1703356800,
		"score":     score,
		"ip_hash":   "abc",
		"hostname":  "example.com",
		"action":    action,
		"cdata":     "order-42",
	}
}

func TestVerifyValidToken(t *testing.T) {
	f, srv := newFakeServer(t, map[string]map[string]any{"tok": validToken("login", 0.15)})
	c := New(srv.URL+"/", testSecret)

	got, err := c.Verify(context.Background(), "tok", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	want := Result{
		Valid:    true,
		Score:    0.15,
		SiteKey:  "site-1",
		Hostname: "example.com",
		Action:   "login",
		CData:    "order-42",
		IssuedAt: time.Unix(1703356800, 0).UTC(),
	}
	if *got != want {
		t.Errorf("Verify = %+v, want %+v", *got, want)
	}
	if f.last.RemoteIP != "203.0.113.10" || f.last.Secret != testSecret {
		t.Errorf("request = %+v", f.last)
	}
}

func TestVerifyIsSingleUse(t *testing.T) {
	_, srv := newFakeServer(t, map[string]map[string]any{"tok": validToken("", 0.1)})
	c := New(srv.URL, testSecret)

	if r, err := c.Verify(context.Background(), "tok", ""); err != nil || !r.Valid {
		t.Fatalf("first Verify = %+v, %v", r, err)
	}
	r, err := c.Verify(context.Background(), "tok", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Valid || r.Reason != "token_already_used" {
		t.Errorf("second Verify = %+v, want token_already_used", r)
	}
	if !r.IssuedAt.IsZero() {
		t.Errorf("IssuedAt = %v on an invalid token", r.IssuedAt)
	}
}

func TestVerifyMissingTokenSkipsNetwork(t *testing.T) {
	c := New("http://127.0.0.1:1", testSecret)
	r, err := c.Verify(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Valid || r.Reason != "missing_token" {
		t.Errorf("Verify(\"\") = %+v", r)
	}
}

func TestVerifyBadSecretIsAnError(t *testing.T) {
	_, srv := newFakeServer(t, nil)
	_, err := New(srv.URL, "wrong").Verify(context.Background(), "tok", "")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if !strings.Contains(err.Error(), "invalid_secret") {
		t.Errorf("err = %v, want the server's reason", err)
	}
}

func TestVerifyServerFaults(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{"401 without body", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}, "secret rejected"},
		{"500", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, "unexpected status 500"},
		{"not JSON", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<html>")
		}, "decode response"},
		{"state unavailable", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"valid":false,"reason":"state_unavailable"}`)
		}, "state unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			r, err := New(srv.URL, testSecret).Verify(context.Background(), "tok", "")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Verify = %+v, %v; want error containing %q", r, err, tt.want)
			}
		})
	}
}

func TestVerifyUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, err := New(url, testSecret).Verify(context.Background(), "tok", ""); err == nil {
		t.Fatal("Verify against a closed server succeeded")
	}
}

func TestVerifyBadBaseURL(t *testing.T) {
	if _, err := New("://bad", testSecret).Verify(context.Background(), "tok", ""); err == nil {
		t.Fatal("Verify with a malformed base URL succeeded")
	}
}

func TestVerifyTokenWithoutScore(t *testing.T) {
	tok := validToken("", 0)
	delete(tok, "score")
	_, srv := newFakeServer(t, map[string]map[string]any{"tok": tok})
	r, err := New(srv.URL, testSecret).Verify(context.Background(), "tok", "")
	if err != nil || !r.Valid || r.Score != 0 {
		t.Fatalf("Verify = %+v, %v", r, err)
	}
}

func TestWithHTTPClient(t *testing.T) {
	_, srv := newFakeServer(t, map[string]map[string]any{"tok": validToken("", 0.1)})
	var used bool
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return http.DefaultTransport.RoundTrip(r)
	})}
	if _, err := New(srv.URL, testSecret, WithHTTPClient(hc)).Verify(context.Background(), "tok", ""); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("custom HTTP client was not used")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
