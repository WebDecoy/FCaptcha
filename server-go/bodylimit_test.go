package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestBodyLimit(t *testing.T) {
	called := false
	h := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	tooLarge := strings.NewReader(strings.Repeat("x", int(maxRequestBodyBytes)+1))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/verify", tooLarge))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: got status %d, want 413", w.Code)
	}
	if called {
		t.Fatal("oversized body reached the application handler")
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/verify", strings.NewReader("{}")))
	if w.Code != http.StatusNoContent || !called {
		t.Fatalf("small body did not reach handler: status=%d called=%v", w.Code, called)
	}
}
