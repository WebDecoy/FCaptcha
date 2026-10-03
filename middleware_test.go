package fcaptcha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func okHandler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ResultFromContext(r.Context()); !ok {
			t.Error("accepted request has no Result in its context")
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func formRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(url.Values{TokenField: {token}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestMiddleware(t *testing.T) {
	tokens := map[string]map[string]any{
		"login":  validToken("login", 0.2),
		"signup": validToken("signup", 0.2),
		"risky":  validToken("login", 0.45),
	}

	tests := []struct {
		name string
		opts MiddlewareOptions
		req  *http.Request
		want int
	}{
		{"valid form token", MiddlewareOptions{}, formRequest("login"), http.StatusNoContent},
		{"missing token", MiddlewareOptions{}, formRequest(""), http.StatusForbidden},
		{"forged token", MiddlewareOptions{}, formRequest("forged"), http.StatusForbidden},
		{"action matches", MiddlewareOptions{Action: "login"}, formRequest("login"), http.StatusNoContent},
		{"action mismatch", MiddlewareOptions{Action: "login"}, formRequest("signup"), http.StatusForbidden},
		{"hostname mismatch", MiddlewareOptions{Hostname: "other.example"}, formRequest("login"), http.StatusForbidden},
		{"score over route limit", MiddlewareOptions{MaxScore: 0.3}, formRequest("risky"), http.StatusForbidden},
		{"score under route limit", MiddlewareOptions{MaxScore: 0.5}, formRequest("risky"), http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A fresh server per case: tokens are single use.
			_, srv := newFakeServer(t, tokens)
			h := New(srv.URL, testSecret).Middleware(tt.opts)(okHandler(t))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, tt.req)
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d (%s)", w.Code, tt.want, w.Body.String())
			}
		})
	}
}

func TestMiddlewareHeaderToken(t *testing.T) {
	_, srv := newFakeServer(t, map[string]map[string]any{"tok": validToken("", 0.1)})
	h := New(srv.URL, testSecret).Middleware(MiddlewareOptions{})(okHandler(t))

	r := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-FCaptcha-Token", "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}

func TestMiddlewareRemoteIP(t *testing.T) {
	f, srv := newFakeServer(t, map[string]map[string]any{"tok": validToken("", 0.1)})
	h := New(srv.URL, testSecret).Middleware(MiddlewareOptions{
		RemoteIP: func(r *http.Request) string { return r.Header.Get("X-Real-IP") },
	})(okHandler(t))

	r := formRequest("tok")
	r.Header.Set("X-Real-IP", "198.51.100.7")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if f.last.RemoteIP != "198.51.100.7" {
		t.Errorf("remoteip sent = %q", f.last.RemoteIP)
	}
}

func TestMiddlewareDefaultIsNoIPBinding(t *testing.T) {
	f, srv := newFakeServer(t, map[string]map[string]any{"tok": validToken("", 0.1)})
	New(srv.URL, testSecret).Middleware(MiddlewareOptions{})(okHandler(t)).ServeHTTP(httptest.NewRecorder(), formRequest("tok"))
	if f.last.RemoteIP != "" {
		t.Errorf("remoteip sent = %q without a RemoteIP option", f.last.RemoteIP)
	}
}

func TestMiddlewareFailsClosed(t *testing.T) {
	_, srv := newFakeServer(t, nil)
	h := New(srv.URL, "wrong").Middleware(MiddlewareOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler ran without a verdict")
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, formRequest("tok"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestMiddlewareCustomHandlers(t *testing.T) {
	_, srv := newFakeServer(t, nil)

	var rejected *Result
	h := New(srv.URL, testSecret).Middleware(MiddlewareOptions{
		OnReject: func(w http.ResponseWriter, r *http.Request, res *Result) {
			rejected = res
			w.WriteHeader(http.StatusTeapot)
		},
	})(okHandler(t))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, formRequest("forged"))
	if w.Code != http.StatusTeapot || rejected == nil || rejected.Reason != "invalid_signature" {
		t.Errorf("OnReject: status %d, result %+v", w.Code, rejected)
	}

	var gotErr error
	h = New(srv.URL, "wrong").Middleware(MiddlewareOptions{
		OnError: func(w http.ResponseWriter, r *http.Request, err error) {
			gotErr = err
			w.WriteHeader(http.StatusBadGateway)
		},
	})(okHandler(t))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, formRequest("tok"))
	if w.Code != http.StatusBadGateway || !errors.Is(gotErr, ErrUnauthorized) {
		t.Errorf("OnError: status %d, err %v", w.Code, gotErr)
	}
}

func TestResultFromContextEmpty(t *testing.T) {
	if _, ok := ResultFromContext(context.Background()); ok {
		t.Error("ResultFromContext found a Result in an empty context")
	}
}
