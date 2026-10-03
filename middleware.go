package fcaptcha

import (
	"context"
	"net/http"
)

// MiddlewareOptions tightens what Middleware accepts. The zero value accepts
// any valid token.
type MiddlewareOptions struct {
	// Action, when set, must equal the action the widget was rendered with
	// (data-action). It stops a token earned on one form being spent on
	// another.
	Action string

	// Hostname, when set, must equal the hostname the token was minted for.
	Hostname string

	// MaxScore, when above zero, rejects tokens whose score exceeds it. The
	// server already refuses to mint tokens above its own threshold, so this
	// only matters when a route wants to be stricter than the server.
	MaxScore float64

	// RemoteIP returns the visitor IP to bind the token to. Nil skips the IP
	// check. Only set it when the address is trustworthy: behind a proxy,
	// r.RemoteAddr is the proxy, and binding to it rejects every visitor.
	RemoteIP func(*http.Request) string

	// OnReject handles a request whose token was missing or invalid. The
	// default answers 403. result is never nil.
	OnReject func(w http.ResponseWriter, r *http.Request, result *Result)

	// OnError handles a request for which no verdict was reached, such as an
	// unreachable FCaptcha server. The default answers 503: failing open would
	// let every bot through whenever the server is down.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

type contextKey struct{}

// ResultFromContext returns the Result that Middleware stored for an accepted
// request.
func ResultFromContext(ctx context.Context) (*Result, bool) {
	r, ok := ctx.Value(contextKey{}).(*Result)
	return r, ok
}

// Middleware verifies the token on every request before passing it to next.
// The token is read from the fcaptcha_token form field, or from the
// X-FCaptcha-Token header for requests that are not forms. Wrap only the
// handlers that receive a submission: each token works once.
func (c *Client) Middleware(opts MiddlewareOptions) func(http.Handler) http.Handler {
	onReject := opts.OnReject
	if onReject == nil {
		onReject = func(w http.ResponseWriter, _ *http.Request, _ *Result) {
			http.Error(w, "captcha verification failed", http.StatusForbidden)
		}
	}
	onError := opts.OnError
	if onError == nil {
		onError = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "captcha verification unavailable", http.StatusServiceUnavailable)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-FCaptcha-Token")
			if token == "" {
				token = r.FormValue(TokenField)
			}

			var remoteIP string
			if opts.RemoteIP != nil {
				remoteIP = opts.RemoteIP(r)
			}

			result, err := c.Verify(r.Context(), token, remoteIP)
			if err != nil {
				onError(w, r, err)
				return
			}
			if reason := opts.check(result); reason != "" {
				result.Valid = false
				result.Reason = reason
			}
			if !result.Valid {
				onReject(w, r, result)
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, result)))
		})
	}
}

// check applies the route's own constraints to a token the server accepted.
func (o MiddlewareOptions) check(result *Result) string {
	switch {
	case !result.Valid:
		return result.Reason
	case o.Action != "" && result.Action != o.Action:
		return "action_mismatch"
	case o.Hostname != "" && result.Hostname != o.Hostname:
		return "hostname_mismatch"
	case o.MaxScore > 0 && result.Score > o.MaxScore:
		return "score_too_high"
	}
	return ""
}
