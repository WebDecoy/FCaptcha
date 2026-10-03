// Package fcaptcha verifies FCaptcha tokens from a Go backend.
//
// The FCaptcha widget runs in the visitor's browser and, when the visitor
// passes, puts a signed single-use token in the form field fcaptcha_token. Your
// backend must redeem that token with the FCaptcha server before trusting the
// request; a token that was never redeemed proves nothing.
//
//	client := fcaptcha.New("https://captcha.example.com", os.Getenv("FCAPTCHA_VERIFY_SECRET"))
//	result, err := client.Verify(ctx, r.FormValue("fcaptcha_token"), "")
//	if err != nil {
//		// The FCaptcha server could not be reached or rejected the secret.
//	}
//	if !result.Valid {
//		// Expired, forged, reused or bound to another IP: treat as a bot.
//	}
//
// Middleware wraps the same check around an http.Handler.
//
// This package is a client only. The server lives in server-go in the same
// repository and ships as a container image; see the repository README.
package fcaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TokenField is the form field the widget writes the token into.
const TokenField = "fcaptcha_token"

// ErrUnauthorized is returned when the FCaptcha server rejects the verify
// secret. It is a configuration fault, not a verdict about the visitor, so it
// is an error rather than an invalid Result.
var ErrUnauthorized = errors.New("fcaptcha: verify secret rejected")

// Result is the outcome of redeeming a token.
type Result struct {
	// Valid reports whether the token was genuine, unexpired, unused and,
	// when an IP was supplied, bound to that IP. The server only mints tokens
	// for visitors who passed, so a valid token is a pass.
	Valid bool

	// Reason explains an invalid token: "expired", "invalid_signature",
	// "token_already_used", "ip_mismatch" and so on. Empty when Valid.
	Reason string

	// Score is the bot score the token was minted with, from 0 (human) to 1
	// (bot). Zero when the token carried none.
	Score float64

	SiteKey  string
	Hostname string
	Action   string
	CData    string

	// IssuedAt is when the token was minted. Zero when Valid is false.
	IssuedAt time.Time
}

// Client redeems tokens against one FCaptcha server. It is safe for
// concurrent use.
type Client struct {
	baseURL    string
	secret     string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client used to reach the FCaptcha server. The
// default has a 10 second timeout.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// New returns a Client for the FCaptcha server at baseURL, authenticating with
// secret (the server's FCAPTCHA_VERIFY_SECRET, or FCAPTCHA_SECRET when that is
// unset).
func New(baseURL, secret string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		secret:     secret,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type verifyRequest struct {
	Token    string `json:"token"`
	Secret   string `json:"secret"`
	RemoteIP string `json:"remoteip,omitempty"`
}

type verifyResponse struct {
	Valid     bool     `json:"valid"`
	Reason    string   `json:"reason"`
	Score     *float64 `json:"score"`
	SiteKey   string   `json:"site_key"`
	Hostname  string   `json:"hostname"`
	Action    string   `json:"action"`
	CData     string   `json:"cdata"`
	Timestamp float64  `json:"timestamp"`
}

// Verify redeems token. Tokens are single use: a second Verify of the same
// token reports token_already_used.
//
// remoteIP, when not empty, must be the visitor's address as seen by the
// browser-facing request; the server rejects the token if it was minted for a
// different one. Pass "" to skip the check, which is the safe choice when you
// are not certain you know the real client IP behind your proxies.
//
// An empty token is invalid without a network call. An error means no verdict
// was reached: the server was unreachable, answered something other than the
// verify contract, or rejected the secret (ErrUnauthorized).
func (c *Client) Verify(ctx context.Context, token, remoteIP string) (*Result, error) {
	if token == "" {
		return &Result{Reason: "missing_token"}, nil
	}

	body, err := json.Marshal(verifyRequest{Token: token, Secret: c.secret, RemoteIP: remoteIP})
	if err != nil {
		return nil, fmt.Errorf("fcaptcha: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/token/verify", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("fcaptcha: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fcaptcha: verify: %w", err)
	}
	defer resp.Body.Close()

	// Bounded: the response is a handful of short fields.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("fcaptcha: read response: %w", err)
	}

	var vr verifyResponse
	decodeErr := json.Unmarshal(raw, &vr)

	if resp.StatusCode == http.StatusUnauthorized {
		if decodeErr == nil && vr.Reason != "" {
			return nil, fmt.Errorf("%w (%s)", ErrUnauthorized, vr.Reason)
		}
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fcaptcha: verify: unexpected status %d", resp.StatusCode)
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("fcaptcha: decode response: %w", decodeErr)
	}
	// state_unavailable is the server failing closed on its own store, not a
	// judgement about the token; retrying later can succeed.
	if !vr.Valid && vr.Reason == "state_unavailable" {
		return nil, errors.New("fcaptcha: verify: server state unavailable")
	}

	result := &Result{
		Valid:    vr.Valid,
		Reason:   vr.Reason,
		SiteKey:  vr.SiteKey,
		Hostname: vr.Hostname,
		Action:   vr.Action,
		CData:    vr.CData,
	}
	if vr.Score != nil {
		result.Score = *vr.Score
	}
	if vr.Valid && vr.Timestamp > 0 {
		result.IssuedAt = time.Unix(int64(vr.Timestamp), 0).UTC()
	}
	return result, nil
}
