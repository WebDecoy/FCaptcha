package main

// Drop-in compatibility with the Turnstile / reCAPTCHA / hCaptcha siteverify
// contract.
//
// Every one of those services validates a token the same way: a server-to-server
// POST carrying `secret` and `response`, answered with a small JSON object whose
// shape has been stable for a decade. Every backend SDK, CMS plugin and Stack
// Overflow snippet in circulation speaks it:
//
//	POST /turnstile/v0/siteverify        (form-encoded or JSON)
//	  secret, response, remoteip, idempotency_key
//	-> {success, challenge_ts, hostname, action, cdata, error-codes}
//
// FCaptcha's native endpoint (POST /api/token/verify -> {valid, score, ...}) is
// a different shape, which means none of that existing integration work applies.
// Serving the familiar contract alongside the native one turns a migration into
// a base-URL change, so this file is deliberately an *adapter* over
// VerifyTokenWithIP rather than a second verification path — there is one
// implementation of token validity and this translates its vocabulary.
//
// Three things the native endpoint did not do, which the contract requires:
//
//   - `secret` is checked. All three servers previously accepted the parameter
//     and ignored it, so anyone who could reach the endpoint could verify
//     tokens. The README documented sending it, which made the omission worse:
//     integrators believed they were authenticated.
//   - `hostname` is reported, so the caller can confirm the token was minted on
//     a page they actually serve. This is what stops a lifted site key from
//     being used against someone else's deployment.
//   - `idempotency_key` makes retries safe. Tokens are single-use, so a network
//     timeout on the first validation would otherwise burn the token and fail
//     the user's request on the retry.
//
// Mirrors server-node/siteverify.js and server-python/siteverify.py.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/redis/go-redis/v9"
)

const (
	// How long a validation result stays replayable under its idempotency key.
	// Matched to the token lifetime: past that the token is expired anyway, so
	// a retry has nothing left to be idempotent about.
	idempotencyTTL = 300 * time.Second

	// Bounded because the key is caller-supplied. Same reasoning as sitekeys.go:
	// anything keyed on a value the client chooses needs a ceiling.
	maxIdempotencyEntries = 10000

	// `action` and `cdata` are echoed back verbatim, so they are
	// attacker-controlled output. Length-capped to keep them from bloating the
	// token, and in cdata's case to keep it a label rather than a smuggling
	// channel.
	maxActionLength = 32
	maxCdataLength  = 255

	// Cap on a siteverify request body. The endpoint takes four short strings;
	// anything larger is not a caller we need to serve.
	maxSiteverifyBodyBytes = 64 << 10
)

// The error-code vocabulary. These strings are the contract — integrators
// branch on them — so they match Cloudflare's spelling exactly, hyphens and all.
const (
	errMissingSecret      = "missing-input-secret"
	errInvalidSecret      = "invalid-input-secret"
	errMissingResponse    = "missing-input-response"
	errInvalidResponse    = "invalid-input-response"
	errBadRequest         = "bad-request"
	errTimeoutOrDuplicate = "timeout-or-duplicate"
	errInternalError      = "internal-error"
)

// reasonToErrorCode maps VerifyTokenWithIP's internal reason onto that
// vocabulary.
//
// The collapse is lossy on purpose. A caller learning *why* a token failed
// learns something about the signing key or the replay window, so every
// structural failure reports the same invalid-input-response, and expiry and
// replay share timeout-or-duplicate exactly as Cloudflare's do.
func reasonToErrorCode(reason string) string {
	switch reason {
	case "expired", "token_already_used":
		return errTimeoutOrDuplicate
	default:
		return errInvalidResponse
	}
}

// TokenBinding is what a token is bound to beyond its score: the page that
// minted it and the action it was minted for.
type TokenBinding struct {
	Hostname string
	Action   string
	CData    string
}

// SiteverifyResponse is the wire shape.
//
// A map rather than a struct, because the three servers must emit the *same*
// key set and Go's struct tags cannot express that cheaply: `omitempty` would
// drop `hostname` when a token carries no host binding, where server-node and
// server-python both emit `""`. An integrator reading `response.hostname` would
// then get a value from two servers and nothing from the third. Building the
// object explicitly, the way the other two do, keeps them byte-comparable.
type SiteverifyResponse = map[string]interface{}

// siteverifyFailure is the failure shape: success plus codes, nothing else,
// matching Cloudflare's.
func siteverifyFailure(codes ...string) SiteverifyResponse {
	return SiteverifyResponse{"success": false, "error-codes": codes}
}

// siteverifySuccess is the success shape: every contract field always present.
func siteverifySuccess(challengeTS, hostname, action, cdata string, score interface{}) SiteverifyResponse {
	return SiteverifyResponse{
		"success":      true,
		"challenge_ts": challengeTS,
		"hostname":     hostname,
		"action":       action,
		"cdata":        cdata,
		"error-codes":  []string{},
		// Not part of the upstream contract, but the whole reason to run
		// FCaptcha: a caller that only wants pass/fail can ignore it, and one
		// that wants to risk-band on the score has it without a second call.
		"score": score,
	}
}

// hostFromURL pulls the host out of a URL-shaped header value.
//
// Returns "" rather than an error on anything unparseable, including the literal
// "null" that browsers send as Origin from a sandboxed iframe or a file:// page.
// An opaque origin is genuinely the absence of a hostname, not a failure — the
// token simply carries no host binding.
func hostFromURL(value string) string {
	if value == "" || value == "null" {
		return ""
	}
	u, err := url.Parse(value)
	if err != nil {
		return ""
	}
	// Hostname() strips the port and the IPv6 brackets, which is the
	// normalisation we want: example.com:8443 and example.com are one host.
	return strings.ToLower(u.Hostname())
}

// RequestHostname is the hostname a token should be bound to, from the headers
// of the request that mints it.
//
// Origin first: the widget's verification call is a CORS POST, so browsers
// attach it, and unlike Referer it is not suppressed by referrer policy. Referer
// is the fallback for same-origin deployments where Origin may be absent on some
// request shapes. Neither is trustworthy against a non-browser caller — anything
// that can forge one can forge both — so this binds the *browser* case, which is
// the case that matters: it stops a site key lifted from your page from minting
// tokens that your own backend will accept.
func RequestHostname(headers map[string]string) string {
	if headers == nil {
		return ""
	}
	if h := hostFromURL(headers["origin"]); h != "" {
		return h
	}
	return hostFromURL(headers["referer"])
}

// sanitizeLabel trims a caller-supplied label to something safe to sign and echo.
func sanitizeLabel(value string, maxLength int) string {
	// Control characters would ride through into the JSON response and any log
	// line that records it.
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(cleaned) > maxLength {
		cleaned = cleaned[:maxLength]
	}
	return cleaned
}

// SanitizeAction trims an action label.
func SanitizeAction(value string) string { return sanitizeLabel(value, maxActionLength) }

// SanitizeCData trims a customer-data label.
func SanitizeCData(value string) string { return sanitizeLabel(value, maxCdataLength) }

// SecretMatches compares two secrets in constant time.
//
// Both sides are hashed to a fixed width first so the comparison length does not
// itself depend on the secret.
func SecretMatches(provided, expected string) bool {
	a := sha256.Sum256([]byte(provided))
	b := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// HostnameAllowlist optionally restricts which page origins may mint tokens.
//
// Off by default so zero-config self-hosting keeps working, and permissive when
// a request carries no derivable Origin — a native mobile client or a
// server-side integration legitimately has none, and refusing those would break
// them for no security gain.
type HostnameAllowlist struct {
	hostnames map[string]struct{}
}

// HostnameAllowlistFromEnv reads FCAPTCHA_ALLOWED_HOSTNAMES (comma-separated).
func HostnameAllowlistFromEnv() *HostnameAllowlist {
	return NewHostnameAllowlist(strings.Split(os.Getenv("FCAPTCHA_ALLOWED_HOSTNAMES"), ","))
}

// NewHostnameAllowlist builds an allowlist from a list of hostnames.
func NewHostnameAllowlist(hostnames []string) *HostnameAllowlist {
	set := make(map[string]struct{})
	for _, h := range hostnames {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			set[h] = struct{}{}
		}
	}
	return &HostnameAllowlist{hostnames: set}
}

// Enabled reports whether any restriction is in force.
func (a *HostnameAllowlist) Enabled() bool { return len(a.hostnames) > 0 }

// Permits reports whether a hostname may mint tokens. An empty hostname passes:
// see the type comment — absence of an Origin is not evidence of a bad one.
func (a *HostnameAllowlist) Permits(hostname string) bool {
	if !a.Enabled() || hostname == "" {
		return true
	}
	_, ok := a.hostnames[hostname]
	return ok
}

// Describe renders the configuration for the startup log.
func (a *HostnameAllowlist) Describe() string {
	if !a.Enabled() {
		return "any (unrestricted)"
	}
	names := make([]string, 0, len(a.hostnames))
	for h := range a.hostnames {
		names = append(names, h)
	}
	return strings.Join(names, ", ")
}

// IdempotencyStore caches validation results so a retried siteverify returns the
// first answer instead of tripping the single-use guard.
//
// Keyed on the idempotency key *and* the token: reusing one key across different
// tokens is a caller bug, and answering the second one from the first one's
// cache entry would report success for a token nobody validated. Binding both
// degrades that case to an ordinary fresh verification.
type IdempotencyStore struct {
	entries *expirable.LRU[string, SiteverifyResponse]
	redis   *redis.Client
}

// NewRedisIdempotencyStore shares retry responses between replicas. Keys are
// hashed before leaving the process so caller-provided idempotency values and
// tokens never appear in Redis key listings.
func NewRedisIdempotencyStore(client *redis.Client) *IdempotencyStore {
	return &IdempotencyStore{redis: client}
}

// NewIdempotencyStore builds a bounded, self-expiring result cache.
func NewIdempotencyStore() *IdempotencyStore {
	return &IdempotencyStore{
		entries: expirable.NewLRU[string, SiteverifyResponse](maxIdempotencyEntries, nil, idempotencyTTL),
	}
}

func (s *IdempotencyStore) key(idempotencyKey, token string) string {
	sum := sha256.Sum256([]byte(token))
	return idempotencyKey + ":" + hex.EncodeToString(sum[:])[:32]
}

func (s *IdempotencyStore) redisKey(idempotencyKey, token string) string {
	sum := sha256.Sum256([]byte(s.key(idempotencyKey, token)))
	return redisStatePrefix + "siteverify:idempotency:" + hex.EncodeToString(sum[:])
}

// Get returns a cached response, if one is still live.
func (s *IdempotencyStore) Get(idempotencyKey, token string) (SiteverifyResponse, bool) {
	if idempotencyKey == "" {
		return SiteverifyResponse{}, false
	}
	if s.redis != nil {
		payload, err := s.redis.Get(context.Background(), s.redisKey(idempotencyKey, token)).Bytes()
		if err != nil {
			return SiteverifyResponse{}, false
		}
		var response SiteverifyResponse
		if json.Unmarshal(payload, &response) != nil {
			return SiteverifyResponse{}, false
		}
		return response, true
	}
	return s.entries.Get(s.key(idempotencyKey, token))
}

// Set records a response for replay.
func (s *IdempotencyStore) Set(idempotencyKey, token string, resp SiteverifyResponse) {
	if idempotencyKey == "" {
		return
	}
	if s.redis != nil {
		payload, err := json.Marshal(resp)
		if err == nil {
			_ = s.redis.Set(context.Background(), s.redisKey(idempotencyKey, token), payload, idempotencyTTL).Err()
		}
		return
	}
	s.entries.Add(s.key(idempotencyKey, token), resp)
}

// siteverifyParams are the four inputs the contract defines.
type siteverifyParams struct {
	Secret         string
	Response       string
	RemoteIP       string
	IdempotencyKey string
}

// readSiteverifyParams reads the parameters from either encoding.
//
// Both are accepted because the contract accepts both, and callers in the wild
// are split: PHP and Python examples overwhelmingly post form-encoded, Node and
// Go examples post JSON.
func readSiteverifyParams(r *http.Request) (siteverifyParams, bool) {
	var p siteverifyParams

	// Bound the body before either parser touches it.
	r.Body = io.NopCloser(io.LimitReader(r.Body, maxSiteverifyBodyBytes))

	// Content-Type may carry a charset parameter; only the media type matters.
	mediaType := r.Header.Get("Content-Type")
	if idx := strings.Index(mediaType, ";"); idx >= 0 {
		mediaType = mediaType[:idx]
	}

	if strings.EqualFold(strings.TrimSpace(mediaType), "application/json") {
		var body struct {
			Secret         string `json:"secret"`
			Response       string `json:"response"`
			RemoteIP       string `json:"remoteip"`
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return p, false
		}
		p.Secret = body.Secret
		p.Response = body.Response
		p.RemoteIP = body.RemoteIP
		p.IdempotencyKey = body.IdempotencyKey
		return p, true
	}

	if err := r.ParseForm(); err != nil {
		return p, false
	}
	p.Secret = r.PostFormValue("secret")
	p.Response = r.PostFormValue("response")
	p.RemoteIP = r.PostFormValue("remoteip")
	p.IdempotencyKey = r.PostFormValue("idempotency_key")
	return p, true
}

// siteverifyHandler serves the compatibility contract.
//
// requireSecret is threaded rather than read from the environment here so the
// handler stays testable and the policy decision lives in one place in main.
func siteverifyHandler(engine *ScoringEngine, trust *ProxyTrust, store *IdempotencyStore, verifySecret string, requireSecret bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeJSON := func(resp SiteverifyResponse) {
			// Callers index into error-codes, so it is never null on the wire.
			if resp["error-codes"] == nil {
				resp["error-codes"] = []string{}
			}
			json.NewEncoder(w).Encode(resp)
		}

		params, ok := readSiteverifyParams(r)
		if !ok {
			writeJSON(siteverifyFailure(errBadRequest))
			return
		}

		if requireSecret {
			if params.Secret == "" {
				writeJSON(siteverifyFailure(errMissingSecret))
				return
			}
			if !SecretMatches(params.Secret, verifySecret) {
				writeJSON(siteverifyFailure(errInvalidSecret))
				return
			}
		}

		if params.Response == "" {
			writeJSON(siteverifyFailure(errMissingResponse))
			return
		}

		if cached, hit := store.Get(params.IdempotencyKey, params.Response); hit {
			writeJSON(cached)
			return
		}

		// remoteip is passed through to the IP-binding check. Empty means the
		// caller declined to assert one, which the token verifier treats as
		// "don't check".
		result := engine.VerifyTokenWithIP(params.Response, params.RemoteIP)

		var resp SiteverifyResponse
		if valid, _ := result["valid"].(bool); valid {
			challengeTS := ""
			if ts, ok := result["timestamp"].(float64); ok {
				challengeTS = time.Unix(int64(ts), 0).UTC().Format("2006-01-02T15:04:05.000Z")
			}
			// nil, not 0, when the token carries no score: JSON null matches what
			// server-node and server-python emit for the same case.
			var score interface{}
			if s, ok := result["score"].(float64); ok {
				score = s
			}
			resp = siteverifySuccess(
				challengeTS,
				stringField(result, "hostname"),
				stringField(result, "action"),
				stringField(result, "cdata"),
				score,
			)
		} else {
			resp = siteverifyFailure(reasonToErrorCode(stringField(result, "reason")))
		}

		store.Set(params.IdempotencyKey, params.Response, resp)
		writeJSON(resp)
	}
}

// stringField reads a string out of the verification result without panicking on
// a missing or differently-typed key.
func stringField(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}
