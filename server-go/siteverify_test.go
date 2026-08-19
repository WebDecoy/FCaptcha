package main

// Tests for the siteverify compatibility layer. Mirrors
// server-node/siteverify.test.js and server-python/test_siteverify.py — the
// three servers must agree on hostname derivation, the error-code vocabulary
// and the idempotency semantics, because an integrator switching between them
// should not be able to tell which one answered.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// legacyToken mints a token in the pre-binding four-key format, using the same
// signing scheme. Kept as a literal reconstruction rather than a call into
// generateToken so it stays pinned to the old shape even as generateToken moves.
func legacyToken(e *ScoringEngine, ip string) string {
	ipHash := sha256.Sum256([]byte(ip))
	data := map[string]interface{}{
		"site_key":  "test-site",
		"timestamp": time.Now().Unix(),
		"score":     math.Round(0.22*1000) / 1000,
		"ip_hash":   hex.EncodeToString(ipHash[:4]),
	}
	payload, _ := json.Marshal(data)
	h := hmac.New(sha256.New, []byte(e.secretKey))
	h.Write(payload)
	data["sig"] = hex.EncodeToString(h.Sum(nil))
	tokenData, _ := json.Marshal(data)
	// Deliberately padded: that is what the Go server used to emit, so this also
	// exercises decodeTokenBase64's tolerance of the old convention.
	return base64.URLEncoding.EncodeToString(tokenData)
}

// tamperTokenHostname rewrites the hostname claim without re-signing.
func tamperTokenHostname(t *testing.T, token, hostname string) string {
	t.Helper()
	raw, err := decodeTokenBase64(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data["hostname"] = hostname
	out, _ := json.Marshal(data)
	return base64.RawURLEncoding.EncodeToString(out)
}

// ---------------------------------------------------------------- hostname

func TestHostFromURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://Example.COM:8443/a/b?c=d", "example.com"},
		{"http://example.com", "example.com"},
		// Sandboxed iframes and file:// pages send the literal string "null".
		{"null", ""},
		{"", ""},
		{"://nonsense", ""},
		// Hostname() unwraps the IPv6 brackets.
		{"https://[::1]:3000/", "::1"},
	}
	for _, c := range cases {
		if got := hostFromURL(c.in); got != c.want {
			t.Errorf("hostFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRequestHostnamePrefersOrigin(t *testing.T) {
	got := RequestHostname(map[string]string{
		"origin":  "https://origin.example",
		"referer": "https://referer.example/p",
	})
	if got != "origin.example" {
		t.Errorf("got %q, want origin.example", got)
	}
}

func TestRequestHostnameFallsBack(t *testing.T) {
	if got := RequestHostname(map[string]string{"referer": "https://referer.example/p"}); got != "referer.example" {
		t.Errorf("referer fallback: got %q", got)
	}
	// An opaque Origin must fall through to Referer rather than pinning "".
	if got := RequestHostname(map[string]string{"origin": "null", "referer": "https://r.example/"}); got != "r.example" {
		t.Errorf("opaque origin fallback: got %q", got)
	}
	if got := RequestHostname(map[string]string{}); got != "" {
		t.Errorf("empty headers: got %q", got)
	}
	if got := RequestHostname(nil); got != "" {
		t.Errorf("nil headers: got %q", got)
	}
}

// --------------------------------------------------------------- allowlist

func TestHostnameAllowlist(t *testing.T) {
	unset := NewHostnameAllowlist(nil)
	if unset.Enabled() || !unset.Permits("anything.example") {
		t.Error("an unset allowlist must permit everything")
	}

	list := NewHostnameAllowlist([]string{"a.example", " B.EXAMPLE "})
	if !list.Enabled() {
		t.Fatal("allowlist should be enabled")
	}
	if !list.Permits("a.example") {
		t.Error("listed host rejected")
	}
	if !list.Permits("b.example") {
		t.Error("matching should be case-insensitive and trimmed")
	}
	if list.Permits("evil.example") {
		t.Error("unlisted host admitted")
	}
	// A native mobile client or server-side integration has no Origin. Refusing
	// those would break them without stopping anything: an attacker who can
	// forge an Origin would just forge an allowed one.
	if !list.Permits("") {
		t.Error("a request with no derivable hostname must be admitted")
	}
}

// -------------------------------------------------------------- sanitizing

func TestSanitizeLabels(t *testing.T) {
	if got := SanitizeAction(strings.Repeat("x", 200)); len(got) != maxActionLength {
		t.Errorf("action length %d, want %d", len(got), maxActionLength)
	}
	if got := SanitizeCData(strings.Repeat("x", 9999)); len(got) != maxCdataLength {
		t.Errorf("cdata length %d, want %d", len(got), maxCdataLength)
	}
	// These are echoed back to the caller and into logs.
	if got := SanitizeAction("log\nin"); got != "login" {
		t.Errorf("control characters survived: %q", got)
	}
	if got := SanitizeCData("a\r\nb"); got != "ab" {
		t.Errorf("control characters survived: %q", got)
	}
}

// ----------------------------------------------------------------- secrets

func TestSecretMatches(t *testing.T) {
	if !SecretMatches("hunter2", "hunter2") {
		t.Error("equal secrets should match")
	}
	if SecretMatches("hunter2", "hunter3") {
		t.Error("different secrets should not match")
	}
	// Hashing first is what keeps unequal lengths from being a special case.
	if SecretMatches("short", "a-much-longer-secret") {
		t.Error("unequal lengths should not match")
	}
	if SecretMatches("", "x") {
		t.Error("empty should not match")
	}
}

// ------------------------------------------------------------- error codes

func TestReasonToErrorCode(t *testing.T) {
	cases := map[string]string{
		"expired":            errTimeoutOrDuplicate,
		"token_already_used": errTimeoutOrDuplicate,
		"invalid_signature":  errInvalidResponse,
		"ip_mismatch":        errInvalidResponse,
		// An unrecognised reason must not leak through as itself.
		"some unexpected internal error": errInvalidResponse,
		"":                               errInvalidResponse,
	}
	for reason, want := range cases {
		if got := reasonToErrorCode(reason); got != want {
			t.Errorf("reasonToErrorCode(%q) = %q, want %q", reason, got, want)
		}
	}
}

// ------------------------------------------------------------- the handler

const testSecret = "the-secret"

// mintToken produces a token the way a successful verification would.
func mintToken(e *ScoringEngine, ip string, binding TokenBinding) string {
	return e.generateToken(ip, "test-site", 0.11, binding)
}

func newTestHandler(e *ScoringEngine, requireSecret bool) (http.HandlerFunc, *IdempotencyStore) {
	store := NewIdempotencyStore()
	return siteverifyHandler(e, ProxyTrustFromEnv(), store, testSecret, requireSecret), store
}

func postForm(h http.HandlerFunc, body string) map[string]interface{} {
	req := httptest.NewRequest(http.MethodPost, "/turnstile/v0/siteverify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, req)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func postJSON(h http.HandlerFunc, body string) map[string]interface{} {
	req := httptest.NewRequest(http.MethodPost, "/turnstile/v0/siteverify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	h(w, req)
	var out map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func errorCodes(resp map[string]interface{}) []string {
	raw, _ := resp["error-codes"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func firstCode(t *testing.T, resp map[string]interface{}) string {
	t.Helper()
	codes := errorCodes(resp)
	if len(codes) != 1 {
		t.Fatalf("want exactly one error code, got %v", codes)
	}
	return codes[0]
}

func TestSiteverifySuccessShape(t *testing.T) {
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	tok := mintToken(e, "", TokenBinding{Hostname: "example.com", Action: "login", CData: "sess-42"})

	resp := postForm(h, "secret="+testSecret+"&response="+tok)
	if resp["success"] != true {
		t.Fatalf("expected success, got %v", resp)
	}
	if resp["hostname"] != "example.com" || resp["action"] != "login" || resp["cdata"] != "sess-42" {
		t.Errorf("binding not reported: %v", resp)
	}
	if len(errorCodes(resp)) != 0 {
		t.Errorf("error-codes should be empty on success: %v", resp)
	}
	// challenge_ts must be the ISO-8601 shape the contract specifies.
	ts, _ := resp["challenge_ts"].(string)
	if !strings.HasSuffix(ts, "Z") || len(ts) != len("2006-01-02T15:04:05.000Z") {
		t.Errorf("challenge_ts not ISO-8601 with milliseconds: %q", ts)
	}
}

func TestSiteverifyAcceptsJSONBody(t *testing.T) {
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	tok := mintToken(e, "", TokenBinding{Hostname: "shop.example", Action: "checkout"})

	resp := postJSON(h, `{"secret":"`+testSecret+`","response":"`+tok+`"}`)
	if resp["success"] != true {
		t.Fatalf("JSON body should verify the same as form-encoded: %v", resp)
	}
	if resp["hostname"] != "shop.example" {
		t.Errorf("hostname not reported: %v", resp)
	}
}

func TestSiteverifySecretGate(t *testing.T) {
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	tok := mintToken(e, "", TokenBinding{Hostname: "example.com"})

	if got := firstCode(t, postForm(h, "response="+tok)); got != errMissingSecret {
		t.Errorf("no secret: got %q", got)
	}
	if got := firstCode(t, postForm(h, "secret=wrong&response="+tok)); got != errInvalidSecret {
		t.Errorf("wrong secret: got %q", got)
	}
	// The token must survive both rejections — they happen before verification,
	// so the single-use guard has not been spent.
	if resp := postForm(h, "secret="+testSecret+"&response="+tok); resp["success"] != true {
		t.Errorf("token should be unspent after a rejected secret: %v", resp)
	}
}

func TestSiteverifyMissingResponse(t *testing.T) {
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	if got := firstCode(t, postForm(h, "secret="+testSecret)); got != errMissingResponse {
		t.Errorf("got %q, want %q", got, errMissingResponse)
	}
}

func TestSiteverifyLegacyUnauthenticated(t *testing.T) {
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, false)
	tok := mintToken(e, "", TokenBinding{})
	if resp := postForm(h, "response="+tok); resp["success"] != true {
		t.Errorf("requireSecret=false should restore the old behaviour: %v", resp)
	}
}

func TestSiteverifyGarbageToken(t *testing.T) {
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	if got := firstCode(t, postForm(h, "secret="+testSecret+"&response=not-a-token")); got != errInvalidResponse {
		t.Errorf("got %q, want %q", got, errInvalidResponse)
	}
}

func TestSiteverifyReplayIsRefused(t *testing.T) {
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	tok := mintToken(e, "", TokenBinding{Hostname: "example.com"})

	if resp := postForm(h, "secret="+testSecret+"&response="+tok); resp["success"] != true {
		t.Fatalf("first use should succeed: %v", resp)
	}
	resp := postForm(h, "secret="+testSecret+"&response="+tok)
	if resp["success"] != false {
		t.Fatal("a token must be single-use")
	}
	if got := firstCode(t, resp); got != errTimeoutOrDuplicate {
		t.Errorf("got %q, want %q", got, errTimeoutOrDuplicate)
	}
}

func TestSiteverifyIdempotencyKeyMakesRetrySafe(t *testing.T) {
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	tok := mintToken(e, "", TokenBinding{Hostname: "idem.example", Action: "submit"})

	body := "secret=" + testSecret + "&response=" + tok + "&idempotency_key=abc-123"
	first := postForm(h, body)
	second := postForm(h, body)

	if first["success"] != true {
		t.Fatalf("first call: %v", first)
	}
	if second["success"] != true {
		t.Fatalf("retry under the same key must succeed, got %v", second)
	}
	if first["challenge_ts"] != second["challenge_ts"] || first["hostname"] != second["hostname"] {
		t.Errorf("retry must replay the first answer: %v vs %v", first, second)
	}
}

func TestSiteverifyIdempotencyKeyDoesNotCrossAnswer(t *testing.T) {
	// Reusing a key for a different token is a caller bug; answering the second
	// from the first's cache would report success for a token nobody validated.
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	good := mintToken(e, "", TokenBinding{Hostname: "a.example"})

	if resp := postForm(h, "secret="+testSecret+"&response="+good+"&idempotency_key=k"); resp["success"] != true {
		t.Fatalf("first: %v", resp)
	}
	resp := postForm(h, "secret="+testSecret+"&response=different-token&idempotency_key=k")
	if resp["success"] != false {
		t.Error("a different token under the same key must be verified on its own merits")
	}
}

func TestSiteverifyFailureIsReplayableToo(t *testing.T) {
	// Otherwise a retried failure could turn into a different failure, and the
	// caller cannot tell a stable rejection from a flaky one.
	e := NewScoringEngine(testSecret)
	h, _ := newTestHandler(e, true)
	body := "secret=" + testSecret + "&response=bad-token&idempotency_key=k"
	first := postForm(h, body)
	second := postForm(h, body)
	if first["success"] != false || second["success"] != false {
		t.Fatal("both should fail")
	}
	if firstCode(t, first) != firstCode(t, second) {
		t.Error("a replayed failure must report the same code")
	}
}

// ------------------------------------------------------- token round-trips

func TestTokenCarriesBinding(t *testing.T) {
	e := NewScoringEngine(testSecret)
	tok := mintToken(e, "203.0.113.5", TokenBinding{Hostname: "bound.example", Action: "signup", CData: "abc"})

	result := e.VerifyTokenWithIP(tok, "203.0.113.5")
	if valid, _ := result["valid"].(bool); !valid {
		t.Fatalf("token should verify: %v", result)
	}
	if result["hostname"] != "bound.example" || result["action"] != "signup" || result["cdata"] != "abc" {
		t.Errorf("binding did not round-trip: %v", result)
	}
}

func TestLegacyFourKeyTokenStillVerifies(t *testing.T) {
	// Tokens minted before hostname/action/cdata existed carry four keys. The
	// signature covers whatever keys are present, so they must still validate —
	// this change is additive, not a format break. A token in flight during a
	// rolling deploy depends on it.
	e := NewScoringEngine(testSecret)
	legacy := legacyToken(e, "203.0.113.9")

	result := e.VerifyTokenWithIP(legacy, "203.0.113.9")
	if valid, _ := result["valid"].(bool); !valid {
		t.Fatalf("a pre-binding token must still verify: %v", result)
	}
	if result["hostname"] != "" || result["action"] != "" || result["cdata"] != "" {
		t.Errorf("missing fields should read as empty, got %v", result)
	}
}

func TestTokenBindingIsSigned(t *testing.T) {
	// The binding is only worth reporting if it cannot be edited in flight.
	e := NewScoringEngine(testSecret)
	tok := mintToken(e, "", TokenBinding{Hostname: "real.example"})

	tampered := tamperTokenHostname(t, tok, "attacker.example")
	result := e.VerifyTokenWithIP(tampered, "")
	if valid, _ := result["valid"].(bool); valid {
		t.Fatal("a token with an edited hostname must not verify")
	}
	if result["reason"] != "invalid_signature" {
		t.Errorf("want invalid_signature, got %v", result["reason"])
	}
}

// ------------------------------------------- cross-language token format
//
// The three servers sign the same claims, so they must serialise them the same
// way. They did not: Go emitted padded base64url, Node unpadded, and Python
// signed a payload with a space after every ':' and ','. No two could verify
// each other's tokens, and nothing caught it because each server only ever
// verified its own. These fixtures pin the shared format so a future edit to
// any one implementation fails here instead of in a mixed fleet.
//
// Keep byte-identical across server-node/siteverify.test.js,
// server-go/siteverify_test.go and server-python/test_siteverify.py.

const (
	fixturePayload = `{"action":"login","cdata":"c1","hostname":"example.com","ip_hash":"abcd1234","score":0.11,"site_key":"s","timestamp":1700000000}`
	fixtureSig     = "75bd31f5adfc85b1af1be4811ebe228995320a09b59bda3826ac9383bb1cb6b0"
	fixtureSecret  = "fixture-secret"
)

func fixtureClaims() map[string]interface{} {
	return map[string]interface{}{
		"site_key":  "s",
		"timestamp": int64(1700000000),
		"score":     0.11,
		"ip_hash":   "abcd1234",
		"hostname":  "example.com",
		"action":    "login",
		"cdata":     "c1",
	}
}

func TestCanonicalPayloadIsSortedAndUnspaced(t *testing.T) {
	payload, err := json.Marshal(fixtureClaims())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(payload) != fixturePayload {
		t.Errorf("payload diverged from the shared format:\n got %s\nwant %s", payload, fixturePayload)
	}
}

func TestFixtureClaimsProduceTheSharedSignature(t *testing.T) {
	e := NewScoringEngine(fixtureSecret)
	payload, _ := json.Marshal(fixtureClaims())
	if got := e.computeSignature(payload); got != fixtureSig {
		t.Errorf("signature diverged: got %s, want %s", got, fixtureSig)
	}
}

func TestTokensAreUnpaddedBase64URL(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(fixturePayload))
	if strings.ContainsAny(encoded, "=+/") {
		t.Errorf("token must be unpadded and url-safe, got %q", encoded)
	}
	// and the decoder must still accept the padded form other versions emitted
	padded := base64.URLEncoding.EncodeToString([]byte(fixturePayload))
	decoded, err := decodeTokenBase64(padded)
	if err != nil || string(decoded) != fixturePayload {
		t.Errorf("padded form must still decode: %v / %q", err, decoded)
	}
}
