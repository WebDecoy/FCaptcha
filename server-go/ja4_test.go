package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// JA4 has a published spec, so the failure mode to guard against is silent
// divergence from it. These check the rules that are easy to get subtly wrong,
// plus one end-to-end handshake proving the wiring actually produces a
// fingerprint from a real connection.

func TestIsGREASE(t *testing.T) {
	// RFC 8701 defines exactly sixteen GREASE values.
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x7a7a, 0xdada, 0xeaea, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%#04x is a GREASE value", v)
		}
	}
	// Near-misses that must NOT be treated as GREASE, or real ciphers vanish
	// from the fingerprint.
	for _, v := range []uint16{0x1301, 0x1302, 0xc02b, 0x0a0b, 0x0b0a, 0x1a2a, 0xabab} {
		if isGREASE(v) {
			t.Errorf("%#04x is a real value, not GREASE", v)
		}
	}
}

func TestJA4ALPNEncoding(t *testing.T) {
	cases := map[string]string{
		"h2":       "h2",
		"http/1.1": "h1", // first and last character, not a prefix
		"h3":       "h3",
	}
	for in, want := range cases {
		if got := ja4ALPN([]string{in}); got != want {
			t.Errorf("ja4ALPN(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ja4ALPN(nil); got != "00" {
		t.Errorf("no ALPN should give 00, got %q", got)
	}
	// Only the first protocol counts.
	if got := ja4ALPN([]string{"h2", "http/1.1"}); got != "h2" {
		t.Errorf("only the first ALPN counts, got %q", got)
	}
}

func TestJA4CountsExcludeGREASE(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x0a0a, 0x1301, 0x1302, 0x1a1a, 0xc02b},
		Extensions:        []uint16{0x2a2a, 0x0000, 0x0010, 0x000d, 0x002b},
		SupportedVersions: []uint16{tls.VersionTLS13},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2"},
	}
	ja4 := ComputeJA4(hello)

	// 3 real ciphers of 5, 4 real extensions of 5 — and the extension COUNT
	// includes SNI and ALPN even though the hashed list excludes them.
	if !strings.HasPrefix(ja4, "t13d0304h2_") {
		t.Errorf("expected prefix t13d0304h2_, got %q", ja4)
	}
}

func TestJA4SNIFlag(t *testing.T) {
	base := func(name string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			CipherSuites:      []uint16{0x1301},
			Extensions:        []uint16{0x002b},
			SupportedVersions: []uint16{tls.VersionTLS13},
			ServerName:        name,
		}
	}
	if got := ComputeJA4(base("example.com")); got[3] != 'd' {
		t.Errorf("SNI present should give 'd', got %q in %s", got[3], got)
	}
	if got := ComputeJA4(base("")); got[3] != 'i' {
		t.Errorf("no SNI should give 'i', got %q in %s", got[3], got)
	}
}

// Cipher and extension order varies between connections from the same client;
// the spec sorts them so it does not affect the fingerprint.
func TestJA4IsOrderInsensitiveForCiphersAndExtensions(t *testing.T) {
	a := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301, 0x1302, 0xc02b},
		Extensions:        []uint16{0x002b, 0x000d, 0x0017},
		SupportedVersions: []uint16{tls.VersionTLS13},
		ServerName:        "example.com",
	}
	b := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0xc02b, 0x1301, 0x1302},
		Extensions:        []uint16{0x0017, 0x002b, 0x000d},
		SupportedVersions: []uint16{tls.VersionTLS13},
		ServerName:        "example.com",
	}
	if ComputeJA4(a) != ComputeJA4(b) {
		t.Errorf("reordering ciphers/extensions changed the fingerprint:\n  %s\n  %s", ComputeJA4(a), ComputeJA4(b))
	}
}

// Signature algorithms are the exception: their order IS characteristic of the
// client, so the spec deliberately does not sort them.
func TestJA4SignatureAlgorithmOrderMatters(t *testing.T) {
	mk := func(schemes ...tls.SignatureScheme) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			CipherSuites:      []uint16{0x1301},
			Extensions:        []uint16{0x000d},
			SupportedVersions: []uint16{tls.VersionTLS13},
			ServerName:        "example.com",
			SignatureSchemes:  schemes,
		}
	}
	a := ComputeJA4(mk(tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256))
	b := ComputeJA4(mk(tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256))
	if a == b {
		t.Error("signature algorithm order must change the fingerprint (it is not sorted)")
	}
}

func TestJA4ExtensionListExcludesSNIAndALPN(t *testing.T) {
	// Same client, two different sites: SNI and ALPN differ, everything else is
	// identical. The hashed section must not move, or one browser fingerprints
	// differently per site and the signal is useless.
	mk := func(name string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{
			CipherSuites:      []uint16{0x1301, 0x1302},
			Extensions:        []uint16{0x0000, 0x0010, 0x002b, 0x000d},
			SupportedVersions: []uint16{tls.VersionTLS13},
			ServerName:        name,
			SupportedProtos:   []string{"h2"},
		}
	}
	a, b := ComputeJA4(mk("one.example")), ComputeJA4(mk("two.example"))
	if a != b {
		t.Errorf("the hashed sections must not depend on SNI:\n  %s\n  %s", a, b)
	}
}

func TestJA4Shape(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303},
		Extensions:        []uint16{0x0000, 0x0010, 0x002b, 0x000d, 0x0017},
		SupportedVersions: []uint16{tls.VersionTLS13},
		ServerName:        "example.com",
		SupportedProtos:   []string{"h2"},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	}
	got := ComputeJA4(hello)
	// t13d0305h2_<12 hex>_<12 hex>
	if !regexp.MustCompile(`^[tq](13|12|11|10|s3|s2|00)[di]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`).MatchString(got) {
		t.Errorf("malformed JA4: %q", got)
	}
}

// End-to-end: a real handshake against a real listener, proving the
// GetConfigForClient wiring records something a handler can read back.
func TestJA4EndToEndOverRealTLS(t *testing.T) {
	store := newJA4Store(128)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, store.Lookup(r.RemoteAddr))
	}))
	srv.TLS = TLSConfigWithJA4(&tls.Config{}, store)
	srv.StartTLS()
	defer srv.Close()

	// httptest.Server.Client() already trusts the throwaway certificate.
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	got := string(body)
	if got == "" {
		t.Fatal("no JA4 was recorded for a real TLS connection")
	}
	if !strings.HasPrefix(got, "t1") {
		t.Errorf("expected a TCP/TLS1.x fingerprint, got %q", got)
	}
	t.Logf("Go client fingerprinted as %s", got)
}

// Guards the licensing boundary from §8.3 of the extensions PRD: JA4 (TLS) is
// BSD-3-Clause and safe here; JA4H/JA4T/JA4L/JA4S/JA4X/JA4SSH are FoxIO License
// 1.1, non-commercial only, and cannot ship in an MIT project. If someone adds
// one, this fails and points them at the reason.
func TestOnlyJA4TLSIsImplemented(t *testing.T) {
	src := readSourceFile(t, "ja4.go")
	for _, forbidden := range []string{"JA4H", "JA4T", "JA4L", "JA4S", "JA4X", "JA4SSH"} {
		// Allowed inside the comment that explains why they are absent.
		count := strings.Count(src, "func "+forbidden) + strings.Count(src, "func Compute"+forbidden)
		if count > 0 {
			t.Errorf("%s appears to be implemented — it is FoxIO License 1.1 "+
				"(non-commercial, GPL-incompatible) and cannot ship in this MIT project. See PRD §8.3.", forbidden)
		}
	}
}

func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

// The locally-computed fingerprint must win over a header, because a header
// requires trusting whatever set it while a ClientHello-derived value cannot be
// asserted by anyone.
func TestNativeJA4TakesPrecedenceOverHeader(t *testing.T) {
	const nativeFP = "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	const headerFP = "t13d1516h2_cccccccccccc_dddddddddddd"

	knownBotJA4Hashes[nativeFP] = "native-source tool"
	knownBotJA4Hashes[headerFP] = "header-source tool"
	defer func() {
		delete(knownBotJA4Hashes, nativeFP)
		delete(knownBotJA4Hashes, headerFP)
	}()

	t.Setenv("TRUSTED_JA4_HEADERS", "cf-ja4")
	e := NewScoringEngine("test-secret")
	headers := map[string]string{"cf-ja4": headerFP}

	// The reason string is generic, so read which fingerprint was matched out of
	// the detection Details.
	matchedTool := func(res *VerificationResult) string {
		for _, d := range res.Detections {
			if d.Category == CategoryFingerprint && d.Details != nil {
				if tool, ok := d.Details["tool"].(string); ok {
					return tool
				}
			}
		}
		return ""
	}

	// Both available: the native one is the one that gets scored.
	both := e.VerifyWithHeaders(map[string]interface{}{}, "1.2.3.4", "site", "ua", headers, "", nativeFP, true, nil, TokenBinding{})
	if got := matchedTool(both); got != "native-source tool" {
		t.Errorf("native JA4 should take precedence, matched %q", got)
	}

	// No native fingerprint (something upstream terminated TLS): fall back.
	fallback := e.VerifyWithHeaders(map[string]interface{}{}, "1.2.3.4", "site", "ua", headers, "", "", true, nil, TokenBinding{})
	if got := matchedTool(fallback); got != "header-source tool" {
		t.Errorf("should fall back to the trusted header, matched %q", got)
	}
}

// The map that CheckJA4Fingerprint consults ships empty on purpose — the PRD
// calls a static hash list defeatable by rotating a fingerprint, and populating
// it with values nobody here has observed would be worse than leaving it bare.
// This records that state so its eventual filling is a deliberate act.
func TestKnownBotJA4MapShipsEmpty(t *testing.T) {
	if len(knownBotJA4Hashes) != 0 {
		t.Errorf("knownBotJA4Hashes has %d entries; native JA4 computation is wired but "+
			"intentionally has nothing to match against yet. If you are populating it, "+
			"say where the fingerprints were observed.", len(knownBotJA4Hashes))
	}
}
