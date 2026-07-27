package main

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
)

func request(remoteAddr string, headers map[string]string) *http.Request {
	r, _ := http.NewRequest("POST", "/api/verify", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func defaultTrust() *ProxyTrust {
	return NewProxyTrust("127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
}

// The bypass this file exists to prevent: a caller reaching the server directly
// claims a residential IP and expects the datacenter/Tor/rate-limit checks to
// see it.
func TestClientIPIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	trust := defaultTrust()

	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"x-real-ip", map[string]string{"X-Real-IP": "73.15.22.100"}},
		{"x-forwarded-for", map[string]string{"X-Forwarded-For": "73.15.22.100"}},
		{"both", map[string]string{"X-Real-IP": "73.15.22.100", "X-Forwarded-For": "8.8.8.8"}},
		{"chain", map[string]string{"X-Forwarded-For": "73.15.22.100, 1.1.1.1, 2.2.2.2"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 159.65.1.1 is a DigitalOcean range in detection.go's list.
			got := trust.ClientIP(request("159.65.1.1:44321", tc.headers))
			if got != "159.65.1.1" {
				t.Errorf("spoofed header honoured: got %q, want the socket address 159.65.1.1", got)
			}
		})
	}
}

func TestClientIPHonoursTrustedProxy(t *testing.T) {
	trust := defaultTrust()

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "x-real-ip from loopback nginx",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Real-IP": "73.15.22.100"},
			want:       "73.15.22.100",
		},
		{
			name:       "x-forwarded-for from private-network proxy",
			remoteAddr: "10.0.1.5:33333",
			headers:    map[string]string{"X-Forwarded-For": "73.15.22.100"},
			want:       "73.15.22.100",
		},
		{
			// The client prepended a fake hop; the rightmost untrusted entry is
			// still the address our edge actually accepted.
			name:       "client-prepended chain resolves to the real hop",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4, 73.15.22.100"},
			want:       "73.15.22.100",
		},
		{
			// Two real proxies in front of us: skip our own, keep the client.
			name:       "trusted hops are skipped right to left",
			remoteAddr: "10.0.1.5:33333",
			headers:    map[string]string{"X-Forwarded-For": "73.15.22.100, 10.0.1.9, 192.168.1.2"},
			want:       "73.15.22.100",
		},
		{
			name:       "x-real-ip wins over x-forwarded-for",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Real-IP": "73.15.22.100", "X-Forwarded-For": "1.2.3.4"},
			want:       "73.15.22.100",
		},
		{
			name:       "malformed hop falls back to the peer",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Forwarded-For": "73.15.22.100, unknown"},
			want:       "127.0.0.1",
		},
		{
			name:       "no headers falls back to the peer",
			remoteAddr: "127.0.0.1:8080",
			headers:    nil,
			want:       "127.0.0.1",
		},
		{
			name:       "entirely trusted chain falls back to the peer",
			remoteAddr: "10.0.1.5:33333",
			headers:    map[string]string{"X-Forwarded-For": "10.0.1.9"},
			want:       "10.0.1.5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := trust.ClientIP(request(tc.remoteAddr, tc.headers)); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// RemoteAddr always carries a port and may be IPv6 or IPv4-mapped. The value
// handed to IsDatacenterIP has to be a bare, dotted address or CIDR matching
// silently fails.
func TestClientIPNormalizesAddresses(t *testing.T) {
	trust := defaultTrust()

	tests := []struct {
		remoteAddr string
		want       string
	}{
		{"159.65.1.1:44321", "159.65.1.1"},
		{"[2001:db8::1]:44321", "2001:db8::1"},
		{"[::ffff:159.65.1.1]:44321", "159.65.1.1"},
		{"159.65.1.1", "159.65.1.1"},
	}

	for _, tc := range tests {
		t.Run(tc.remoteAddr, func(t *testing.T) {
			if got := trust.ClientIP(request(tc.remoteAddr, nil)); got != tc.want {
				t.Errorf("ClientIP(%q) = %q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}

	// An IPv4-mapped loopback peer must still be recognised as trusted.
	got := trust.ClientIP(request("[::ffff:127.0.0.1]:8080", map[string]string{"X-Real-IP": "73.15.22.100"}))
	if got != "73.15.22.100" {
		t.Errorf("IPv4-mapped loopback peer not trusted: got %q", got)
	}
}

func TestProxyTrustSpecs(t *testing.T) {
	headers := map[string]string{"X-Real-IP": "73.15.22.100"}

	t.Run("wildcard trusts every peer", func(t *testing.T) {
		if got := NewProxyTrust("*").ClientIP(request("159.65.1.1:44321", headers)); got != "73.15.22.100" {
			t.Errorf("ClientIP = %q, want the header value", got)
		}
	})

	t.Run("none trusts no peer", func(t *testing.T) {
		if got := NewProxyTrust("none").ClientIP(request("127.0.0.1:8080", headers)); got != "127.0.0.1" {
			t.Errorf("ClientIP = %q, want the socket address", got)
		}
	})

	t.Run("empty spec trusts no peer", func(t *testing.T) {
		if got := NewProxyTrust("").ClientIP(request("127.0.0.1:8080", headers)); got != "127.0.0.1" {
			t.Errorf("ClientIP = %q, want the socket address", got)
		}
	})

	t.Run("bare IP is a single host", func(t *testing.T) {
		trust := NewProxyTrust("203.0.113.7")
		if got := trust.ClientIP(request("203.0.113.7:9999", headers)); got != "73.15.22.100" {
			t.Errorf("listed host not trusted: got %q", got)
		}
		if got := trust.ClientIP(request("203.0.113.8:9999", headers)); got != "203.0.113.8" {
			t.Errorf("unlisted host trusted: got %q", got)
		}
	})

	t.Run("invalid entries are skipped without killing valid ones", func(t *testing.T) {
		trust := NewProxyTrust("not-an-ip, 999.0.0.1/8, 127.0.0.0/8")
		if got := trust.ClientIP(request("127.0.0.1:8080", headers)); got != "73.15.22.100" {
			t.Errorf("valid entry lost: got %q", got)
		}
	})
}

// A client that can set its own JA3 presents a stock Chrome fingerprint and
// erases the signal, so the header is only read from a trusted proxy.
func TestTrustedHeaderGatesJA3(t *testing.T) {
	trust := defaultTrust()
	headers := map[string]string{"X-JA3-Hash": "cd08e31494f9531f560d64c695473da9"}

	if got := trust.TrustedHeader(request("159.65.1.1:44321", headers), "X-JA3-Hash"); got != "" {
		t.Errorf("JA3 accepted from untrusted peer: %q", got)
	}
	if got := trust.TrustedHeader(request("127.0.0.1:8080", headers), "X-JA3-Hash"); got != headers["X-JA3-Hash"] {
		t.Errorf("JA3 dropped from trusted proxy: %q", got)
	}
}

func TestProxyTrustFromEnvDefaults(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "")
	if got := ProxyTrustFromEnv().ClientIP(request("127.0.0.1:8080", map[string]string{"X-Real-IP": "73.15.22.100"})); got != "127.0.0.1" {
		t.Errorf("explicit empty TRUSTED_PROXIES should trust nothing, got %q", got)
	}

	// t.Setenv above registered restoration of the original value, so unsetting
	// here is safe and exercises the LookupEnv-miss path.
	if err := os.Unsetenv("TRUSTED_PROXIES"); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if got := ProxyTrustFromEnv().ClientIP(request("127.0.0.1:8080", map[string]string{"X-Real-IP": "73.15.22.100"})); got != "73.15.22.100" {
		t.Errorf("unset TRUSTED_PROXIES should trust loopback, got %q", got)
	}
	if got := ProxyTrustFromEnv().ClientIP(request("159.65.1.1:44321", map[string]string{"X-Real-IP": "73.15.22.100"})); got != "159.65.1.1" {
		t.Errorf("unset TRUSTED_PROXIES should not trust a public peer, got %q", got)
	}
}

// The misconfiguration hint: an unlisted reverse proxy and a spoofing client
// look identical here, and the silent failure (every visitor collapsing onto
// one address) is the expensive one, so it must be logged and bounded.
func TestUntrustedForwardingWarning(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stdout)

	trust := defaultTrust()

	// No forwarding headers: nothing unusual, nothing logged.
	trust.ClientIP(request("159.65.1.1:44321", nil))
	if buf.Len() != 0 {
		t.Errorf("warned with no forwarding headers: %s", buf.String())
	}

	// A trusted peer is the normal path, also silent.
	trust.ClientIP(request("127.0.0.1:8080", map[string]string{"X-Real-IP": "73.15.22.100"}))
	if buf.Len() != 0 {
		t.Errorf("warned for a trusted proxy: %s", buf.String())
	}

	// Untrusted peer sending forwarding headers: warn, and name the peer so it
	// can be pasted into TRUSTED_PROXIES.
	trust.ClientIP(request("159.65.1.1:44321", map[string]string{"X-Real-IP": "73.15.22.100"}))
	first := buf.String()
	if !strings.Contains(first, "159.65.1.1") || !strings.Contains(first, "TRUSTED_PROXIES") {
		t.Errorf("warning missing peer or remedy: %q", first)
	}

	// Bounded: a directly exposed server sees spoofing constantly.
	for i := 0; i < 50; i++ {
		trust.ClientIP(request("159.65.1.1:44321", map[string]string{"X-Forwarded-For": "73.15.22.100"}))
	}
	if got := strings.Count(buf.String(), "untrusted peer"); got != maxProxyMisconfigWarnings {
		t.Errorf("emitted %d warnings, want the cap of %d", got, maxProxyMisconfigWarnings)
	}
	if !strings.Contains(buf.String(), "further warnings suppressed") {
		t.Error("cap reached without saying so")
	}
}
