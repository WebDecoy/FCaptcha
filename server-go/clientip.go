package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

// Client IP resolution.
//
// Every IP-derived signal in FCaptcha — datacenter ranges, Tor/VPN, rate
// limiting, token IP binding, PoW difficulty — is only as trustworthy as the
// address it is handed. X-Forwarded-For and X-Real-IP are set by whoever is on
// the other end of the socket, so honouring them unconditionally lets any
// caller claim a clean residential IP and walk past all of it. They are
// credible only when the peer that sent them is a proxy we put there.
//
// TRUSTED_PROXIES holds the peers allowed to speak for someone else, as a
// comma-separated list of CIDRs and bare IPs. Unset means the private and
// loopback defaults below. "*" trusts every peer (only correct when an edge you
// control always overwrites the headers). "none" trusts nobody, so the socket
// address is always used.

// defaultTrustedProxyCIDRs is the fallback trust set: loopback plus the private
// and link-local ranges. A server exposed directly to the internet sees public
// peer addresses, which are not in this set, so forged headers are ignored. A
// server behind a sidecar or in-cluster reverse proxy (nginx, Railway, Fly,
// Kubernetes ingress) sees a loopback or private peer and behaves as before.
var defaultTrustedProxyCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fe80::/10",
	"fc00::/7",
}

// maxProxyMisconfigWarnings bounds the misconfiguration hint below. A directly
// exposed server sees spoof attempts continuously, and that is working as
// intended — the operator needs the hint once, not a running commentary.
const maxProxyMisconfigWarnings = 10

// ProxyTrust decides which peers may set client-identifying headers.
type ProxyTrust struct {
	nets     []*net.IPNet
	trustAll bool
	warnings atomic.Int32
}

// NewProxyTrust parses a comma-separated list of CIDRs and bare IPs. Invalid
// entries are logged and skipped rather than fatal: a typo in one entry should
// narrow trust, not take the server down.
func NewProxyTrust(spec string) *ProxyTrust {
	t := &ProxyTrust{}
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" || strings.EqualFold(entry, "none") {
			continue
		}
		if entry == "*" {
			t.trustAll = true
			continue
		}
		// Accept a bare IP as a single-host range.
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				log.Printf("warning: ignoring invalid TRUSTED_PROXIES entry %q", raw)
				continue
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			entry = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			log.Printf("warning: ignoring invalid TRUSTED_PROXIES entry %q: %v", raw, err)
			continue
		}
		t.nets = append(t.nets, network)
	}
	return t
}

// ProxyTrustFromEnv builds the trust set from TRUSTED_PROXIES, falling back to
// the private/loopback defaults when the variable is not set at all. An
// explicitly empty value means "trust nothing", which is why this distinguishes
// unset from empty.
func ProxyTrustFromEnv() *ProxyTrust {
	spec, ok := os.LookupEnv("TRUSTED_PROXIES")
	if !ok {
		spec = strings.Join(defaultTrustedProxyCIDRs, ",")
	}
	return NewProxyTrust(spec)
}

// Describe renders the trust set for the startup log.
func (t *ProxyTrust) Describe() string {
	if t.trustAll {
		return "* (all peers)"
	}
	if len(t.nets) == 0 {
		return "none (forwarding headers ignored)"
	}
	parts := make([]string, 0, len(t.nets))
	for _, n := range t.nets {
		parts = append(parts, n.String())
	}
	return strings.Join(parts, ", ")
}

// trusts reports whether an address belongs to a configured proxy.
func (t *ProxyTrust) trusts(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if t.trustAll {
		return true
	}
	for _, n := range t.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// PeerTrusted reports whether the immediate peer may speak for another client.
func (t *ProxyTrust) PeerTrusted(r *http.Request) bool {
	return t.trusts(net.ParseIP(hostOnly(r.RemoteAddr)))
}

// TrustedHeader returns a header value only when the peer is a trusted proxy,
// and "" otherwise. Used for X-JA3-Hash: a client free to state its own TLS
// fingerprint would simply present a stock Chrome one and erase the signal.
func (t *ProxyTrust) TrustedHeader(r *http.Request, name string) string {
	if !t.PeerTrusted(r) {
		return ""
	}
	return r.Header.Get(name)
}

// ClientIP resolves the address to attribute the request to. Forwarding headers
// are read only when the peer is trusted; otherwise the socket address wins.
func (t *ProxyTrust) ClientIP(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	if normalized := normalizeIP(peer); normalized != "" {
		peer = normalized
	}
	if !t.trusts(net.ParseIP(peer)) {
		t.warnUntrustedForwarding(peer, r)
		return peer
	}

	// A trusted proxy sets X-Real-IP to the address it accepted the connection
	// from, so it needs no chain walking.
	if realIP := normalizeIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); realIP != "" {
		return realIP
	}

	// Otherwise walk X-Forwarded-For right to left. Each proxy appends the peer
	// it saw, so the rightmost entries are the ones our own infrastructure
	// wrote. The first entry that is not a proxy we trust is the closest thing
	// to a real client; everything to its left was supplied by that client and
	// cannot be believed.
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			entry := strings.TrimSpace(parts[i])
			if entry == "" {
				continue
			}
			ip := normalizeIP(hostOnly(entry))
			if ip == "" {
				// A malformed hop makes everything to its left unreadable, so
				// stop and fall back to the peer rather than guess.
				break
			}
			if t.trusts(net.ParseIP(ip)) {
				continue
			}
			return ip
		}
	}

	return peer
}

// warnUntrustedForwarding flags the one misconfiguration this design can cause.
// A peer that sends forwarding headers but is not in the trust set is either a
// real reverse proxy the operator forgot to list — in which case every visitor
// is now collapsed onto that proxy's address, silently wrecking rate limiting
// and IP reputation — or a client spoofing them, which is exactly what we want
// ignored. The two are indistinguishable here, so say both and name the peer so
// it can be pasted into TRUSTED_PROXIES.
func (t *ProxyTrust) warnUntrustedForwarding(peer string, r *http.Request) {
	if r.Header.Get("X-Forwarded-For") == "" && r.Header.Get("X-Real-IP") == "" {
		return
	}
	count := t.warnings.Add(1)
	if count > maxProxyMisconfigWarnings {
		return
	}
	suffix := ""
	if count == maxProxyMisconfigWarnings {
		suffix = " (further warnings suppressed)"
	}
	log.Printf("warning: ignoring forwarding headers from untrusted peer %s. "+
		"If that is your reverse proxy, add it to TRUSTED_PROXIES — until then every "+
		"visitor is attributed to %s. If not, a client is spoofing them and they are "+
		"correctly ignored.%s", peer, peer, suffix)
}

// normalizeIP validates an address and renders IPv4-mapped IPv6 (::ffff:1.2.3.4)
// in dotted form so the CIDR checks in detection.go match either spelling.
// Returns "" when the value is not an IP.
func normalizeIP(s string) string {
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// hostOnly strips a trailing :port or wrapping brackets from an address.
// http.Request.RemoteAddr always carries a port; header values usually do not.
func hostOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.Trim(addr, "[]")
}
