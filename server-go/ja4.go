package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// JA4 TLS client fingerprinting, computed natively from the ClientHello.
//
// # Scope, and a licensing line not to cross
//
// This implements **JA4 (TLS) only**. JA4 is published under BSD-3-Clause and
// FoxIO explicitly disclaims patent coverage for it, which is what makes it
// safe to ship in an MIT project that people deploy commercially.
//
// The rest of the family — JA4H (HTTP), JA4T, JA4L, JA4S, JA4X, JA4SSH — is
// licensed under FoxIO License 1.1: non-commercial use only, patent-pending on
// the detection logic, and incompatible with GPL/AGPL. FoxIO's FAQ is explicit
// that indirect monetization requires an OEM licence. **Do not add them here.**
// If you want header-order or RTT heuristics, derive them from first principles
// — a header-order signature is SHA256 over the lowercased names in order plus
// a casing flag, about fifteen lines, and owes nothing to anyone.
//
// # Where this works, and where it does not
//
// It reads the ClientHello, so it only produces a fingerprint when *this
// process* terminates TLS. Behind Railway, Cloudflare, nginx or any other
// terminating proxy the ClientHello was consumed upstream and there is nothing
// here to read — those deployments must keep using the trusted-header path
// (TRUSTED_JA4_HEADERS), which is unchanged and remains the default.
//
// That covers the single-binary self-hosted case FCaptcha advertises, and
// nothing else. It is not a replacement for the header path; it is the option
// for people who do not have a proxy to read the header from.
//
// # Why Go 1.24
//
// crypto/tls only began exposing the ClientHello extension list in 1.24
// (ClientHelloInfo.Extensions, golang/go#32936). Without it the extension hash
// cannot be computed and JA4 is not derivable from the stdlib at all.

// GREASE values (RFC 8701) are random padding a client injects to keep the
// ecosystem tolerant of unknown values. They vary per connection by design, so
// including them would make the fingerprint different every time — the JA4 spec
// excludes them from every count and every list.
func isGREASE(v uint16) bool {
	// 0x0a0a, 0x1a1a, 0x2a2a ... 0xfafa: both bytes equal, low nibble 0xa.
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func filterGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// ja4TLSVersion renders the negotiated-or-highest-offered version as the two
// characters the spec uses.
func ja4TLSVersion(versions []uint16) string {
	best := uint16(0)
	for _, v := range filterGREASE(versions) {
		if v > best {
			best = v
		}
	}
	switch best {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

// ja4ALPN takes the first and last character of the first offered protocol:
// "h2" -> "h2", "http/1.1" -> "h1". Non-ASCII values fall back to the hex of
// those bytes, per the spec's note on non-printable ALPNs.
func ja4ALPN(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}
	p := protos[0]
	first, last := p[0], p[len(p)-1]

	printable := func(b byte) bool {
		return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
	}
	if printable(first) && printable(last) {
		return string([]byte{first, last})
	}
	return fmt.Sprintf("%x%x", first>>4, last&0x0f)
}

// twoDigit caps a count at 99, which is what the fixed-width JA4_a field allows.
func twoDigit(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func hexList(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// sha256First12 is the truncation the spec specifies for both hashed sections.
func sha256First12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ComputeJA4 builds the fingerprint from a ClientHello.
//
// Layout: ja4_a _ ja4_b _ ja4_c
//
//	ja4_a  transport, TLS version, SNI presence, cipher count, extension
//	       count, first ALPN — human-readable, 10 chars
//	ja4_b  truncated SHA-256 over the sorted cipher list
//	ja4_c  truncated SHA-256 over the sorted extension list, an underscore,
//	       and the signature algorithms in their original order
//
// Two asymmetries in the spec are deliberate and easy to get wrong: the
// extension *count* in ja4_a includes SNI and ALPN, while the extension *list*
// in ja4_c excludes them; and the signature algorithms are NOT sorted, because
// their order is itself characteristic of the client.
func ComputeJA4(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}

	ciphers := filterGREASE(hello.CipherSuites)
	extensions := filterGREASE(hello.Extensions)

	// "d" when the client sent SNI (a domain), "i" when it connected by IP.
	sni := "i"
	if hello.ServerName != "" {
		sni = "d"
	}

	// "t" for TCP. QUIC would be "q", but a net/http server reaching this code
	// path is TCP by construction.
	ja4a := "t" + ja4TLSVersion(hello.SupportedVersions) + sni +
		twoDigit(len(ciphers)) + twoDigit(len(extensions)) + ja4ALPN(hello.SupportedProtos)

	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	ja4b := sha256First12(hexList(sortedCiphers))

	// SNI (0x0000) and ALPN (0x0010) are excluded from the hashed list: they
	// carry per-request content rather than client identity, so including them
	// would make the same browser fingerprint differently per site.
	hashable := make([]uint16, 0, len(extensions))
	for _, e := range extensions {
		if e != 0x0000 && e != 0x0010 {
			hashable = append(hashable, e)
		}
	}
	sort.Slice(hashable, func(i, j int) bool { return hashable[i] < hashable[j] })

	sigAlgs := make([]uint16, 0, len(hello.SignatureSchemes))
	for _, s := range hello.SignatureSchemes {
		if !isGREASE(uint16(s)) {
			sigAlgs = append(sigAlgs, uint16(s))
		}
	}

	ja4c := sha256First12(hexList(hashable) + "_" + hexList(sigAlgs))

	return ja4a + "_" + ja4b + "_" + ja4c
}

// ja4Store keeps the fingerprint for the life of a connection.
//
// The ClientHello is only visible during the handshake, in a callback that has
// no request attached to it yet. So it is recorded against the connection there
// and read back when the request arrives on that same connection. Bounded, so a
// long-lived server cannot accumulate entries for connections that never
// produced a request.
type ja4Store struct {
	byConn *expirable.LRU[string, string]
}

// TLSConfigWithJA4 returns a tls.Config that records a JA4 fingerprint per
// connection, and a lookup the HTTP handler can use.
//
// GetConfigForClient is the hook: it fires once per handshake with the parsed
// ClientHello and is otherwise free to return nil, meaning "use the base
// config". Recording a fingerprint there is a side effect on the connection's
// remote address, which is the only stable key available at that point.
func TLSConfigWithJA4(base *tls.Config, store *ja4Store) *tls.Config {
	cfg := base.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.Conn != nil {
			store.Record(hello.Conn.RemoteAddr().String(), ComputeJA4(hello))
		}
		return nil, nil
	}
	return cfg
}

// ja4ConnTTL bounds how long a recorded fingerprint outlives its handshake.
// Keep-alive connections can serve requests for a while, but an entry that has
// not been read within this window belongs to a connection that handshook and
// then went quiet.
const ja4ConnTTL = 5 * time.Minute

// maxTrackedJA4Conns bounds the per-connection table. Generous next to any
// realistic count of simultaneously-open connections, small enough that the
// store cannot become a leak.
const maxTrackedJA4Conns = 20_000

func newJA4Store(max int) *ja4Store {
	return &ja4Store{byConn: expirable.NewLRU[string, string](max, nil, ja4ConnTTL)}
}

func (s *ja4Store) Record(remoteAddr, fp string) {
	if fp != "" {
		s.byConn.Add(remoteAddr, fp)
	}
}

func (s *ja4Store) Lookup(remoteAddr string) string {
	fp, _ := s.byConn.Get(remoteAddr)
	return fp
}
