package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	webbotauth "github.com/WebDecoy/web-bot-auth"
	"github.com/WebDecoy/web-bot-auth/httpsig"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

// The upstream verifier caches forever by directory URL. Give each single-agent
// header its own verifier, and retain at most sixteen. A verifier can resolve
// only one directory/JWKS URL; CIMD is not resolved by this dependency.
type directoryVerifier struct {
	mu         sync.Mutex
	verifier   *webbotauth.Verifier
	retryAfter time.Time
}
type boundedBotAuth struct {
	mu      sync.Mutex
	entries *expirable.LRU[string, *directoryVerifier]
	slots   chan struct{}
	client  *http.Client
}

type directoryTransport struct{ base http.RoundTripper }

func (t directoryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusOK {
		return response, err
	}
	const maximum = 256 * 1024
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > maximum {
		return nil, fmt.Errorf("bot directory exceeds size limit")
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

func newBoundedBotAuth() *boundedBotAuth {
	// Share one bounded connection pool across evicted verifiers. A transport
	// per cache entry would otherwise retain idle sockets after eviction.
	dialer := &net.Dialer{Timeout: 2 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("refusing non-public bot directory address")
		}
		if v4 := ip.To4(); v4 != nil && (v4[0] == 0 || v4[0] >= 224 || (v4[0] == 100 && v4[1]&0xc0 == 64)) {
			return fmt.Errorf("refusing non-public bot directory address")
		}
		return nil
	}}
	client := &http.Client{Timeout: webBotAuthTimeout, Transport: directoryTransport{base: &http.Transport{
		DialContext: dialer.DialContext, MaxIdleConns: 16, MaxIdleConnsPerHost: 2,
		MaxConnsPerHost: 2, IdleConnTimeout: 30 * time.Second,
		TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second,
	}}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &boundedBotAuth{entries: expirable.NewLRU[string, *directoryVerifier](16, nil, time.Hour), slots: make(chan struct{}, 8), client: client}
}
func singleAgent(header string) bool {
	if len(header) > 2048 || header == "" {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(header), `"`) {
		// A bare structured string cannot contain another member or escaped quote.
		return strings.Count(header, `"`) == 2 && !strings.Contains(header, `\`)
	}
	members, err := httpsig.ParseDictionaryHeader(header)
	return err == nil && len(members) == 1
}
func (b *boundedBotAuth) Verify(ctx context.Context, req *httpsig.Request) *webbotauth.Result {
	header := strings.Join(req.Header.Values("Signature-Agent"), ", ")
	if !singleAgent(header) {
		return nil
	}
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		return nil
	}
	b.mu.Lock()
	entry, ok := b.entries.Get(header)
	if !ok {
		entry = &directoryVerifier{verifier: webbotauth.NewVerifier(webbotauth.WithOpenDirectories(), webbotauth.WithHTTPClient(b.client))}
		b.entries.Add(header, entry)
	}
	b.mu.Unlock()
	// Coalesce discovery: concurrent callers wait only within their request's
	// timeout; no unbounded waiter queue is possible because of the eight slots.
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if ctx.Err() != nil || time.Now().Before(entry.retryAfter) {
		return nil
	}
	result := entry.verifier.Verify(ctx, req)
	if result.Status != webbotauth.StatusVerified && !webBotAuthForged(result.Errors) {
		entry.retryAfter = time.Now().Add(30 * time.Second)
	}
	return result
}
