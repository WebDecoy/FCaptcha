package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Bounds on server-side state keyed by client-supplied values.
//
// FCaptcha partitions rate-limit, fingerprint and challenge state by siteKey,
// which no server validates against any registry — the only existing check is
// that a PoW solution's siteKey matches its own challenge, which is internal
// consistency, not registration. Every partition key therefore begins with a
// string the caller chose:
//
//	pow:{siteKey}:{ip}   PoW difficulty escalation
//	{siteKey}:{ip}       rate-abuse detection
//	{siteKey}:{fp}       fingerprint reuse
//
// A caller varying siteKey per request allocates unbounded map entries. This is
// not a detection bypass — obtaining a challenge for site X requires asking with
// siteKey=X, which lands in X's bucket — but it is a memory-exhaustion vector.
//
// SiteKeyGuard caps how many distinct siteKeys one IP may allocate state for and
// folds the excess into a single overflow bucket. Folding rather than rejecting
// has a useful property: a caller rotating siteKeys to dodge rate limiting ends
// up sharing one bucket, so requests accumulate against it faster than with a
// single honest key. The evasion makes the limit bite harder.
//
// Mirrors server-node/limits.js.

const (
	// Distinct siteKeys one IP may allocate state for. A browser uses exactly
	// one; a shared NAT egress or CDN might carry a handful.
	defaultMaxSiteKeysPerIP = 8

	// Where excess or unlisted siteKeys are filed. Deliberately not a valid key
	// shape so it cannot collide with a real one.
	overflowSiteKey = " overflow"

	// Bound on the tracking table itself, so the guard cannot become the leak
	// it prevents.
	maxTrackedSiteKeyIPs = 50_000
	siteKeyWindow        = time.Hour
)

type siteKeySet struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

// SiteKeyGuard bounds distinct siteKeys per source IP and optionally restricts
// them to an allowlist.
type SiteKeyGuard struct {
	allowlist map[string]struct{} // nil = accept any key
	maxPerIP  int
	seen      *expirable.LRU[string, *siteKeySet]
}

// NewSiteKeyGuard builds a guard. An empty allowlist means no allowlist, which
// is the default and preserves zero-config self-hosting.
func NewSiteKeyGuard(allowlist []string, maxPerIP int) *SiteKeyGuard {
	g := &SiteKeyGuard{maxPerIP: maxPerIP}
	if g.maxPerIP <= 0 {
		g.maxPerIP = defaultMaxSiteKeysPerIP
	}
	if len(allowlist) > 0 {
		g.allowlist = make(map[string]struct{}, len(allowlist))
		for _, k := range allowlist {
			if k = strings.TrimSpace(k); k != "" {
				g.allowlist[k] = struct{}{}
			}
		}
	}
	g.seen = expirable.NewLRU[string, *siteKeySet](maxTrackedSiteKeyIPs, nil, siteKeyWindow)
	return g
}

// SiteKeyGuardFromEnv reads FCAPTCHA_SITE_KEYS (comma-separated allowlist,
// unset = any) and FCAPTCHA_MAX_SITE_KEYS_PER_IP.
func SiteKeyGuardFromEnv() *SiteKeyGuard {
	var allowlist []string
	if raw := os.Getenv("FCAPTCHA_SITE_KEYS"); raw != "" {
		allowlist = strings.Split(raw, ",")
	}
	maxPerIP := 0
	if raw := os.Getenv("FCAPTCHA_MAX_SITE_KEYS_PER_IP"); raw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
			maxPerIP = n
		} else {
			log.Printf("warning: ignoring invalid FCAPTCHA_MAX_SITE_KEYS_PER_IP %q", raw)
		}
	}
	return NewSiteKeyGuard(allowlist, maxPerIP)
}

// Describe renders the configuration for the startup log.
func (g *SiteKeyGuard) Describe() string {
	list := "any (no allowlist)"
	if g.allowlist != nil {
		list = strconv.Itoa(len(g.allowlist)) + " allowlisted"
	}
	return list + ", max " + strconv.Itoa(g.maxPerIP) + " distinct per IP"
}

// Normalize returns the siteKey state should be filed under. It never rejects a
// request: an over-quota caller is folded into the overflow bucket, which bounds
// state while leaving the request answerable.
func (g *SiteKeyGuard) Normalize(siteKey, ip string) string {
	key := siteKey
	if key == "" {
		key = "default"
	}
	if g.allowlist != nil {
		if _, ok := g.allowlist[key]; !ok {
			return overflowSiteKey
		}
	}
	if ip == "" {
		return key
	}

	set, ok := g.seen.Get(ip)
	if !ok {
		set = &siteKeySet{keys: make(map[string]struct{}, g.maxPerIP)}
		g.seen.Add(ip, set)
	}

	set.mu.Lock()
	defer set.mu.Unlock()
	if _, seen := set.keys[key]; seen {
		return key
	}
	if len(set.keys) >= g.maxPerIP {
		return overflowSiteKey
	}
	set.keys[key] = struct{}{}
	return key
}
