package main

import (
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Adaptive challenge cost: what a source pays is a function of what that source
// has recently been caught doing, rather than a constant.
//
// # Why the cost is mostly time, not hashing
//
// A constant difficulty is strictly dominated: it either fails to inconvenience
// an attacker or it does hurt real users. The measurements behind that claim:
// browser JS runs 1-3M hash/s, native code 100-500M/s, so difficulty 6 costs a
// native solver about a millisecond and a budget Android phone about sixteen
// seconds. Raising difficulty is close to a pure tax on the slowest legitimate
// devices.
//
// Wall-clock is the knob that does not have that property. Nobody can make less
// time pass, so a minimum challenge age caps how fast one source can mint
// tokens no matter what hardware it brings. So suspicion moves the time floor
// first and difficulty barely at all.
//
// # What this deliberately is not
//
// This is not Workstream F 10.1 (cross-session correlation). It stores strong-
// verdict timestamps per source, nothing else: no behavioral vectors, no
// per-fingerprint history, no traces that survive the window. It is the same
// shape and the same privacy class as the rate limiter sitting next to it, and
// it should stay that way — 10.1 has a privacy load this does not, and the two
// should not be conflated because they happen to both be "server-side memory".

const (
	// suspicionStrongScore is the verdict score at or above which a
	// verification counts as evidence. Deliberately high: a marginal verdict is
	// exactly the case where the scoring might be wrong about a real person, and
	// making the next person from that address wait is not worth the guess.
	suspicionStrongScore = 0.8

	// suspicionWindow is how long a strong verdict keeps counting. Short enough
	// that a shared egress address recovers on its own within a coffee break.
	suspicionWindow = 15 * time.Minute

	// suspicionMaxHits bounds the per-source slice. Only the count matters and
	// every tier saturates well below this, so there is nothing to gain from
	// remembering more.
	suspicionMaxHits = 16

	// suspicionMaxSources bounds the table. Sources with no strong verdicts
	// never get an entry at all, so this only has to cover addresses actively
	// failing verification.
	suspicionMaxSources = 50_000
)

// SuspicionLedger records recent strong verdicts per source.
//
// Entries are created only when a source produces a strong verdict, so the
// common case — a legitimate visitor — allocates nothing and looks up nothing
// but a miss.
type SuspicionLedger struct {
	mu   sync.Mutex
	hits *expirable.LRU[string, []int64]
}

func NewSuspicionLedger() *SuspicionLedger {
	return &SuspicionLedger{
		hits: expirable.NewLRU[string, []int64](suspicionMaxSources, nil, suspicionWindow),
	}
}

func suspicionKey(siteKey, ip string) string {
	return siteKey + "|" + ip
}

// Record notes a verdict. Scores below the strong threshold are ignored
// entirely rather than recorded and weighted, so a source that merely looks
// unusual never accumulates anything.
func (s *SuspicionLedger) Record(siteKey, ip string, score float64) {
	if s == nil || score < suspicionStrongScore || ip == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := suspicionKey(siteKey, ip)
	now := time.Now().UnixMilli()
	cutoff := now - suspicionWindow.Milliseconds()

	existing, _ := s.hits.Get(key)
	kept := make([]int64, 0, len(existing)+1)
	for _, t := range existing {
		if t > cutoff {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) > suspicionMaxHits {
		kept = kept[len(kept)-suspicionMaxHits:]
	}

	s.hits.Add(key, kept)
}

// Count returns how many strong verdicts this source produced inside the
// window. The LRU's TTL runs from the last write, so counting from the
// timestamps rather than trusting the entry's existence is what makes an old
// hit actually decay while newer ones keep the entry alive.
func (s *SuspicionLedger) Count(siteKey, ip string) int {
	if s == nil || ip == "" {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	hits, ok := s.hits.Get(suspicionKey(siteKey, ip))
	if !ok {
		return 0
	}

	cutoff := time.Now().UnixMilli() - suspicionWindow.Milliseconds()
	n := 0
	for _, t := range hits {
		if t > cutoff {
			n++
		}
	}
	return n
}

// ChallengeCost is what a source has to pay for a challenge.
type ChallengeCost struct {
	// Difficulty is the leading-zero count the PoW hash must reach.
	Difficulty int
	// MinAgeMs is how old the challenge must be before a solution for it is
	// accepted without penalty. The client is told this value and waits it out,
	// so for an honest client the cost is latency rather than a worse score.
	MinAgeMs int64
}

// Baseline cost. A clean visitor pays exactly this, which is what the server
// has always charged everyone.
const (
	baseDifficulty = 4
	baseMinAgeMs   = 1500
)

// maxDifficulty caps the compute knob at 5, below the 6 this server used to
// reach. Difficulty 6 buys about a millisecond of attacker time and spends
// about sixteen seconds of a budget phone's; the escalation belongs in MinAgeMs
// where an attacker cannot buy their way out of it.
const maxDifficulty = 5

// maxMinAgeMs caps the time knob at 15s. At the 1.5s baseline one address can
// mint roughly 40 tokens a minute; at 15s, four. Pushing further buys little
// and is felt by anyone sharing a poisoned egress address.
const maxMinAgeMs = 15_000

// ComputeChallengeCost maps accumulated suspicion onto a cost.
//
// Note what does NOT raise difficulty here: being on a datacenter address. That
// used to jump straight to difficulty 5, which charges a real person on a
// corporate VPN or iCloud Private Relay several seconds of blocked hashing on a
// slow phone for the offence of having a shared IP. It now moves the time floor
// instead, which a datacenter-hosted scraper feels as reduced throughput and a
// person filling in a form does not feel at all.
func ComputeChallengeCost(strongHits int, isDatacenter bool, requestCount int, rateExceeded bool) ChallengeCost {
	cost := ChallengeCost{Difficulty: baseDifficulty, MinAgeMs: baseMinAgeMs}

	switch {
	case strongHits >= 6:
		cost.Difficulty, cost.MinAgeMs = 5, 15_000
	case strongHits >= 3:
		cost.Difficulty, cost.MinAgeMs = 5, 8_000
	case strongHits >= 1:
		cost.MinAgeMs = 4_000
	}

	// Floors from signals that are suggestive rather than damning. They raise
	// the time floor and never the difficulty.
	raiseTo := func(ms int64) {
		if cost.MinAgeMs < ms {
			cost.MinAgeMs = ms
		}
	}
	if isDatacenter {
		raiseTo(3_000)
	}
	if requestCount > 10 {
		raiseTo(6_000)
	}
	if rateExceeded {
		raiseTo(10_000)
	}

	if cost.Difficulty > maxDifficulty {
		cost.Difficulty = maxDifficulty
	}
	if cost.MinAgeMs > maxMinAgeMs {
		cost.MinAgeMs = maxMinAgeMs
	}
	return cost
}
