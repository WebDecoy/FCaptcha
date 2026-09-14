package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type admissionEntry struct {
	count   int
	expires time.Time
}
type AdmissionLimiter struct {
	mu          sync.Mutex
	entries     map[string]admissionEntry
	nextCleanup time.Time
	redis       *redis.Client
}

func newAdmissionLimiter(client *redis.Client) *AdmissionLimiter {
	return &AdmissionLimiter{entries: make(map[string]admissionEntry), redis: client}
}

var admissionScript = redis.NewScript(`
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if count >= tonumber(ARGV[1]) then return 0 end
redis.call('INCR', KEYS[1])
if count == 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return 1
`)

func (a *AdmissionLimiter) Allow(key string, maximum int, seconds int) (bool, error) {
	if a.redis != nil {
		result, err := admissionScript.Run(context.Background(), a.redis, []string{redisOpaqueKey("admission", key)}, maximum, seconds*1000).Int()
		return result == 1, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if !now.Before(a.nextCleanup) {
		for k, entry := range a.entries {
			if !now.Before(entry.expires) {
				delete(a.entries, k)
			}
		}
		a.nextCleanup = now.Add(time.Minute)
	}
	entry, ok := a.entries[key]
	if ok && !now.Before(entry.expires) {
		delete(a.entries, key)
		ok = false
	}
	if !ok {
		if len(a.entries) >= 100000 {
			return false, nil
		}
		entry = admissionEntry{expires: now.Add(time.Duration(seconds) * time.Second)}
	}
	if entry.count >= maximum {
		return false, nil
	}
	entry.count++
	a.entries[key] = entry
	return true, nil
}
func admissionMiddleware(engine *ScoringEngine, trust *ProxyTrust) func(http.Handler) http.Handler {
	limiter := newAdmissionLimiter(engine.redisClient)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/siteverify") || strings.HasPrefix(path, "/turnstile/") || strings.HasPrefix(path, "/recaptcha/") {
				ip := trust.ClientIP(r)
				quotas := []struct {
					key string
					max int
				}{{"global", 20000}, {"source:" + ip, 600}}
				if path == "/api/pow/challenge" {
					quotas = append(quotas, struct {
						key string
						max int
					}{"challenge:" + ip, 60})
				}
				for _, quota := range quotas {
					allowed, err := limiter.Allow(quota.key, quota.max, 60)
					if err != nil {
						http.Error(w, `{"error":"state_unavailable"}`, 503)
						return
					}
					if !allowed {
						w.Header().Set("Retry-After", "60")
						http.Error(w, `{"error":"rate_limited"}`, 429)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
func (e *ScoringEngine) ipBinding(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil {
		ip = parsed.String()
	}
	derive := hmac.New(sha256.New, []byte(e.secretKey))
	derive.Write([]byte("fcaptcha:ip-binding:v2"))
	mac := hmac.New(sha256.New, derive.Sum(nil))
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil))
}
