package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	webbotauth "github.com/WebDecoy/web-bot-auth"
	"github.com/WebDecoy/web-bot-auth/httpsig"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/redis/go-redis/v9"
)

// ThreatCategory represents types of detected threats
type ThreatCategory string

const (
	CategoryVisionAI    ThreatCategory = "vision_ai"
	CategoryHeadless    ThreatCategory = "headless"
	CategoryAutomation  ThreatCategory = "automation"
	CategoryCDP         ThreatCategory = "cdp"
	CategoryBot         ThreatCategory = "bot"
	CategoryCaptchaFarm ThreatCategory = "captcha_farm"
	CategoryBehavioral  ThreatCategory = "behavioral"
	CategoryFingerprint ThreatCategory = "fingerprint"
	CategoryRateLimit   ThreatCategory = "rate_limit"
	CategoryDatacenter  ThreatCategory = "datacenter"
	CategoryTorVPN      ThreatCategory = "tor_vpn"
	CategoryDeclaredAI  ThreatCategory = "declared_ai"
)

// DetectionResult from a single check
type DetectionResult struct {
	Category   ThreatCategory
	Score      float64
	Confidence float64
	Reason     string
	Details    map[string]interface{}

	// Dispositive marks a signal a browser cannot produce without being
	// automated, as opposed to one that merely correlates with automation.
	// It triggers dispositiveFloor. See applyDispositiveFloor.
	Dispositive bool
}

// VerificationResult is the final result
type VerificationResult struct {
	Success        bool
	Score          float64
	Token          string
	Timestamp      int64
	Detections     []DetectionResult
	CategoryScores map[string]float64
	Recommendation string
	// Reason explains a token withheld for something other than the score:
	// "pow_not_satisfied" or "hostname_not_allowed". Empty otherwise. Without it
	// an integrator whose score is comfortably under the threshold has no way to
	// tell why no token came back.
	Reason string
}

// PoWChallenge for server-verified proof of work
type PoWChallenge struct {
	ID         string `json:"challengeId"`
	SiteKey    string `json:"siteKey"`
	Prefix     string `json:"prefix"`
	Difficulty int    `json:"difficulty"`
	Timestamp  int64  `json:"timestamp"`
	ExpiresAt  int64  `json:"expiresAt"`
	Nonce      string `json:"nonce"`
	Sig        string `json:"sig"`
	// MinAgeMs is how old this challenge must be before its solution is
	// accepted without penalty. Sent to the client, which waits it out, and
	// covered by Sig so it cannot be lowered on the way back.
	MinAgeMs int64  `json:"minAgeMs"`
	IP       string `json:"ip"` // Stored server-side; HTTP response uses a separate DTO.
}

// PoWSolution from client
type PoWSolution struct {
	ChallengeID string `json:"challengeId"`
	Nonce       int    `json:"nonce"`
	Hash        string `json:"hash"`
	SignalsHash string `json:"signalsHash,omitempty"`
}

// PoWVerifyResult is the result of PoW verification
type PoWVerifyResult struct {
	Valid         bool
	Reason        string
	Difficulty    int
	ServerElapsed int64
	Nonce         string
	// MinAgeMs is the floor this particular challenge was issued with, which
	// varies with how suspicious the source was at the time.
	MinAgeMs int64
}

// PoWChallengeStore manages challenges and replay-protects spent solutions.
// usedSolutions is a bounded LRU with TTL — under attack it caps memory and
// evicts the oldest entries, instead of the previous behavior of wiping all
// entries when count crossed a threshold (which opened a replay window).
type PoWChallengeStore struct {
	mu            sync.RWMutex
	challenges    map[string]*PoWChallenge
	usedSolutions *expirable.LRU[string, struct{}]
	redis         *redis.Client
}

const (
	usedSolutionsCap = 100_000
	usedSolutionsTTL = 10 * time.Minute
)

func newPoWChallengeStore() *PoWChallengeStore {
	store := &PoWChallengeStore{
		challenges:    make(map[string]*PoWChallenge),
		usedSolutions: expirable.NewLRU[string, struct{}](usedSolutionsCap, nil, usedSolutionsTTL),
	}
	// Start cleanup goroutine
	go store.cleanupLoop()
	return store
}

func newRedisPoWChallengeStore(client *redis.Client) *PoWChallengeStore {
	return &PoWChallengeStore{redis: client}
}

const redisStatePrefix = "fcaptcha:v1:"

func (s *PoWChallengeStore) putChallenge(challenge *PoWChallenge) error {
	if s.redis == nil {
		s.mu.Lock()
		s.challenges[challenge.ID] = challenge
		s.mu.Unlock()
		return nil
	}
	payload, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	ttl := time.Until(time.UnixMilli(challenge.ExpiresAt))
	if ttl <= 0 {
		return fmt.Errorf("challenge already expired")
	}
	return s.redis.Set(context.Background(), redisStatePrefix+"pow:challenge:"+challenge.ID, payload, ttl).Err()
}

func (s *PoWChallengeStore) getChallenge(id string) (*PoWChallenge, error) {
	if s.redis == nil {
		s.mu.RLock()
		defer s.mu.RUnlock()
		challenge := s.challenges[id]
		return challenge, nil
	}
	payload, err := s.redis.Get(context.Background(), redisStatePrefix+"pow:challenge:"+id).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var challenge PoWChallenge
	if err := json.Unmarshal(payload, &challenge); err != nil {
		return nil, err
	}
	return &challenge, nil
}

var claimRedisChallenge = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[1]) == false then return -1 end
redis.call('DEL', KEYS[1])
return 1
`)

// claimChallenge atomically consumes a challenge and records the winning
// solution. This is the cross-instance replay boundary: exactly one verifier
// may turn an issued challenge into a token.
func (s *PoWChallengeStore) claimChallenge(challengeID, solutionKey string) (bool, string, error) {
	if s.redis == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.challenges[challengeID]; !ok {
			return false, "challenge_not_found", nil
		}
		if s.usedSolutions.Contains(solutionKey) {
			return false, "solution_already_used", nil
		}
		s.usedSolutions.Add(solutionKey, struct{}{})
		delete(s.challenges, challengeID)
		return true, "", nil
	}
	keys := []string{
		redisStatePrefix + "pow:challenge:" + challengeID,
		redisStatePrefix + "pow:spent:" + solutionKey,
	}
	result, err := claimRedisChallenge.Run(context.Background(), s.redis, keys, usedSolutionsTTL.Milliseconds()).Int()
	if err != nil {
		return false, "", err
	}
	switch result {
	case 1:
		return true, "", nil
	case -1:
		return false, "solution_already_used", nil
	default:
		return false, "challenge_not_found", nil
	}
}

func (s *PoWChallengeStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		s.cleanup()
	}
}

func (s *PoWChallengeStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UnixMilli()
	for id, challenge := range s.challenges {
		if now > challenge.ExpiresAt {
			delete(s.challenges, id)
		}
	}
	// usedSolutions evicts via cap + TTL; no manual sweep needed.
}

// IsSolutionUsed is a non-locking best-effort early-out to reject obvious
// replays before doing any hash verification work. The authoritative
// test-and-set is MarkSolutionUsed.
func (s *PoWChallengeStore) IsSolutionUsed(key string) bool {
	if s.redis != nil {
		exists, err := s.redis.Exists(context.Background(), redisStatePrefix+"pow:spent:"+key).Result()
		return err == nil && exists > 0
	}
	return s.usedSolutions.Contains(key)
}

// MarkSolutionUsed atomically claims a (challengeID, nonce) pair, returning
// false if another caller already marked it (treat as replay).
func (s *PoWChallengeStore) MarkSolutionUsed(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usedSolutions.Contains(key) {
		return false
	}
	s.usedSolutions.Add(key, struct{}{})
	return true
}

// DeleteChallenge removes a one-time challenge after it has been spent.
func (s *PoWChallengeStore) DeleteChallenge(id string) {
	if s.redis != nil {
		_ = s.redis.Del(context.Background(), redisStatePrefix+"pow:challenge:"+id).Err()
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.challenges, id)
}

// Legacy Challenge for backward compatibility
type Challenge struct {
	ID         string
	Difficulty int
	Expires    int64
}

// ScoringEngine handles all verification
type ScoringEngine struct {
	secretKey        string
	rateLimiter      *RateLimiter
	fingerprintStore *FingerprintStore
	powStore         *PoWChallengeStore
	tokenStore       *TokenStore
	suspicion        *SuspicionLedger
	weights          map[ThreatCategory]float64
	uaPatterns       []*regexp.Regexp
	webBotAuth       *webbotauth.Verifier
	// Which page origins may mint tokens. Unrestricted unless the operator sets
	// FCAPTCHA_ALLOWED_HOSTNAMES; see siteverify.go.
	allowedHostnames *HostnameAllowlist
}

// webBotAuthTimeout bounds the whole Web Bot Auth verification, including the
// one-time SSRF-guarded fetch of an agent's key directory. The verifier caches
// directories, so only the first request for a new signer pays this cost; keep
// it short so a slow or hostile directory can never stall the scoring path.
const webBotAuthTimeout = 3 * time.Second

// RateLimiter tracks request rates
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string][]int64
}

// FingerprintStore tracks fingerprint patterns
type FingerprintStore struct {
	mu             sync.RWMutex
	fingerprints   map[string]*FingerprintData
	ipFingerprints map[string]map[string]bool
}

type FingerprintData struct {
	FirstSeen int64
	Count     int
	IPs       map[string]bool
}

// TokenStore prevents token replay attacks. Backed by a bounded LRU with TTL
// so the store size is capped under sustained load and the previous O(n)
// inline cleanup (which scanned the whole map under the write lock on every
// 100th insert past 1000) is gone.
type TokenStore struct {
	mu    sync.Mutex
	cache *expirable.LRU[string, struct{}]
}

const (
	usedTokensCap = 100_000
	usedTokensTTL = 10 * time.Minute
)

func newTokenStore() *TokenStore {
	return &TokenStore{
		cache: expirable.NewLRU[string, struct{}](usedTokensCap, nil, usedTokensTTL),
	}
}

func (t *TokenStore) IsUsed(sig string) bool {
	return t.cache.Contains(sig)
}

func (t *TokenStore) MarkUsed(sig string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cache.Contains(sig) {
		return false
	}
	t.cache.Add(sig, struct{}{})
	return true
}

// NewScoringEngine creates a new engine
func NewScoringEngine(secretKey string) *ScoringEngine {
	return &ScoringEngine{
		secretKey:        secretKey,
		rateLimiter:      newRateLimiter(),
		fingerprintStore: newFingerprintStore(),
		powStore:         newPoWChallengeStore(),
		tokenStore:       newTokenStore(),
		suspicion:        NewSuspicionLedger(),
		weights: map[ThreatCategory]float64{
			CategoryVisionAI:    0.15,
			CategoryHeadless:    0.15,
			CategoryAutomation:  0.08,
			CategoryCDP:         0.12,
			CategoryBehavioral:  0.18,
			CategoryFingerprint: 0.08,
			CategoryRateLimit:   0.01,
			CategoryDatacenter:  0.07,
			CategoryTorVPN:      0.01,
			CategoryBot:         0.13,
			CategoryDeclaredAI:  0.02,
		},
		uaPatterns:       compileUAPatterns(),
		allowedHostnames: HostnameAllowlistFromEnv(),
		// Open directories: FCaptcha wants to attempt verification of ANY
		// claimed agent identity — the interesting outcome is a signature that
		// claims an identity and fails to prove it. An allowlist would silently
		// skip unknown spoofers. The default fetch client is SSRF-guarded
		// (https-only, refuses loopback/private/link-local, size-capped,
		// re-validated per redirect hop) and caches directories.
		webBotAuth: webbotauth.NewVerifier(webbotauth.WithOpenDirectories()),
	}
}

// NewScoringEngineWithRedis creates engine with Redis backend
func NewScoringEngineWithRedis(secretKey, redisURL string) *ScoringEngine {
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		panic(fmt.Sprintf("invalid REDIS_URL: %v", err))
	}
	client := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		panic(fmt.Sprintf("REDIS_URL is configured but unavailable: %v", err))
	}
	engine := NewScoringEngine(secretKey)
	engine.powStore = newRedisPoWChallengeStore(client)
	return engine
}

func newRateLimiter() *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]int64),
	}
}

func newFingerprintStore() *FingerprintStore {
	return &FingerprintStore{
		fingerprints:   make(map[string]*FingerprintData),
		ipFingerprints: make(map[string]map[string]bool),
	}
}

func compileUAPatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)headless`,
		`(?i)phantomjs`,
		`(?i)selenium`,
		`(?i)webdriver`,
		`(?i)puppeteer`,
		`(?i)playwright`,
		`(?i)cypress`,
		`(?i)nightwatch`,
		`(?i)zombie`,
		`(?i)electron`,
		`(?i)chromium.*headless`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

// VerifyWithHeaders performs full verification with HTTP headers. preDetections
// are detections computed by the caller (the HTTP layer) that require the raw
// request — currently Web Bot Auth signature verification, which needs the
// accurately-reconstructed signed request. They are seeded into the detection
// set so they participate in scoring like any engine-produced detection.
// nativeJA4 is a fingerprint this process computed from the ClientHello (see
// ja4.go), empty when something upstream terminated TLS.
//
// binding carries what the issued token should be bound to beyond its score.
// Only Action and CData are read from it: Hostname is derived here from the
// request headers, because a caller that could state the hostname could state
// any hostname, which is exactly what the binding exists to prevent.
//
// NOTE: this parameter list has now grown four times and is overdue a
// request-context struct. Left positional for now so the vendored copy in
// fcaptcha-cloud stays a straight file copy rather than a port.
func (e *ScoringEngine) VerifyWithHeaders(signals map[string]interface{}, ip, siteKey, userAgent string, headers map[string]string, ja3Hash, nativeJA4 string, peerTrusted bool, preDetections []DetectionResult, binding TokenBinding, powSolution ...*PoWSolution) *VerificationResult {
	detections := make([]DetectionResult, 0, len(preDetections)+8)
	detections = append(detections, preDetections...)

	// Verify PoW if provided.
	//
	// powSatisfied records whether the caller actually completed the challenge
	// this server issued. It gates token issuance below rather than only feeding
	// the score, because a proof of work is a precondition, not evidence: the
	// widget solves one on every path and aborts rather than submit without it,
	// so a request that arrives without a valid solution did not come from the
	// widget at all.
	//
	// Scoring it alone was not enough. The final score is a weighted sum, so the
	// bot category contributes at most its 0.13 weight — every PoW failure
	// firing at once reached 0.1298 against a 0.5 threshold, and a bare `curl`
	// with no solution and no signals was issued a valid token. The detections
	// were all correct; the aggregation discarded them.
	var pow *PoWSolution
	if len(powSolution) > 0 {
		pow = powSolution[0]
	}
	powSatisfied := false
	if pow != nil && pow.ChallengeID != "" {
		powResult := e.VerifyPoWSolutionFromIP(pow, siteKey, ip, pow.SignalsHash)
		if !powResult.Valid {
			detections = append(detections, DetectionResult{
				Category:   CategoryBot,
				Score:      0.7,
				Confidence: 0.8,
				Reason:     "PoW verification failed: " + powResult.Reason,
				// Deliberately NOT Dispositive.
				//
				// The gate above already withholds the token, which is the whole
				// security requirement. Flooring the score as well says "this
				// visitor is a blatant bot", and a failed proof of work does not
				// mean that: a challenge expires after five minutes, challenges
				// live only in memory so every deploy invalidates the
				// outstanding ones, and a double-click replays a solution. All
				// three are ordinary things that happen to real people with a
				// tab left open.
				//
				// Marking this dispositive turned each of them into a hard block
				// at 0.9. It did so on the project's own demo site, to its
				// author, in an ordinary browser.
			})
		} else {
			powSatisfied = true
		}

		// Verify challenge nonce binding
		if powResult.Valid && powResult.Nonce != "" {
			clientNonce := ""
			if meta := getMap(signals, "meta"); meta != nil {
				clientNonce = getString(meta, "challengeNonce")
			}
			if clientNonce == "" || clientNonce != powResult.Nonce {
				// The solution verifies but the signals it commits to are not
				// the ones presented, so the work was done for a different
				// payload. Revokes the pass granted above.
				powSatisfied = false
				detections = append(detections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.9,
					Confidence: 0.9,
					Reason:     "Challenge nonce mismatch (signals not bound to challenge)",
					// Not dispositive, for the same reason as above: the gate
					// already refuses the token, and a stale challenge produces
					// this too.
				})
			}
		}

		// Two thresholds, because they mean different things. Under the
		// universal baseline nothing legitimate can have happened: no human
		// completes an interaction that fast, so it scores as it always has.
		//
		// Between the baseline and this source's own elevated floor is weaker
		// evidence. A client that predates adaptive cost does not know to wait,
		// and neither does one served from a stale cache, so a full-strength
		// penalty there would punish the wrong people. It contributes instead.
		if powResult.Valid {
			switch {
			case powResult.ServerElapsed < baseMinAgeMs:
				detections = append(detections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.8,
					Confidence: 0.85,
					Reason:     fmt.Sprintf("Challenge solved too fast (%dms server-side)", powResult.ServerElapsed),
				})
			case powResult.ServerElapsed < powResult.MinAgeMs:
				detections = append(detections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.5,
					Confidence: 0.5,
					Reason:     fmt.Sprintf("Challenge submitted before the required delay for this source (%dms of %dms)", powResult.ServerElapsed, powResult.MinAgeMs),
				})
			}
		}
	} else {
		// No PoW solution provided - hard fail
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.9,
			Confidence: 0.95,
			Reason:     "No PoW solution provided",
			// Not dispositive. The gate refuses the token; inflating the score
			// on top of that only mislabels whoever hit a stale page.
		})
	}

	// Behavioral detectors
	detections = append(detections, e.detectVisionAI(signals)...)
	detections = append(detections, e.detectHeadless(signals, userAgent)...)
	detections = append(detections, e.detectStealthArtifacts(signals)...)
	detections = append(detections, e.detectAutomation(signals)...)
	detections = append(detections, e.detectCDP(signals)...)
	detections = append(detections, e.detectBehavioral(signals)...)
	// Input forensics v2 (PRD workstream C): typing cadence and modality, the
	// paste-shortcut/platform contradiction, scroll morphology, font coherence.
	detections = append(detections, e.detectInputForensics(signals)...)
	detections = append(detections, e.detectTouchAuthenticity(signals, userAgent)...)
	detections = append(detections, e.detectSensorEntropy(signals, userAgent)...)
	detections = append(detections, e.detectTouchKinematics(signals)...)
	detections = append(detections, e.detectFingerprint(signals, ip, siteKey)...)
	detections = append(detections, e.detectRateAbuse(ip, siteKey)...)

	// Network/infrastructure detectors
	detections = append(detections, e.CheckIPReputation(ip)...)
	detections = append(detections, e.CheckBrowserConsistency(userAgent, signals)...)
	detections = append(detections, e.CheckDeclaredAIAgent(userAgent, headers)...)

	// HTTP-level detectors
	if headers != nil {
		detections = append(detections, e.AnalyzeHeaders(headers, peerTrusted)...)
	}

	// TLS fingerprint (JA3) — client-supplied, spoofable
	if ja3Hash != "" {
		detections = append(detections, e.CheckJA3Fingerprint(ja3Hash)...)
	}

	// TLS fingerprint (JA4). Two sources, and the local one wins.
	//
	// A natively-computed fingerprint was derived from the ClientHello by this
	// process, so it cannot be asserted by anyone — not the client, and not a
	// misconfigured proxy either. The header path requires trusting whatever sits
	// in front of us to have computed it honestly, which is weaker, so it is only
	// consulted when there is no local fingerprint to use.
	ja4 := nativeJA4
	if ja4 == "" && headers != nil {
		if trustedJA4 := GetTrustedJA4HeaderNames(); len(trustedJA4) > 0 {
			ja4 = ReadJA4FromHeaders(headers, trustedJA4)
		}
	}
	if ja4 != "" {
		detections = append(detections, e.CheckJA4Fingerprint(ja4)...)
	}

	// Form interaction analysis (credential stuffing & spam detection)
	if formAnalysis, ok := signals["formAnalysis"].(map[string]interface{}); ok {
		// A visitor who moved a pointer or touched the screen has shown they are
		// there; that changes how a paste-only form fill should be read.
		detections = append(detections, e.AnalyzeFormInteraction(formAnalysis, hasHumanPresence(getMap(signals, "behavioral")))...)
	}

	// Calculate scores
	categoryScores := e.calculateCategoryScores(detections)
	finalScore := applyDispositiveFloor(e.calculateFinalScore(categoryScores), detections)
	finalScore = applyCorroborationFloor(finalScore, categoryScores)

	// Determine recommendation
	var recommendation string
	switch {
	case finalScore < 0.3:
		recommendation = "allow"
	case finalScore < 0.6:
		recommendation = "challenge"
	default:
		recommendation = "block"
	}

	// The hostname comes from the request headers rather than the caller: it is
	// what the browser reported about the page, not what the page claimed about
	// itself. Overriding whatever the caller put in binding.Hostname is
	// deliberate — see the doc comment.
	hostname := RequestHostname(headers)

	// An unlisted hostname withholds the token but does not touch the score. The
	// visitor is not the problem — a key registered to another site is — so the
	// detection layer has nothing to say about it and the refusal is reported as
	// its own reason rather than smuggled in as a bot verdict.
	hostnameAllowed := e.allowedHostnames.Permits(hostname)

	// Three independent conditions, deliberately not folded into the score.
	//
	// powSatisfied is the one that matters most: a score threshold answers "how
	// suspicious is this visitor", which is the wrong question to ask of someone
	// who never completed the challenge. Gating here means no future reweighting
	// can reopen the bypass, and it holds even if the dispositive floor is
	// lowered or removed.
	success := finalScore < 0.5 && hostnameAllowed && powSatisfied

	// Name the failed precondition whenever one fails, not only when the score
	// would otherwise have allowed. Gating it on the score made the PoW case
	// unreachable — a PoW failure is dispositive, so it floors the score at 0.9
	// and the branch never fired — which is exactly the case a caller most needs
	// explained.
	withheldReason := ""
	switch {
	case !powSatisfied:
		withheldReason = "pow_not_satisfied"
	case !hostnameAllowed:
		withheldReason = "hostname_not_allowed"
	}

	var token string
	if success {
		token = e.generateToken(ip, siteKey, finalScore, TokenBinding{
			Hostname: hostname,
			Action:   SanitizeAction(binding.Action),
			CData:    SanitizeCData(binding.CData),
		})
	}

	// Feed the ledger so the next challenge this source asks for is priced on
	// what it just did. Recorded here rather than in the handlers so every
	// caller — both endpoints and the library API — contributes without having
	// to remember to.
	e.suspicion.Record(siteKey, ip, finalScore)

	return &VerificationResult{
		Success:        success,
		Score:          finalScore,
		Token:          token,
		Timestamp:      time.Now().Unix(),
		Detections:     detections,
		CategoryScores: categoryScores,
		Recommendation: recommendation,
		Reason:         withheldReason,
	}
}

// Verify performs full verification (backward compatible)
func (e *ScoringEngine) Verify(signals map[string]interface{}, ip, siteKey, userAgent string) *VerificationResult {
	return e.VerifyWithHeaders(signals, ip, siteKey, userAgent, nil, "", "", false, nil, TokenBinding{}, nil)
}

// GenerateChallenge creates a new PoW challenge (legacy)
func (e *ScoringEngine) GenerateChallenge() Challenge {
	id := make([]byte, 16)
	rand.Read(id)

	return Challenge{
		ID:         hex.EncodeToString(id),
		Difficulty: 50000,
		Expires:    time.Now().Add(5 * time.Minute).Unix(),
	}
}

// GeneratePoWChallenge creates a server-verified PoW challenge
func (e *ScoringEngine) GeneratePoWChallenge(siteKey, ip string, isDatacenter bool) *PoWChallenge {
	id := make([]byte, 16)
	rand.Read(id)
	challengeID := hex.EncodeToString(id)

	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	now := time.Now().UnixMilli()
	expiresAt := now + (5 * 60 * 1000) // 5 minutes

	// Cost scaling. See suspicion.go for why the escalation lands almost
	// entirely on MinAgeMs rather than on Difficulty.
	rateKey := "pow:" + siteKey + ":" + ip
	exceeded, count := e.rateLimiter.Check(rateKey, 60, 20)
	cost := ComputeChallengeCost(e.suspicion.Count(siteKey, ip), isDatacenter, count, exceeded)

	prefix := challengeID + ":" + formatInt64(now) + ":" + formatInt(cost.Difficulty)

	challenge := &PoWChallenge{
		ID:         challengeID,
		SiteKey:    siteKey,
		Prefix:     prefix,
		Difficulty: cost.Difficulty,
		Timestamp:  now,
		ExpiresAt:  expiresAt,
		Nonce:      nonce,
		MinAgeMs:   cost.MinAgeMs,
		IP:         ip,
	}

	// Sign the challenge
	sigData, _ := json.Marshal(map[string]interface{}{
		"id":         challenge.ID,
		"siteKey":    challenge.SiteKey,
		"timestamp":  challenge.Timestamp,
		"expiresAt":  challenge.ExpiresAt,
		"difficulty": challenge.Difficulty,
		"prefix":     challenge.Prefix,
		"minAgeMs":   challenge.MinAgeMs,
	})
	h := hmac.New(sha256.New, []byte(e.secretKey))
	h.Write(sigData)
	challenge.Sig = hex.EncodeToString(h.Sum(nil))

	// Store challenge. Redis failures are deliberately fail-closed: returning a
	// challenge that another replica can never verify would create a misleading
	// success path. The HTTP handler converts this sentinel into a 503.
	if err := e.powStore.putChallenge(challenge); err != nil {
		return nil
	}

	return challenge
}

// VerifyPoWSolution verifies a PoW solution from the client
// signalsHash is optional; if provided, it's included in the PoW input for signal binding
func (e *ScoringEngine) VerifyPoWSolution(solution *PoWSolution, siteKey string, signalsHash ...string) PoWVerifyResult {
	return e.VerifyPoWSolutionFromIP(solution, siteKey, "", signalsHash...)
}

// VerifyPoWSolutionFromIP additionally binds the solution to the coarse source
// network that acquired its adaptively priced challenge. An empty IP preserves
// the older library method's behavior; HTTP verification always supplies one.
func (e *ScoringEngine) VerifyPoWSolutionFromIP(solution *PoWSolution, siteKey, ip string, signalsHash ...string) PoWVerifyResult {
	if solution == nil || solution.ChallengeID == "" {
		return PoWVerifyResult{Valid: false, Reason: "no_solution"}
	}

	challenge, err := e.powStore.getChallenge(solution.ChallengeID)
	if err != nil {
		return PoWVerifyResult{Valid: false, Reason: "state_unavailable"}
	}
	if challenge == nil {
		return PoWVerifyResult{Valid: false, Reason: "challenge_not_found"}
	}

	now := time.Now().UnixMilli()
	if now > challenge.ExpiresAt {
		e.powStore.DeleteChallenge(solution.ChallengeID)
		return PoWVerifyResult{Valid: false, Reason: "challenge_expired"}
	}

	if challenge.SiteKey != siteKey {
		return PoWVerifyResult{Valid: false, Reason: "site_key_mismatch"}
	}

	if ip != "" && NetworkIdentity(challenge.IP) != NetworkIdentity(ip) {
		return PoWVerifyResult{Valid: false, Reason: "challenge_network_mismatch"}
	}

	// Cheap early-out for obvious replays before doing hash work.
	solutionKey := solution.ChallengeID + ":" + formatInt(solution.Nonce)
	if e.powStore.IsSolutionUsed(solutionKey) {
		return PoWVerifyResult{Valid: false, Reason: "solution_already_used"}
	}

	// Verify the hash (with optional signalsHash binding)
	var input string
	if len(signalsHash) > 0 && signalsHash[0] != "" {
		input = challenge.Prefix + ":" + signalsHash[0] + ":" + formatInt(solution.Nonce)
	} else {
		input = challenge.Prefix + ":" + formatInt(solution.Nonce)
	}
	expectedHash := sha256.Sum256([]byte(input))
	expectedHashHex := hex.EncodeToString(expectedHash[:])

	if solution.Hash != expectedHashHex {
		return PoWVerifyResult{Valid: false, Reason: "invalid_hash"}
	}

	// Check difficulty (hash must start with N zeros)
	target := strings.Repeat("0", challenge.Difficulty)
	if !strings.HasPrefix(solution.Hash, target) {
		return PoWVerifyResult{Valid: false, Reason: "insufficient_difficulty"}
	}

	claimed, reason, err := e.powStore.claimChallenge(solution.ChallengeID, solutionKey)
	if err != nil {
		return PoWVerifyResult{Valid: false, Reason: "state_unavailable"}
	}
	if !claimed {
		return PoWVerifyResult{Valid: false, Reason: reason}
	}

	// Calculate server-side elapsed time (un-spoofable)
	serverElapsed := now - challenge.Timestamp

	minAge := challenge.MinAgeMs
	if minAge <= 0 {
		minAge = baseMinAgeMs // challenge predates adaptive cost
	}

	return PoWVerifyResult{Valid: true, Difficulty: challenge.Difficulty, ServerElapsed: serverElapsed, Nonce: challenge.Nonce, MinAgeMs: minAge}
}

func formatInt64(n int64) string {
	return fmt.Sprintf("%d", n)
}

func formatInt(n int) string {
	return fmt.Sprintf("%d", n)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// VerifyToken verifies a previously issued token
// Pass ip to verify the token was issued to the same IP (prevents token theft)
func (e *ScoringEngine) VerifyToken(token string) map[string]interface{} {
	return e.VerifyTokenWithIP(token, "")
}

// VerifyTokenWithIP verifies a token and optionally checks IP binding
func (e *ScoringEngine) VerifyTokenWithIP(token, ip string) map[string]interface{} {
	result := make(map[string]interface{})

	decoded, err := decodeTokenBase64(token)
	if err != nil {
		result["valid"] = false
		result["reason"] = "invalid_encoding"
		return result
	}

	var data map[string]interface{}
	if err := json.Unmarshal(decoded, &data); err != nil {
		result["valid"] = false
		result["reason"] = "invalid_json"
		return result
	}

	// Check expiration
	timestamp, ok := data["timestamp"].(float64)
	if !ok || time.Now().Unix()-int64(timestamp) > 300 {
		result["valid"] = false
		result["reason"] = "expired"
		return result
	}

	// Verify signature
	sig, ok := data["sig"].(string)
	if !ok {
		result["valid"] = false
		result["reason"] = "missing_signature"
		return result
	}

	delete(data, "sig")
	payload, _ := json.Marshal(data)
	expectedSig := e.computeSignature(payload)

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		result["valid"] = false
		result["reason"] = "invalid_signature"
		return result
	}

	// Check for token replay (single-use tokens)
	if e.tokenStore.IsUsed(sig) {
		result["valid"] = false
		result["reason"] = "token_already_used"
		return result
	}

	// Verify IP matches (if provided)
	if ip != "" {
		ipHash, _ := data["ip_hash"].(string)
		h := sha256.Sum256([]byte(ip))
		expectedIPHash := hex.EncodeToString(h[:])[:8]
		if ipHash != expectedIPHash {
			result["valid"] = false
			result["reason"] = "ip_mismatch"
			return result
		}
	}

	// Mark token as used (prevents replay)
	e.tokenStore.MarkUsed(sig)

	result["valid"] = true
	result["site_key"] = data["site_key"]
	result["timestamp"] = data["timestamp"]
	result["score"] = data["score"]
	result["ip_hash"] = data["ip_hash"]
	// hostname/action/cdata default to "" so a token minted before they existed
	// still verifies and reports the same shape. The signature covers whatever
	// keys the token actually carries, so old four-key tokens validate
	// unchanged — this is additive, not a format break.
	result["hostname"] = stringField(data, "hostname")
	result["action"] = stringField(data, "action")
	result["cdata"] = stringField(data, "cdata")
	return result
}

// ============================================================
// Detection Methods
// ============================================================

// hasHumanMovementMarkers reports whether the movement carries independent
// evidence of a human hand.
//
// A slow pointer is the thing two of these checks look for, and it is also
// exactly what an elderly or motor-impaired visitor produces. The bench human
// panel caught both firing on them: "Mouse event rate abnormally low" on the
// elderly and motor-slow personas, "Mouse velocity too consistent" on motor-slow.
//
// Slowness alone cannot separate those users from an agent, but it does not have
// to. The same captures carry markers no low-effort automation produces:
// saturated micro-tremor, dozens of direction changes, corrective overshoots. On
// the bench corpus the split is total - every human persona clears this bar
// (tremor 1.00, 22-49 direction changes, 1-4 corrections) and every agent misses
// it (tremor 0.04-0.16, 0-1 direction changes, 0 corrections).
//
// So: do not read slowness as automation when the movement independently looks
// like a hand. An agent can of course fake all three, but faking three correlated
// properties of human motion is a materially harder job than running slowly,
// which is the point.
func hasHumanMovementMarkers(behavioral map[string]interface{}) bool {
	tremor := getFloatDefault(behavioral, "microTremorScore", 0.5)
	corrections := getFloat(behavioral, "overshootCorrections")
	changes := getFloat(behavioral, "directionChanges")
	return tremor >= 0.5 && (corrections >= 1 || changes >= 10)
}

// hasHumanPresence reports whether the visitor independently demonstrated they
// were at the keyboard — a real pointer trajectory or a touch. It is not a
// humanity verdict, just evidence that someone was there, which is enough to
// change how an otherwise ambiguous form fill reads.
func hasHumanPresence(behavioral map[string]interface{}) bool {
	return getFloat(behavioral, "totalPoints") >= 5 || getFloat(behavioral, "touchEvents") >= 1
}

// isTouchModality reports whether this visitor is using a touch or pen device,
// and so should be exempt from the mouse-trajectory detections.
//
// The old rule was touchEvents >= 3, which a mobile user who simply taps the
// checkbox does not meet: the client records touchstart and touchmove, and a
// clean tap on a page short enough not to need scrolling produces exactly one
// event. The bench human panel captured precisely that — touchEvents: 1 — and
// the visitor collected three agent detections for it, including
// "Zero mouse, touch, or keyboard events recorded" at confidence 0.9.
//
// One touch event is enough to establish modality. Corroborating it with the
// pointer type keeps a bare forged count from claiming the exemption on its
// own — though note this is a soft check either way, since every input here is
// client-supplied and an agent willing to claim touchEvents: 1 was equally
// willing to claim 3.
func isTouchModality(behavioral map[string]interface{}) bool {
	touchEvents := getFloat(behavioral, "touchEvents")
	if touchEvents >= 3 {
		return true
	}
	nonMouse, _ := behavioral["pointerHasNonMouseType"].(bool)
	return (touchEvents >= 1 || getFloat(behavioral, "touchTotalPoints") >= 1) && nonMouse
}

func (e *ScoringEngine) detectVisionAI(signals map[string]interface{}) []DetectionResult {
	results := make([]DetectionResult, 0)

	behavioral := getMap(signals, "behavioral")
	temporal := getMap(signals, "temporal")

	// Zero/minimal mouse movement - strong indicator of AI agent or programmatic click
	// Exempt: touch users (mobile) and keyboard-only users (accessibility)
	totalPoints := getFloat(behavioral, "totalPoints")
	trajectoryLen := getFloat(behavioral, "trajectoryLength")
	approachPts := getFloat(behavioral, "approachPoints")
	keyEventsAI := getFloat(behavioral, "keyEvents")
	isTouchUser := isTouchModality(behavioral)
	isKeyboardUser := keyEventsAI >= 2 && totalPoints == 0
	// Click-derived fields only exist when a widget was there to click.
	isWidget := hasWidgetInteraction(signals)

	if totalPoints < 5 && trajectoryLen < 10 && !isTouchUser && !isKeyboardUser {
		results = append(results, DetectionResult{
			Category:   CategoryVisionAI,
			Score:      0.9,
			Confidence: 0.85,
			Reason:     "No mouse movement detected before click (AI agent pattern)",
			Details:    map[string]interface{}{"totalPoints": totalPoints, "trajectoryLength": trajectoryLen},
		})
	}

	// Invisible scoring has no target to approach, so a missing approach path
	// says nothing there (see SetInteractionMode).
	if isWidget && approachPts == 0 && !isTouchUser && !isKeyboardUser {
		results = append(results, DetectionResult{
			Category:   CategoryVisionAI,
			Score:      0.7,
			Confidence: 0.8,
			Reason:     "No approach trajectory to target",
		})
	}

	// Check PoW timing (reveals API round-trip)
	if pow := getMap(temporal, "pow"); pow != nil {
		duration := getFloat(pow, "duration")
		iterations := getFloat(pow, "iterations")

		if iterations > 0 {
			expectedMin := (iterations / 500000) * 1000
			expectedMax := (iterations / 50000) * 1000

			if duration < expectedMin*0.5 {
				results = append(results, DetectionResult{
					Category:   CategoryVisionAI,
					Score:      0.8,
					Confidence: 0.7,
					Reason:     "PoW completed impossibly fast",
					Details:    map[string]interface{}{"duration": duration, "expected_min": expectedMin},
				})
			} else if duration > expectedMax*3 {
				results = append(results, DetectionResult{
					Category:   CategoryVisionAI,
					Score:      0.6,
					Confidence: 0.5,
					Reason:     "PoW timing suggests external processing",
					Details:    map[string]interface{}{"duration": duration, "expected_max": expectedMax},
				})
			}
		}
	}

	// Check micro-tremor (humans have natural hand shake).
	//
	// Two things were wrong here. Go defaulted a missing microTremorScore to 0
	// (maximally suspicious) while Node and Python defaulted to 0.5, so a client
	// that omitted the field was flagged by this server and not the others — the
	// E2E suite's touch and keyboard exemption cases failed on Go for exactly
	// this reason. And like the approach-directness check below, it fires on a
	// measurement that does not exist for someone who never moved a mouse; the
	// client itself reports 0.5 as its "no mouse data" sentinel.
	//
	// Default to that sentinel, require real mouse movement before judging its
	// texture, and apply the same exemptions as the surrounding checks.
	microTremor := getFloatDefault(behavioral, "microTremorScore", 0.5)
	hasMouseMovement := totalPoints >= 5
	if hasMouseMovement && !isTouchUser && !isKeyboardUser && microTremor < 0.15 {
		results = append(results, DetectionResult{
			Category:   CategoryVisionAI,
			Score:      0.7,
			Confidence: 0.6,
			Reason:     "Mouse movement lacks natural micro-tremor",
			Details:    map[string]interface{}{"microTremorScore": microTremor},
		})
	}

	// Check approach directness.
	//
	// The client reports directness 1 (perfectly straight) when there is no
	// approach path to measure at all, so this check used to fire on every
	// keyboard-only, screen-reader and touch user — the populations the
	// surrounding checks go out of their way to exempt. Found by the bench
	// human panel: keyboard-only, screen-reader and touch all reported
	// approachPoints 0 with approachDirectness 1.
	//
	// Require an actual path before judging its shape, and apply the same
	// exemptions as its neighbours.
	approachDirectness := getFloat(behavioral, "approachDirectness")
	hasApproachPath := approachPts >= 5
	if hasApproachPath && !isTouchUser && !isKeyboardUser && approachDirectness > 0.95 {
		results = append(results, DetectionResult{
			Category:   CategoryVisionAI,
			Score:      0.5,
			Confidence: 0.5,
			Reason:     "Mouse path to target is unnaturally direct",
			Details:    map[string]interface{}{"approachDirectness": approachDirectness},
		})
	}

	// Check click precision
	clickPrecision := getFloat(behavioral, "clickPrecision")
	if clickPrecision < 2 && clickPrecision > 0 {
		results = append(results, DetectionResult{
			Category:   CategoryVisionAI,
			Score:      0.4,
			Confidence: 0.5,
			Reason:     "Click precision is unnaturally accurate",
			Details:    map[string]interface{}{"clickPrecision": clickPrecision},
		})
	}

	// No exploration before click.
	//
	// explorationRatio is click-derived too, and 0.3 is the "not measured"
	// default the Node and Python engines already use — Go read the absent
	// field as a hostile 0.
	explorationRatio := getFloatDefault(behavioral, "explorationRatio", 0.3)
	trajectoryLength := getFloat(behavioral, "trajectoryLength")
	if isWidget && explorationRatio < 0.05 && trajectoryLength > 50 {
		results = append(results, DetectionResult{
			Category:   CategoryVisionAI,
			Score:      0.4,
			Confidence: 0.4,
			Reason:     "No exploratory mouse movement before click",
			Details:    map[string]interface{}{"explorationRatio": explorationRatio},
		})
	}

	// Input-event forensics: teleport clicks and agent think-time cadence.
	if fcs := getMap(behavioral, "inputForensics"); fcs != nil {
		// A click dispatched at coordinates with no approach trajectory.
		teleports := getFloat(fcs, "teleportClicks")
		if teleports >= 1 && !isTouchUser {
			results = append(results, DetectionResult{
				Category:   CategoryVisionAI,
				Score:      0.7,
				Confidence: 0.7,
				Reason:     fmt.Sprintf("Click injected with no pointer trajectory (%d teleport clicks)", int(teleports)),
				Details:    map[string]interface{}{"teleportClicks": teleports},
			})
		}
		// Bursts of activity separated by multi-second perfect silence — the
		// agent act -> screenshot -> inference loop. Low confidence (slow humans
		// idle too); requires silence to dominate the interaction. Keyboard-only
		// users are exempt (their cadence is naturally bursty).
		if !isKeyboardUser &&
			getFloat(fcs, "cadenceEvents") >= 12 &&
			getFloat(fcs, "cadenceSilentGaps") >= 3 &&
			getFloat(fcs, "cadenceGapCV") > 2.5 &&
			getFloat(fcs, "cadenceSilentRatio") > 0.6 {
			results = append(results, DetectionResult{
				Category:   CategoryVisionAI,
				Score:      0.6,
				Confidence: 0.5,
				Reason:     "Interaction cadence matches agent act/think loop (bursts + dead air)",
				Details: map[string]interface{}{
					"silentGaps": getFloat(fcs, "cadenceSilentGaps"),
					"gapCV":      getFloat(fcs, "cadenceGapCV"),
				},
			})
		}
	}

	return results
}

func (e *ScoringEngine) detectHeadless(signals map[string]interface{}, userAgent string) []DetectionResult {
	results := make([]DetectionResult, 0)

	env := getMap(signals, "environmental")
	headless := getMap(env, "headlessIndicators")
	automation := getMap(env, "automationFlags")

	// WebDriver detection
	if getBool(env, "webdriver") {
		results = append(results, DetectionResult{
			Category:    CategoryHeadless,
			Score:       0.95,
			Confidence:  0.95,
			Dispositive: true, // navigator.webdriver === true — see applyDispositiveFloor
			Reason:      "WebDriver detected (navigator.webdriver = true)",
		})
	}

	// Automation flags
	if automation != nil {
		plugins := getFloat(automation, "plugins")
		if plugins == 0 {
			results = append(results, DetectionResult{
				Category:   CategoryHeadless,
				Score:      0.6,
				Confidence: 0.6,
				Reason:     "No browser plugins detected",
			})
		}

		if !getBool(automation, "languages") {
			results = append(results, DetectionResult{
				Category:   CategoryHeadless,
				Score:      0.5,
				Confidence: 0.5,
				Reason:     "No navigator.languages",
			})
		}
	}

	// Headless indicators
	if headless != nil {
		if !getBool(headless, "hasOuterDimensions") {
			results = append(results, DetectionResult{
				Category:   CategoryHeadless,
				Score:      0.7,
				Confidence: 0.7,
				Reason:     "Window lacks outer dimensions",
			})
		}

		if getBool(headless, "innerEqualsOuter") {
			results = append(results, DetectionResult{
				Category:   CategoryHeadless,
				Score:      0.4,
				Confidence: 0.5,
				Reason:     "Viewport equals window size (no browser chrome)",
			})
		}

		if getString(headless, "notificationPermission") == "denied" {
			results = append(results, DetectionResult{
				Category:   CategoryHeadless,
				Score:      0.3,
				Confidence: 0.4,
				Reason:     "Notifications pre-denied",
			})
		}
	}

	// User-Agent patterns
	for _, pattern := range e.uaPatterns {
		if pattern.MatchString(userAgent) {
			results = append(results, DetectionResult{
				Category:   CategoryHeadless,
				Score:      0.9,
				Confidence: 0.9,
				Reason:     "Automation pattern in User-Agent",
			})
			break
		}
	}

	// WebGL renderer check
	webgl := getMap(env, "webglInfo")
	if webgl != nil {
		renderer := strings.ToLower(getString(webgl, "renderer"))
		if strings.Contains(renderer, "swiftshader") || strings.Contains(renderer, "llvmpipe") {
			results = append(results, DetectionResult{
				Category:   CategoryHeadless,
				Score:      0.8,
				Confidence: 0.8,
				Reason:     "Software WebGL renderer detected (SwiftShader/LLVMpipe)",
			})
		}
	}

	// Playwright-specific detection
	playwright := getMap(env, "playwright")
	if getBool(playwright, "detected") {
		scoreMap := map[string]float64{
			"playwright_globals":     0.95,
			"webdriver_deleted":      0.8,
			"webdriver_configurable": 0.7,
			"chrome_runtime_missing": 0.6,
		}
		// Signals a genuine browser also produces, and therefore not evidence of
		// anything. Ignored here as well as in the client, because clients already
		// deployed will keep sending them.
		//
		// Measured in Chrome 150 with navigator.webdriver === false:
		//   webdriver_configurable  descriptor present and configurable — WebIDL
		//                           defines the attribute that way, so every browser
		//                           reports what a patched one reports
		//   chrome_runtime_missing  window.chrome present, chrome.runtime absent, on
		//                           any page without a matching externally_connectable
		//                           extension — i.e. almost every page
		//
		// They fired together on ordinary Chrome, which is why they cannot corroborate
		// each other either.
		inertSignals := map[string]bool{
			"webdriver_configurable": true,
			"chrome_runtime_missing": true,
		}

		if sigs, ok := playwright["signals"].([]interface{}); ok {
			for _, s := range sigs {
				if sig, ok := s.(string); ok {
					if inertSignals[sig] {
						continue
					}
					sigScore := 0.7
					if v, exists := scoreMap[sig]; exists {
						sigScore = v
					}
					results = append(results, DetectionResult{
						Category:   CategoryHeadless,
						Score:      sigScore,
						Confidence: 0.8,
						Reason:     "Playwright artifact detected: " + sig,
					})
				}
			}
		}
	}

	return results
}

// detectStealthArtifacts flags anti-detection patch traces collected by the
// client. These are FALSE-POSITIVE-SAFE: a genuine browser never produces them,
// because they are internal contradictions / native-function tampering rather
// than environment-shape heuristics (which would misfire on real Linux/VPN
// users). Targets stealth-automation agents (e.g. Manus AI) running real but
// patched Chromium. Only the two FP-safe signals are scored; the client also
// collects privacy-extension-ambiguous artifacts (patched_*) for observability
// that are intentionally NOT scored here. Keep in sync with server-node/python.
func (e *ScoringEngine) detectStealthArtifacts(signals map[string]interface{}) []DetectionResult {
	results := make([]DetectionResult, 0)

	env := getMap(signals, "environmental")
	if env == nil {
		return results
	}

	// Function.prototype.toString proxied — the signature move of stealth
	// frameworks (used to make their other native overrides look untouched).
	if artifacts := getMap(env, "stealthArtifacts"); artifacts != nil {
		if list, ok := artifacts["signals"].([]interface{}); ok {
			for _, s := range list {
				if str, ok := s.(string); ok && str == "tostring_proxied" {
					results = append(results, DetectionResult{
						Category:   CategoryHeadless,
						Score:      0.9,
						Confidence: 0.85,
						Reason:     "Function.prototype.toString is proxied (stealth automation patch)",
					})
					break
				}
			}
		}
	}

	// Notification.permission == "denied" while the Permissions API reports
	// "prompt": a state a real browser cannot reach (classic headless tell).
	if probe := getMap(env, "permissionProbe"); getBool(probe, "contradiction") {
		results = append(results, DetectionResult{
			Category:   CategoryHeadless,
			Score:      0.85,
			Confidence: 0.85,
			Reason:     "Notification permission contradicts Permissions API (headless/stealth tell)",
		})
	}

	return results
}

func (e *ScoringEngine) detectAutomation(signals map[string]interface{}) []DetectionResult {
	results := make([]DetectionResult, 0)

	env := getMap(signals, "environmental")
	behavioral := getMap(signals, "behavioral")

	// JS execution timing
	jsTime := getFloat(env, "jsExecutionTime")
	if jsTime > 0 {
		if jsTime < 0.5 {
			results = append(results, DetectionResult{
				Category:   CategoryAutomation,
				Score:      0.4,
				Confidence: 0.3,
				Reason:     "JS execution unusually fast (possibly VM)",
				Details:    map[string]interface{}{"jsExecutionTime": jsTime},
			})
		} else if jsTime > 50 {
			results = append(results, DetectionResult{
				Category:   CategoryAutomation,
				Score:      0.3,
				Confidence: 0.3,
				Reason:     "JS execution unusually slow",
				Details:    map[string]interface{}{"jsExecutionTime": jsTime},
			})
		}
	}

	// RAF consistency
	raf := getMap(env, "rafConsistency")
	if raf != nil {
		variance := getFloat(raf, "frameTimeVariance")
		if variance < 0.1 {
			results = append(results, DetectionResult{
				Category:   CategoryAutomation,
				Score:      0.5,
				Confidence: 0.4,
				Reason:     "RequestAnimationFrame timing too consistent",
			})
		}
	}

	// Event timing consistency
	eventVariance := getFloat(behavioral, "eventDeltaVariance")
	totalPoints := getFloat(behavioral, "totalPoints")
	if eventVariance < 2 && totalPoints > 10 {
		results = append(results, DetectionResult{
			Category:   CategoryAutomation,
			Score:      0.6,
			Confidence: 0.6,
			Reason:     "Mouse event timing unnaturally consistent",
			Details:    map[string]interface{}{"eventDeltaVariance": eventVariance},
		})
	}

	return results
}

func (e *ScoringEngine) detectCDP(signals map[string]interface{}) []DetectionResult {
	results := make([]DetectionResult, 0)

	env := getMap(signals, "environmental")

	// Input-event forensics: catch CDP-injected input that reports isTrusted:true
	// and so evades the global-based checks below. Touch users are exempt — they
	// don't generate the mouse-pointer batches these signals rely on.
	behavioral := getMap(signals, "behavioral")
	isTouchUser := isTouchModality(behavioral)
	if fcs := getMap(behavioral, "inputForensics"); fcs != nil && !isTouchUser {
		// Real mice coalesce several hardware samples per animation frame; a
		// stream of pointermoves that NEVER coalesced is synthetic injection.
		if getFloat(fcs, "coalescedSamples") >= 20 && getFloat(fcs, "coalescedMax") <= 1 {
			results = append(results, DetectionResult{
				Category:   CategoryCDP,
				Score:      0.8,
				Confidence: 0.6,
				Reason:     "Pointer moves never coalesced across many samples (synthetic/CDP input)",
				Details:    map[string]interface{}{"coalescedSamples": getFloat(fcs, "coalescedSamples")},
			})
		}
		// movementX/Y incoherent with actual position deltas across most moves.
		if getFloat(fcs, "pointerMoveSamples") >= 20 && getFloat(fcs, "pointerMoveZeroRatio") > 0.9 {
			results = append(results, DetectionResult{
				Category:   CategoryCDP,
				Score:      0.6,
				Confidence: 0.5,
				Reason:     "Pointer movement deltas incoherent with position (synthetic input)",
				Details:    map[string]interface{}{"pointerMoveZeroRatio": getFloat(fcs, "pointerMoveZeroRatio")},
			})
		}
	}

	// CDP Runtime/DevTools console consumer attached. Low confidence: a developer
	// with DevTools open also trips this, so it contributes rather than blocks.
	if cdpRuntime := getMap(env, "cdpRuntime"); getBool(cdpRuntime, "consoleAttached") {
		results = append(results, DetectionResult{
			Category:   CategoryCDP,
			Score:      0.6,
			Confidence: 0.5,
			Reason:     "CDP/DevTools console consumer attached (automation protocol or open DevTools)",
		})
	}

	cdp := getMap(env, "cdp")

	detected := getBool(cdp, "detected")
	if !detected {
		return results
	}

	signalsInterface := cdp["signals"]
	signalList, ok := signalsInterface.([]interface{})
	if !ok {
		return results
	}

	// Convert to string slice
	var signals_strs []string
	for _, s := range signalList {
		if str, ok := s.(string); ok {
			signals_strs = append(signals_strs, str)
		}
	}

	signalCount := len(signals_strs)
	if signalCount == 0 {
		return results
	}

	// High-confidence signals
	highConfSignals := map[string]bool{
		"chromedriver_cdc":     true,
		"puppeteer_eval":       true,
		"cdp_script_injection": true,
	}

	hasHighConf := false
	for _, s := range signals_strs {
		if highConfSignals[s] {
			hasHighConf = true
			break
		}
	}

	signalsJoined := strings.Join(signals_strs, ", ")

	if hasHighConf {
		results = append(results, DetectionResult{
			Category:    CategoryCDP,
			Score:       0.9,
			Confidence:  0.95,
			Dispositive: true, // driver-injected globals — see applyDispositiveFloor
			Reason:      "CDP automation detected: " + signalsJoined,
			Details:     map[string]interface{}{"signals": signals_strs},
		})
	} else if signalCount >= 2 {
		results = append(results, DetectionResult{
			Category:   CategoryCDP,
			Score:      0.8,
			Confidence: 0.85,
			Reason:     "Multiple CDP indicators: " + signalsJoined,
			Details:    map[string]interface{}{"signals": signals_strs},
		})
	} else {
		results = append(results, DetectionResult{
			Category:   CategoryCDP,
			Score:      0.6,
			Confidence: 0.7,
			Reason:     "CDP indicator: " + signalsJoined,
			Details:    map[string]interface{}{"signals": signals_strs},
		})
	}

	return results
}

func (e *ScoringEngine) detectBehavioral(signals map[string]interface{}) []DetectionResult {
	results := make([]DetectionResult, 0)

	behavioral := getMap(signals, "behavioral")
	temporal := getMap(signals, "temporal")

	// Insufficient mouse data - critical check for zero-click bots
	// Exempt: touch users (mobile) and keyboard-only users (accessibility)
	totalPoints := getFloat(behavioral, "totalPoints")
	trajectoryLength := getFloat(behavioral, "trajectoryLength")
	keyEvents := getFloat(behavioral, "keyEvents")
	isTouchUsr := isTouchModality(behavioral)
	isKbdUsr := keyEvents >= 2 && totalPoints == 0
	isWidget := hasWidgetInteraction(signals)

	if totalPoints == 0 && !isTouchUsr && !isKbdUsr {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.8,
			Confidence: 0.9,
			Reason:     "Zero mouse, touch, or keyboard events recorded",
		})
	} else if totalPoints < 10 && !isTouchUsr && !isKbdUsr && trajectoryLength < 30 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.6,
			Confidence: 0.7,
			Reason:     "Insufficient mouse movement before interaction",
			Details:    map[string]interface{}{"totalPoints": totalPoints, "trajectoryLength": trajectoryLength},
		})
	}

	// Velocity variance
	velocityVariance := getFloat(behavioral, "velocityVariance")
	if velocityVariance < 0.02 && trajectoryLength > 50 && !hasHumanMovementMarkers(behavioral) {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.6,
			Confidence: 0.6,
			Reason:     "Mouse velocity too consistent",
			Details:    map[string]interface{}{"velocityVariance": velocityVariance},
		})
	}

	// Overshoot corrections. Click-derived, so widget-only.
	overshoots := getFloat(behavioral, "overshootCorrections")
	if isWidget && overshoots == 0 && trajectoryLength > 200 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.4,
			Confidence: 0.4,
			Reason:     "No overshoot corrections on long trajectory",
		})
	}

	// Interaction speed
	interactionTime := getFloat(behavioral, "interactionDuration")
	if interactionTime < 200 && interactionTime > 0 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.7,
			Confidence: 0.7,
			Reason:     "Interaction completed too quickly",
			Details:    map[string]interface{}{"interactionDuration": interactionTime},
		})
	} else if isWidget && interactionTime > 60000 {
		// Widget mode measures time spent solving. Invisible mode reuses the
		// same field for time on page, where a minute is just a reader.
		results = append(results, DetectionResult{
			Category:   CategoryCaptchaFarm,
			Score:      0.3,
			Confidence: 0.3,
			Reason:     "Unusually long interaction time",
		})
	}

	// Page load to first interaction
	firstInteraction := getFloat(temporal, "pageLoadToFirstInteraction")
	if firstInteraction > 0 && firstInteraction < 100 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.5,
			Confidence: 0.5,
			Reason:     "First interaction too soon after page load",
			Details:    map[string]interface{}{"pageLoadToFirstInteraction": firstInteraction},
		})
	}

	// Mouse event rate
	eventRate := getFloat(behavioral, "mouseEventRate")
	if eventRate > 200 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.6,
			Confidence: 0.5,
			Reason:     "Mouse event rate abnormally high",
			Details:    map[string]interface{}{"mouseEventRate": eventRate},
		})
	} else if eventRate > 0 && eventRate < 10 && !hasHumanMovementMarkers(behavioral) {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.4,
			Confidence: 0.4,
			Reason:     "Mouse event rate abnormally low",
		})
	}

	// No scroll/keyboard
	scrollEvents := getFloat(behavioral, "scrollEvents")
	if scrollEvents == 0 && keyEvents == 0 && interactionTime > 5000 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.2,
			Confidence: 0.2,
			Reason:     "No scroll or keyboard activity during session",
		})
	}

	// Direction changes
	dirChanges := getFloat(behavioral, "directionChanges")
	if totalPoints > 50 && dirChanges < 3 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.4,
			Confidence: 0.4,
			Reason:     "Too few direction changes in mouse movement",
		})
	}

	return results
}

// ============================================================
// Mobile-native detectors (touch authenticity, sensor entropy, touch kinematics)
// UA-gated on mobile. Non-mobile UAs: no-op. Designed never to penalize iOS
// Safari without DeviceMotion permission (absence treated as neutral).
// ============================================================

var mobileUARegex = regexp.MustCompile(`(?i)mobile|android|iphone|ipad|ipod`)

func isMobileUA(userAgent string) bool {
	if userAgent == "" {
		return false
	}
	return mobileUARegex.MatchString(userAgent)
}

func (e *ScoringEngine) detectTouchAuthenticity(signals map[string]interface{}, userAgent string) []DetectionResult {
	results := make([]DetectionResult, 0)
	if !isMobileUA(userAgent) {
		return results
	}

	b := getMap(signals, "behavioral")
	if b == nil {
		return results
	}

	touchPoints := getFloat(b, "touchTotalPoints")
	if touchPoints == 0 {
		touchPoints = getFloat(b, "touchEvents")
	}
	if touchPoints < 3 {
		return results
	}

	forceVariance := getFloat(b, "touchForceVariance")
	radiusVariance := getFloat(b, "touchRadiusVariance")
	forceAllOne := getBool(b, "touchForceAllOne")
	uniqueIds := getFloat(b, "touchUniqueIdentifiers")
	forceMax := getFloat(b, "touchForceMax")
	radiusMax := getFloat(b, "touchRadiusMax")

	if forceVariance == 0 && forceMax > 0 && touchPoints >= 5 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.75,
			Confidence: 0.85,
			Reason:     "Touch force is identical across all events (synthetic touch)",
		})
	}

	if forceAllOne && touchPoints >= 5 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.8,
			Confidence: 0.9,
			Reason:     "All touches report force=1.0 exactly (synthetic pattern)",
		})
	}

	if radiusVariance == 0 && radiusMax > 0 && touchPoints >= 5 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.7,
			Confidence: 0.8,
			Reason:     "Touch contact radius identical across all events",
		})
	}

	if touchPoints >= 5 && uniqueIds == 0 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.6,
			Confidence: 0.7,
			Reason:     "Mobile touches lack identifier tracking (synthetic injection)",
		})
	}

	return results
}

func (e *ScoringEngine) detectSensorEntropy(signals map[string]interface{}, userAgent string) []DetectionResult {
	results := make([]DetectionResult, 0)
	if !isMobileUA(userAgent) {
		return results
	}

	env := getMap(signals, "environmental")
	sensor := getMap(env, "sensor")
	if sensor == nil {
		return results
	}

	motionCount := getFloat(sensor, "motionEventCount")
	motionVariance := getFloat(sensor, "motionAccelVariance")
	orientationCount := getFloat(sensor, "orientationEventCount")
	orientationVariance := getFloat(sensor, "orientationVariance")

	if motionCount >= 10 && motionVariance < 0.01 {
		results = append(results, DetectionResult{
			Category:   CategoryHeadless,
			Score:      0.7,
			Confidence: 0.8,
			Reason:     fmt.Sprintf("Motion sensor active but flat (variance=%.4f) — likely emulator", motionVariance),
		})
	}

	if orientationCount >= 10 && orientationVariance < 0.01 {
		results = append(results, DetectionResult{
			Category:   CategoryHeadless,
			Score:      0.6,
			Confidence: 0.7,
			Reason:     "Orientation sensor active but completely flat — likely emulator",
		})
	}

	// motionCount == 0 is NEUTRAL (iOS without permission).
	return results
}

func (e *ScoringEngine) detectTouchKinematics(signals map[string]interface{}) []DetectionResult {
	results := make([]DetectionResult, 0)
	b := getMap(signals, "behavioral")
	if b == nil {
		return results
	}

	touchPoints := getFloat(b, "touchTotalPoints")
	if touchPoints < 10 {
		return results
	}

	straightLine := getFloat(b, "touchStraightLineRatio")
	tremor := getFloat(b, "touchMicroTremorScore")
	dirChanges := getFloat(b, "touchDirectionChanges")

	if straightLine > 0.85 && touchPoints >= 20 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.65,
			Confidence: 0.75,
			Reason:     fmt.Sprintf("Touch path too straight (ratio=%.2f) — automation pattern", straightLine),
		})
	}

	if tremor < 0.05 && touchPoints >= 30 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.55,
			Confidence: 0.65,
			Reason:     "Touch path has no micro-tremor (unnaturally smooth)",
		})
	}

	if dirChanges == 0 && touchPoints >= 30 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.5,
			Confidence: 0.6,
			Reason:     "Touch path has zero direction changes over long trajectory",
		})
	}

	return results
}

func (e *ScoringEngine) detectFingerprint(signals map[string]interface{}, ip, siteKey string) []DetectionResult {
	results := make([]DetectionResult, 0)

	env := getMap(signals, "environmental")
	automation := getMap(env, "automationFlags")

	// Generate fingerprint
	components := []string{
		getString(env, "canvasHash"),
		getString(getMap(env, "webglInfo"), "renderer"),
		getString(automation, "platform"),
		getString(automation, "hardwareConcurrency"),
	}
	fpHash := sha256.Sum256([]byte(strings.Join(components, "|")))
	fingerprint := hex.EncodeToString(fpHash[:8])

	// Record fingerprint
	e.fingerprintStore.Record(fingerprint, ip, siteKey)

	// Check IP fingerprint count
	ipFPCount := e.fingerprintStore.GetIPFingerprintCount(ip)
	if ipFPCount > 5 {
		results = append(results, DetectionResult{
			Category:   CategoryFingerprint,
			Score:      0.6,
			Confidence: 0.6,
			Reason:     "IP has used many different fingerprints",
			Details:    map[string]interface{}{"unique_fingerprints": ipFPCount},
		})
	}

	// Check fingerprint IP count
	fpIPCount := e.fingerprintStore.GetFingerprintIPCount(fingerprint, siteKey)
	if fpIPCount > 10 {
		results = append(results, DetectionResult{
			Category:   CategoryFingerprint,
			Score:      0.5,
			Confidence: 0.5,
			Reason:     "Fingerprint seen from many IPs",
			Details:    map[string]interface{}{"ip_count": fpIPCount},
		})
	}

	// Canvas hash anomalies
	canvasHash := getString(env, "canvasHash")
	if canvasHash == "error" || canvasHash == "" {
		results = append(results, DetectionResult{
			Category:   CategoryFingerprint,
			Score:      0.4,
			Confidence: 0.4,
			Reason:     "Canvas fingerprinting blocked or failed",
		})
	}

	// Audio hash
	audioHash := getString(env, "audioHash")
	if audioHash == "unsupported" {
		results = append(results, DetectionResult{
			Category:   CategoryFingerprint,
			Score:      0.3,
			Confidence: 0.3,
			Reason:     "AudioContext not supported",
		})
	}

	return results
}

func (e *ScoringEngine) detectRateAbuse(ip, siteKey string) []DetectionResult {
	results := make([]DetectionResult, 0)

	key := siteKey + ":" + ip

	exceeded, count := e.rateLimiter.Check(key, 60, 10)
	if exceeded {
		results = append(results, DetectionResult{
			Category:   CategoryRateLimit,
			Score:      0.8,
			Confidence: 0.9,
			Reason:     "Rate limit exceeded (per-minute)",
			Details:    map[string]interface{}{"count": count, "window": 60},
		})
	} else if count > 5 {
		results = append(results, DetectionResult{
			Category:   CategoryRateLimit,
			Score:      0.3,
			Confidence: 0.5,
			Reason:     "High request rate",
			Details:    map[string]interface{}{"count": count},
		})
	}

	return results
}

// ============================================================
// Score Calculation
// ============================================================

// =============================================================================
// Web Bot Auth (RFC 9421 HTTP Message Signatures) verification
// =============================================================================

// CheckWebBotAuth cryptographically verifies a Web Bot Auth signed request and
// maps the outcome to detections. The request must be reconstructed from the
// real *http.Request (see webbotauth.RequestFromHTTP) so the signature base is
// accurate — a header-map approximation could mis-derive the authority and make
// a genuine signature fail crypto verification, false-positiving a real agent.
//
// Outcomes:
//   - verified   → declared_ai (verified:true, high confidence): a trustworthy
//     signed identity, e.g. OpenAI Operator. A policy signal, not a hard block.
//   - forged     → bot (low confidence, contributory): the request claimed an
//     agent identity and the signature failed cryptographic verification. Only
//     a genuine crypto failure counts; see webBotAuthForged.
//   - otherwise  → fail open to a presence-only declared_ai signal identical to
//     the pre-verification behavior. A directory we could not fetch (network,
//     timeout, SSRF-blocked) is not proof of spoofing, so it must not accuse.
func (e *ScoringEngine) CheckWebBotAuth(ctx context.Context, req *httpsig.Request) []DetectionResult {
	agent := displayAgent(req.Header.Get("signature-agent"))

	// Verifier unavailable (construction failed): preserve presence detection.
	if e.webBotAuth == nil {
		return []DetectionResult{webBotAuthPresence(agent)}
	}

	res := e.webBotAuth.Verify(ctx, req)
	if res.Agent != "" {
		agent = res.Agent
	}
	return classifyWebBotAuth(res, agent)
}

// classifyWebBotAuth turns a verification Result into detections. It is pure (no
// I/O) so the verdict policy is unit-testable without a live key directory.
// maxWebBotAuthLifetime bounds how far out a signature's `expires` may sit.
// draft-meunier-webbotauth-httpsig-protocol-00 RECOMMENDS no more than 24h. The
// library already rejects an *already-expired* signature; nothing upstream caps
// how long a live one may remain replayable, which is what this adds.
//
// Because the draft says RECOMMENDED and not MUST, an over-long window is not
// treated as forgery — the request simply drops to presence-only, the same
// verdict as any other non-cryptographic failure. Mirrors
// MAX_SIGNATURE_LIFETIME_S in server-node/webbotauth.js.
const maxWebBotAuthLifetime = 24 * time.Hour

func classifyWebBotAuth(res *webbotauth.Result, agent string) []DetectionResult {
	switch res.Status {
	case webbotauth.StatusVerified:
		if !res.Created.IsZero() && !res.Expires.IsZero() &&
			res.Expires.Sub(res.Created) > maxWebBotAuthLifetime {
			return []DetectionResult{webBotAuthPresence(agent)}
		}
		return []DetectionResult{webBotAuthVerified(agent, res.KeyID, string(res.Algorithm))}
	case webbotauth.StatusInvalid:
		if webBotAuthForged(res.Errors) {
			return []DetectionResult{webBotAuthForgedDetection(agent, res.Errors)}
		}
		// Structural or fetch failure: could not complete verification through
		// no fault of the signature. Fail open to presence-only.
		return []DetectionResult{webBotAuthPresence(agent)}
	default: // StatusNoSignature
		return nil
	}
}

// webBotAuthVerified is the detection for a cryptographically verified signed
// agent: declared_ai, verified:true — a trustworthy identity and a policy
// signal, not a hard block.
func webBotAuthVerified(agent, keyID, algorithm string) DetectionResult {
	return DetectionResult{
		Category:   CategoryDeclaredAI,
		Score:      0.5,
		Confidence: 0.99,
		Reason:     "Verified AI agent (Web Bot Auth): " + agent,
		Details: map[string]interface{}{
			"signatureAgent": agent,
			"verified":       true,
			"keyId":          keyID,
			"algorithm":      algorithm,
		},
	}
}

// webBotAuthForgedDetection is the detection for a signature that failed
// cryptographic verification: a contributory (low-confidence) bot signal.
func webBotAuthForgedDetection(agent string, errs []error) DetectionResult {
	return DetectionResult{
		Category:   CategoryBot,
		Score:      0.5,
		Confidence: 0.5,
		Reason:     "Forged Web Bot Auth signature (crypto verification failed): " + agent,
		Details: map[string]interface{}{
			"signatureAgent": agent,
			"verified":       false,
			"errors":         errStrings(errs),
		},
	}
}

// webBotAuthForged reports whether a StatusInvalid result failed because the
// signature itself did not verify against the key — the one outcome that is
// affirmative evidence of a forged identity claim. Everything else a
// StatusInvalid can mean (unreachable/blocked directory, key absent, expired,
// malformed) is deliberately excluded so transient or benign failures never
// accuse a legitimate signer. Matched on the library's stable crypto-failure
// wording; when in doubt this returns false (fail open, no false accusation).
func webBotAuthForged(errs []error) bool {
	for _, err := range errs {
		if err != nil && strings.Contains(err.Error(), "signature verification failed") {
			return true
		}
	}
	return false
}

// webBotAuthPresence is the pre-verification detection: signature headers are
// present but unverified. declared_ai, verified:false — an identification, not
// an accusation.
func webBotAuthPresence(agent string) DetectionResult {
	return DetectionResult{
		Category:   CategoryDeclaredAI,
		Score:      0.4,
		Confidence: 0.95,
		Reason:     "Signed agent request (Web Bot Auth, unverified): " + agent,
		Details:    map[string]interface{}{"signatureAgent": agent, "verified": false},
	}
}

// displayAgent normalizes a Signature-Agent header value for display: the wire
// form is an RFC 8941 string (quoted) or dictionary member, e.g. `"https://a"`.
func displayAgent(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, `"`)
	if s == "" {
		return "unknown"
	}
	return s
}

func errStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	return out
}

// calculateCategoryScores combines the detections within each category.
//
// # Why this is not a mean
//
// It used to be a confidence-weighted mean, which had a property nobody
// intended: corroborating evidence *lowered* the verdict. A visitor whose
// browser reported navigator.webdriver = true and nothing else scored 0.95 in
// the headless category. The same visitor, additionally caught with no plugins,
// a software renderer, a viewport equal to its window and three more automation
// tells, scored 0.686 — because each additional signal, being individually
// weaker than the first, pulled the average down. Seven pieces of corroboration
// made the case weaker than one.
//
// Noisy-OR fixes that. Each detection is independent evidence of strength
// Score×Confidence, and the category is the probability at least one is right:
//
//	category = 1 - ∏(1 - Scoreᵢ × Confidenceᵢ)
//
// Evidence now accumulates: adding a signal can only raise a category, never
// lower it. And it is *more* forgiving of isolated weak evidence than the mean
// was — one detection at score 0.4, confidence 0.5 contributes 0.20 rather than
// setting the whole category to 0.40 — which is the right treatment for a lone
// low-confidence hit on a real user.
//
// Measured on the bench corpus (bench/tools/compare-aggregation.js): human
// median 0.182 → 0.097 and human max 0.260 → 0.171, while agent median rose
// 0.517 → 0.570. Both populations moved in the direction they should.
// dispositiveFloor is the score below which a self-declared automated browser
// cannot fall.
//
// # Why a floor exists at all
//
// The final score is a weighted sum across all eleven categories, so a category
// can contribute at most its own weight no matter how certain it is. A local
// automated browser trips at most the six categories reachable without a
// datacenter IP, a reused fingerprint or a rate-limit hit — about 0.81 of the
// weight — and in practice lands near 0.5. The bench measured exactly that: a
// Playwright browser reporting navigator.webdriver = true, no plugins, a
// software renderer and four more automation tells scored 0.549, i.e.
// "challenge", not "block".
//
// That is the weighted sum working as designed. It expresses "what fraction of
// the total suspicion budget did this visitor consume", and no single fact can
// consume most of that budget. The trouble is that some facts are not
// probabilistic evidence at all — they are the browser saying so.
//
// # What qualifies
//
// Only detections marked Dispositive, and the bar for that mark is that a
// browser cannot produce the signal without being automated:
//
//   - navigator.webdriver = true — a W3C-specified flag whose sole purpose is
//     to tell the page it is under automation.
//   - ChromeDriver / Puppeteer injected globals (chromedriver_cdc,
//     puppeteer_eval, cdp_script_injection), which exist in no ordinary
//     browsing session.
//
// Deliberately excluded, though both look tempting: the "console consumer
// attached" CDP check, because the bench human panel proves it fires on a
// developer with DevTools open; and the Playwright webdriver_configurable
// artifact, which relies on a property-descriptor detail no specification
// guarantees.
//
// # What this does not do
//
// It does not catch a stealth agent, which patches navigator.webdriver before
// the page ever sees it. That is not a regression — such an agent scores the
// same as it did before — and it is the reason the behavioural workstreams
// still matter. The floor closes the case where an agent is not even trying to
// hide, which was previously being waved through with a "challenge".
const dispositiveFloor = 0.9

func applyDispositiveFloor(score float64, detections []DetectionResult) float64 {
	for _, d := range detections {
		if d.Dispositive {
			return math.Max(score, dispositiveFloor)
		}
	}
	return score
}

// Behavioural corroboration floor.
//
// # The problem
//
// A source-patched browser scrubs every JS-observable automation flag at the
// binary level, so it trips no headless, cdp, fingerprint, datacenter or bot
// category. Those weights total 0.59, and the weighted sum silently keeps all of
// it — leaving such a browser a ceiling of 0.41 against a 0.5 threshold. It
// cannot be blocked however obviously robotic its movement is.
//
// Measured, not argued: the corpus sample of that adversary trips seven correct
// behavioural detections and scores 0.234. Every one of them fires; the
// aggregation discards the verdict. This is the same structural flaw that let a
// bare curl through before v1.23.0, landing this time on the behavioural
// detection that is the point of the product.
//
// The flaw is treating absence of environmental evidence as evidence of absence.
// On this adversary a clean environment is not exculpatory — it is the attack
// working.
//
// # The rule
//
// When two or more behavioural categories independently reach 0.5, floor the
// score at 0.6. Corroboration across independent views is itself evidence,
// distinct from any one of them being strong.
//
// # Why these numbers
//
// Swept over a 40-point grid against the labelled corpus
// (bench/tools/sweep-corroboration.js), not chosen by reasoning. The measurement
// that decides it:
//
//	threshold   humans reaching 2+     agents reaching 2+
//	0.30         0 of 126               75 of 75
//	0.40         0 of 126               66 of 75
//	0.50         0 of 126               66 of 75
//	0.60         0 of 126               62 of 75
//	0.70         0 of 126               47 of 75
//
// No human in the panel reaches two agreeing behavioural categories at any
// threshold tested. 0.5 sits mid-region — 0.3, 0.4 and 0.5 behave identically
// and it falls off at 0.6 — so a real captured trace scoring somewhat lower than
// the synthetic one still fires the rule.
//
// Requiring three categories fails outright: all sixteen such combinations leave
// the adversary at 0.234 or 0.423, still allowed. An earlier 3-of-4 rule chosen
// because it "felt conservative" produced results byte-identical to no rule at
// all, because this adversary reaches 0.5 in exactly two categories.
//
// The floor value does not affect separation — every value from 0.5 to 0.8
// separates identically, since it only sets where a caught agent lands. 0.6 is
// therefore a policy choice: the block boundary, kept distinct from the 0.9
// reserved for a browser that declares its own automation.
//
// # What this does not claim
//
// The adversary is one synthetic, hand-authored sample. This shows the
// arithmetic works on the shape the corpus describes, not that it works on a
// real source-patched browser. A captured trace is what would make it evidence.
const (
	// corroborationAgreeAt is the category score counting as one behavioural
	// category agreeing.
	corroborationAgreeAt = 0.5
	// corroborationMinAgree is how many must agree. Two; three never fires.
	corroborationMinAgree = 2
	// corroborationFloor is where an agreeing verdict lands: a block, not the
	// 0.9 reserved for self-declared automation.
	corroborationFloor = 0.6
)

// behaviouralCategories are the categories a browser trips by how it moves
// rather than by what it is. A patched binary can hide what it is; it cannot
// hide that nothing is moving the pointer like a hand.
var behaviouralCategories = []ThreatCategory{
	CategoryVisionAI,
	CategoryBehavioral,
	CategoryAutomation,
	CategoryCDP,
}

func applyCorroborationFloor(score float64, categoryScores map[string]float64) float64 {
	agreeing := 0
	for _, cat := range behaviouralCategories {
		if categoryScores[string(cat)] >= corroborationAgreeAt {
			agreeing++
		}
	}
	if agreeing >= corroborationMinAgree {
		return math.Max(score, corroborationFloor)
	}
	return score
}

func (e *ScoringEngine) calculateCategoryScores(detections []DetectionResult) map[string]float64 {
	// Probability that every detection in a category is wrong; the category
	// score is one minus that.
	survives := make(map[ThreatCategory]float64)

	for _, d := range detections {
		if _, ok := survives[d.Category]; !ok {
			survives[d.Category] = 1.0
		}
		strength := math.Max(0, math.Min(1, d.Score*d.Confidence))
		survives[d.Category] *= 1 - strength
	}

	result := make(map[string]float64)
	for cat, s := range survives {
		result[string(cat)] = math.Min(1.0, 1-s)
	}

	// Fill missing categories
	for cat := range e.weights {
		if _, ok := result[string(cat)]; !ok {
			result[string(cat)] = 0.0
		}
	}

	return result
}

func (e *ScoringEngine) calculateFinalScore(categoryScores map[string]float64) float64 {
	var total float64
	for cat, weight := range e.weights {
		if score, ok := categoryScores[string(cat)]; ok {
			total += score * weight
		}
	}
	return math.Min(1.0, total)
}

// ============================================================
// Token Generation
// ============================================================

// generateToken mints a signed token bound to the source, the site, the score,
// and — via binding — the page that minted it and the action it was minted for.
//
// The binding is what lets a backend reject a token that is valid but was not
// issued for what it is being spent on: an `action=login` token replayed against
// a password-reset endpoint, or a token minted on a site that lifted the key.
//
// Empty strings rather than omitted keys: the signing payload is a sorted-key
// JSON serialisation, so a token whose key set varied with what the browser
// happened to send would be a second payload shape to keep in sync across three
// languages. Fixed shape, empty when unknown.
func (e *ScoringEngine) generateToken(ip, siteKey string, score float64, binding TokenBinding) string {
	ipHash := sha256.Sum256([]byte(ip))

	data := map[string]interface{}{
		"site_key":  siteKey,
		"timestamp": time.Now().Unix(),
		"score":     math.Round(score*1000) / 1000,
		"ip_hash":   hex.EncodeToString(ipHash[:4]),
		"hostname":  binding.Hostname,
		"action":    binding.Action,
		"cdata":     binding.CData,
	}

	payload, _ := json.Marshal(data)
	sig := e.computeSignature(payload)

	data["sig"] = sig
	tokenData, _ := json.Marshal(data)

	// Unpadded base64url, matching server-node and server-python.
	//
	// This used to be padded URLEncoding, which meant a token minted by the Go
	// server could not be decoded by the Node one and vice versa. Nobody noticed
	// because each server only ever verified its own tokens — until a backend
	// started calling siteverify against a fleet where the instance that minted
	// the token is not the instance that validates it. See decodeTokenBase64.
	return base64.RawURLEncoding.EncodeToString(tokenData)
}

// decodeTokenBase64 accepts a token in either padding convention.
//
// Go emitted padded base64url historically and emits unpadded now, so both are
// in circulation during a rolling deploy and for one token lifetime after it.
// Accepting both costs a TrimRight and removes the only reason a valid token
// would be rejected across a version boundary.
func decodeTokenBase64(token string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
}

func (e *ScoringEngine) computeSignature(payload []byte) string {
	h := hmac.New(sha256.New, []byte(e.secretKey))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// ============================================================
// Rate Limiter Methods
// ============================================================

func (rl *RateLimiter) Check(key string, windowSeconds int64, maxRequests int) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().Unix()
	cutoff := now - windowSeconds

	// Clean old entries
	if timestamps, ok := rl.requests[key]; ok {
		newTimestamps := make([]int64, 0)
		for _, t := range timestamps {
			if t > cutoff {
				newTimestamps = append(newTimestamps, t)
			}
		}
		rl.requests[key] = newTimestamps
	}

	count := len(rl.requests[key])

	if count >= maxRequests {
		return true, count
	}

	rl.requests[key] = append(rl.requests[key], now)
	return false, count + 1
}

// ============================================================
// Fingerprint Store Methods
// ============================================================

func (fs *FingerprintStore) Record(fingerprint, ip, siteKey string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	key := siteKey + ":" + fingerprint

	if _, ok := fs.fingerprints[key]; !ok {
		fs.fingerprints[key] = &FingerprintData{
			FirstSeen: time.Now().Unix(),
			Count:     0,
			IPs:       make(map[string]bool),
		}
	}

	fs.fingerprints[key].Count++
	fs.fingerprints[key].IPs[ip] = true

	if _, ok := fs.ipFingerprints[ip]; !ok {
		fs.ipFingerprints[ip] = make(map[string]bool)
	}
	fs.ipFingerprints[ip][fingerprint] = true
}

func (fs *FingerprintStore) GetIPFingerprintCount(ip string) int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fps, ok := fs.ipFingerprints[ip]; ok {
		return len(fps)
	}
	return 0
}

func (fs *FingerprintStore) GetFingerprintIPCount(fingerprint, siteKey string) int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	key := siteKey + ":" + fingerprint
	if data, ok := fs.fingerprints[key]; ok {
		return len(data.IPs)
	}
	return 0
}

// ============================================================
// Helper Functions
// ============================================================

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

func getFloat(m map[string]interface{}, key string) float64 {
	return getFloatDefault(m, key, 0)
}

// getFloatDefault reads a numeric signal, falling back to def when the client
// did not send it.
//
// getFloat's zero default silently conflates "the client reported 0" with "the
// client reported nothing", which for a signal where low means suspicious turns
// an absent field into an accusation. Callers scoring that kind of signal should
// pass the client's own neutral sentinel instead.
func getFloatDefault(m map[string]interface{}, key string, def float64) float64 {
	if m == nil {
		return def
	}
	if v, ok := m[key].(float64); ok {
		return v
	}
	if v, ok := m[key].(int); ok {
		return float64(v)
	}
	return def
}

func getString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

// serverContextKey holds request facts the server establishes itself, kept
// apart from the client-supplied signal tree it sits beside.
const serverContextKey = "serverContext"

// SetInteractionMode records whether this request came from a rendered widget
// (a real click target) or from invisible scoring.
//
// approachPoints, approachDirectness, clickPrecision, explorationRatio and
// overshootCorrections are all produced by the client's analyzeClick(), which
// only runs when there is a widget to click. Invisible scoring never calls it,
// so those fields are absent and read back as 0 — which is indistinguishable
// from "the pointer teleported onto the target". Production logs showed the
// approach check firing on 100% of invisible calls for exactly that reason.
//
// The mode comes from the endpoint, never from the signals: a client that
// could claim "invisible" could switch these checks off on the widget path.
func SetInteractionMode(signals map[string]interface{}, widget bool) {
	if signals == nil {
		return
	}
	ctx, ok := signals[serverContextKey].(map[string]interface{})
	if !ok {
		ctx = make(map[string]interface{})
		signals[serverContextKey] = ctx
	}
	ctx["widgetInteraction"] = widget
}

// hasWidgetInteraction reports whether click-derived behavioural fields carry
// meaning for this request. Absent context means widget mode: that is the
// long-standing behaviour, and it keeps the checks on for any caller using the
// plain Verify entry point.
func hasWidgetInteraction(signals map[string]interface{}) bool {
	ctx := getMap(signals, serverContextKey)
	if ctx == nil {
		return true
	}
	if v, ok := ctx["widgetInteraction"].(bool); ok {
		return v
	}
	return true
}
