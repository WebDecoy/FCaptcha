package main

import (
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
)

// ThreatCategory represents types of detected threats
type ThreatCategory string

const (
	CategoryVisionAI    ThreatCategory = "vision_ai"
	CategoryHeadless    ThreatCategory = "headless"
	CategoryAutomation  ThreatCategory = "automation"
	CategoryBot         ThreatCategory = "bot"
	CategoryCaptchaFarm ThreatCategory = "captcha_farm"
	CategoryBehavioral  ThreatCategory = "behavioral"
	CategoryFingerprint ThreatCategory = "fingerprint"
	CategoryRateLimit   ThreatCategory = "rate_limit"
	CategoryDatacenter  ThreatCategory = "datacenter"
	CategoryTorVPN      ThreatCategory = "tor_vpn"
)

// DetectionResult from a single check
type DetectionResult struct {
	Category   ThreatCategory
	Score      float64
	Confidence float64
	Reason     string
	Details    map[string]interface{}
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
}

// PoWChallenge for server-verified proof of work
type PoWChallenge struct {
	ID         string `json:"challengeId"`
	SiteKey    string `json:"siteKey"`
	Prefix     string `json:"prefix"`
	Difficulty int    `json:"difficulty"`
	Timestamp  int64  `json:"timestamp"`
	ExpiresAt  int64  `json:"expiresAt"`
	Sig        string `json:"sig"`
	IP         string `json:"-"` // Not sent to client
}

// PoWSolution from client
type PoWSolution struct {
	ChallengeID string `json:"challengeId"`
	Nonce       int    `json:"nonce"`
	Hash        string `json:"hash"`
}

// PoWVerifyResult is the result of PoW verification
type PoWVerifyResult struct {
	Valid      bool
	Reason     string
	Difficulty int
}

// PoWChallengeStore manages challenges
type PoWChallengeStore struct {
	mu            sync.RWMutex
	challenges    map[string]*PoWChallenge
	usedSolutions map[string]bool
}

func newPoWChallengeStore() *PoWChallengeStore {
	store := &PoWChallengeStore{
		challenges:    make(map[string]*PoWChallenge),
		usedSolutions: make(map[string]bool),
	}
	// Start cleanup goroutine
	go store.cleanupLoop()
	return store
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

	// Clear used solutions if too many
	if len(s.usedSolutions) > 10000 {
		s.usedSolutions = make(map[string]bool)
	}
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
	weights          map[ThreatCategory]float64
	uaPatterns       []*regexp.Regexp
}

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

// NewScoringEngine creates a new engine
func NewScoringEngine(secretKey string) *ScoringEngine {
	return &ScoringEngine{
		secretKey:        secretKey,
		rateLimiter:      newRateLimiter(),
		fingerprintStore: newFingerprintStore(),
		powStore:         newPoWChallengeStore(),
		weights: map[ThreatCategory]float64{
			CategoryVisionAI:    0.15,
			CategoryHeadless:    0.15,
			CategoryAutomation:  0.10,
			CategoryBehavioral:  0.20,
			CategoryFingerprint: 0.10,
			CategoryRateLimit:   0.05,
			CategoryDatacenter:  0.10,
			CategoryTorVPN:      0.05,
			CategoryBot:         0.10,
		},
		uaPatterns: compileUAPatterns(),
	}
}

// NewScoringEngineWithRedis creates engine with Redis backend
func NewScoringEngineWithRedis(secretKey, redisURL string) *ScoringEngine {
	// TODO: Implement Redis-backed storage
	return NewScoringEngine(secretKey)
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

// VerifyWithHeaders performs full verification with HTTP headers
func (e *ScoringEngine) VerifyWithHeaders(signals map[string]interface{}, ip, siteKey, userAgent string, headers map[string]string, ja3Hash string) *VerificationResult {
	detections := make([]DetectionResult, 0)

	// Behavioral detectors
	detections = append(detections, e.detectVisionAI(signals)...)
	detections = append(detections, e.detectHeadless(signals, userAgent)...)
	detections = append(detections, e.detectAutomation(signals)...)
	detections = append(detections, e.detectBehavioral(signals)...)
	detections = append(detections, e.detectFingerprint(signals, ip, siteKey)...)
	detections = append(detections, e.detectRateAbuse(ip, siteKey)...)

	// Network/infrastructure detectors
	detections = append(detections, e.CheckIPReputation(ip)...)
	detections = append(detections, e.CheckBrowserConsistency(userAgent, signals)...)

	// HTTP-level detectors
	if headers != nil {
		detections = append(detections, e.AnalyzeHeaders(headers)...)
	}

	// TLS fingerprint (if available from reverse proxy)
	if ja3Hash != "" {
		detections = append(detections, e.CheckJA3Fingerprint(ja3Hash)...)
	}

	// Form interaction analysis (credential stuffing & spam detection)
	if formAnalysis, ok := signals["formAnalysis"].(map[string]interface{}); ok {
		detections = append(detections, e.AnalyzeFormInteraction(formAnalysis)...)
	}

	// Calculate scores
	categoryScores := e.calculateCategoryScores(detections)
	finalScore := e.calculateFinalScore(categoryScores)

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

	success := finalScore < 0.5

	var token string
	if success {
		token = e.generateToken(ip, siteKey, finalScore)
	}

	return &VerificationResult{
		Success:        success,
		Score:          finalScore,
		Token:          token,
		Timestamp:      time.Now().Unix(),
		Detections:     detections,
		CategoryScores: categoryScores,
		Recommendation: recommendation,
	}
}

// Verify performs full verification (backward compatible)
func (e *ScoringEngine) Verify(signals map[string]interface{}, ip, siteKey, userAgent string) *VerificationResult {
	return e.VerifyWithHeaders(signals, ip, siteKey, userAgent, nil, "")
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

	now := time.Now().UnixMilli()
	expiresAt := now + (5 * 60 * 1000) // 5 minutes

	// Difficulty scaling
	difficulty := 4 // Default: ~100-500ms on average hardware
	if isDatacenter {
		difficulty = 5 // Harder for datacenter IPs
	}

	// Check rate for this IP
	rateKey := "pow:" + siteKey + ":" + ip
	_, count := e.rateLimiter.Check(rateKey, 60, 20)
	if count > 10 {
		difficulty = min(6, difficulty+1)
	}

	prefix := challengeID + ":" + formatInt64(now) + ":" + formatInt(difficulty)

	challenge := &PoWChallenge{
		ID:         challengeID,
		SiteKey:    siteKey,
		Prefix:     prefix,
		Difficulty: difficulty,
		Timestamp:  now,
		ExpiresAt:  expiresAt,
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
	})
	h := hmac.New(sha256.New, []byte(e.secretKey))
	h.Write(sigData)
	challenge.Sig = hex.EncodeToString(h.Sum(nil))[:16]

	// Store challenge
	e.powStore.mu.Lock()
	e.powStore.challenges[challengeID] = challenge
	e.powStore.mu.Unlock()

	return challenge
}

// VerifyPoWSolution verifies a PoW solution from the client
func (e *ScoringEngine) VerifyPoWSolution(solution *PoWSolution, siteKey string) PoWVerifyResult {
	if solution == nil || solution.ChallengeID == "" {
		return PoWVerifyResult{Valid: false, Reason: "no_solution"}
	}

	e.powStore.mu.Lock()
	defer e.powStore.mu.Unlock()

	challenge, ok := e.powStore.challenges[solution.ChallengeID]
	if !ok {
		return PoWVerifyResult{Valid: false, Reason: "challenge_not_found"}
	}

	now := time.Now().UnixMilli()
	if now > challenge.ExpiresAt {
		delete(e.powStore.challenges, solution.ChallengeID)
		return PoWVerifyResult{Valid: false, Reason: "challenge_expired"}
	}

	if challenge.SiteKey != siteKey {
		return PoWVerifyResult{Valid: false, Reason: "site_key_mismatch"}
	}

	// Check if solution was already used
	solutionKey := solution.ChallengeID + ":" + formatInt(solution.Nonce)
	if e.powStore.usedSolutions[solutionKey] {
		return PoWVerifyResult{Valid: false, Reason: "solution_already_used"}
	}

	// Verify the hash
	input := challenge.Prefix + ":" + formatInt(solution.Nonce)
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

	// Mark solution as used
	e.powStore.usedSolutions[solutionKey] = true

	// Delete challenge (one-time use)
	delete(e.powStore.challenges, solution.ChallengeID)

	return PoWVerifyResult{Valid: true, Difficulty: challenge.Difficulty}
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
func (e *ScoringEngine) VerifyToken(token string) map[string]interface{} {
	result := make(map[string]interface{})

	decoded, err := base64.URLEncoding.DecodeString(token)
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

	result["valid"] = true
	result["site_key"] = data["site_key"]
	result["timestamp"] = data["timestamp"]
	result["score"] = data["score"]
	return result
}

// ============================================================
// Detection Methods
// ============================================================

func (e *ScoringEngine) detectVisionAI(signals map[string]interface{}) []DetectionResult {
	results := make([]DetectionResult, 0)

	behavioral := getMap(signals, "behavioral")
	temporal := getMap(signals, "temporal")

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

	// Check micro-tremor (humans have natural hand shake)
	microTremor := getFloat(behavioral, "microTremorScore")
	if microTremor < 0.15 {
		results = append(results, DetectionResult{
			Category:   CategoryVisionAI,
			Score:      0.7,
			Confidence: 0.6,
			Reason:     "Mouse movement lacks natural micro-tremor",
			Details:    map[string]interface{}{"microTremorScore": microTremor},
		})
	}

	// Check approach directness
	approachDirectness := getFloat(behavioral, "approachDirectness")
	if approachDirectness > 0.95 {
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

	// No exploration before click
	explorationRatio := getFloat(behavioral, "explorationRatio")
	trajectoryLength := getFloat(behavioral, "trajectoryLength")
	if explorationRatio < 0.05 && trajectoryLength > 50 {
		results = append(results, DetectionResult{
			Category:   CategoryVisionAI,
			Score:      0.4,
			Confidence: 0.4,
			Reason:     "No exploratory mouse movement before click",
			Details:    map[string]interface{}{"explorationRatio": explorationRatio},
		})
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
			Category:   CategoryHeadless,
			Score:      0.95,
			Confidence: 0.95,
			Reason:     "WebDriver detected (navigator.webdriver = true)",
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

func (e *ScoringEngine) detectBehavioral(signals map[string]interface{}) []DetectionResult {
	results := make([]DetectionResult, 0)

	behavioral := getMap(signals, "behavioral")
	temporal := getMap(signals, "temporal")

	// Velocity variance
	velocityVariance := getFloat(behavioral, "velocityVariance")
	trajectoryLength := getFloat(behavioral, "trajectoryLength")
	if velocityVariance < 0.02 && trajectoryLength > 50 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.6,
			Confidence: 0.6,
			Reason:     "Mouse velocity too consistent",
			Details:    map[string]interface{}{"velocityVariance": velocityVariance},
		})
	}

	// Overshoot corrections
	overshoots := getFloat(behavioral, "overshootCorrections")
	if overshoots == 0 && trajectoryLength > 200 {
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
	} else if interactionTime > 60000 {
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
	} else if eventRate > 0 && eventRate < 10 {
		results = append(results, DetectionResult{
			Category:   CategoryBehavioral,
			Score:      0.4,
			Confidence: 0.4,
			Reason:     "Mouse event rate abnormally low",
		})
	}

	// No scroll/keyboard
	scrollEvents := getFloat(behavioral, "scrollEvents")
	keyEvents := getFloat(behavioral, "keyEvents")
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
	totalPoints := getFloat(behavioral, "totalPoints")
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

func (e *ScoringEngine) calculateCategoryScores(detections []DetectionResult) map[string]float64 {
	categoryTotals := make(map[ThreatCategory]struct {
		weightedSum float64
		totalWeight float64
	})

	for _, d := range detections {
		totals := categoryTotals[d.Category]
		totals.weightedSum += d.Score * d.Confidence
		totals.totalWeight += d.Confidence
		categoryTotals[d.Category] = totals
	}

	result := make(map[string]float64)
	for cat, totals := range categoryTotals {
		if totals.totalWeight > 0 {
			result[string(cat)] = math.Min(1.0, totals.weightedSum/totals.totalWeight)
		}
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

func (e *ScoringEngine) generateToken(ip, siteKey string, score float64) string {
	ipHash := sha256.Sum256([]byte(ip))

	data := map[string]interface{}{
		"site_key":  siteKey,
		"timestamp": time.Now().Unix(),
		"score":     math.Round(score*1000) / 1000,
		"ip_hash":   hex.EncodeToString(ipHash[:4]),
	}

	payload, _ := json.Marshal(data)
	sig := e.computeSignature(payload)

	data["sig"] = sig
	tokenData, _ := json.Marshal(data)

	return base64.URLEncoding.EncodeToString(tokenData)
}

func (e *ScoringEngine) computeSignature(payload []byte) string {
	h := hmac.New(sha256.New, []byte(e.secretKey))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))[:16]
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
	if m == nil {
		return 0
	}
	if v, ok := m[key].(float64); ok {
		return v
	}
	if v, ok := m[key].(int); ok {
		return float64(v)
	}
	return 0
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
