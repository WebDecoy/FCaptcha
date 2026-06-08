package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// resolveClientPath finds client/fcaptcha.js at startup so the widget can be
// served from the same origin as the API (matches the Node and Python servers).
// FCAPTCHA_CLIENT_PATH wins; otherwise we probe a few sensible defaults so this
// works for `go run .` from server-go/, a built binary alongside the repo, and
// the Docker image (which COPYs the file to /app/client/fcaptcha.js).
func resolveClientPath() string {
	if p := os.Getenv("FCAPTCHA_CLIENT_PATH"); p != "" {
		return p
	}
	candidates := []string{
		"./client/fcaptcha.js",
		"../client/fcaptcha.js",
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "client", "fcaptcha.js"),
			filepath.Join(dir, "..", "client", "fcaptcha.js"),
		)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func main() {
	// Configuration
	secretKey := os.Getenv("FCAPTCHA_SECRET")
	if secretKey == "" {
		secretKey = "dev-secret-change-in-production"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	redisURL := os.Getenv("REDIS_URL")

	// Initialize scoring engine
	var engine *ScoringEngine
	if redisURL != "" {
		engine = NewScoringEngineWithRedis(secretKey, redisURL)
	} else {
		engine = NewScoringEngine(secretKey)
	}

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// CORS for widget
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-Site-Key"},
		ExposedHeaders:   []string{"X-Request-Id"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Serve the widget from the same origin as the API (matches server-node
	// and server-python). 404 if the client file isn't reachable so callers
	// see the configuration problem instead of a confusing empty response.
	clientPath := resolveClientPath()
	if clientPath == "" {
		log.Printf("warning: client/fcaptcha.js not found; /fcaptcha.js will return 404. Set FCAPTCHA_CLIENT_PATH to override.")
	} else {
		log.Printf("serving /fcaptcha.js from %s", clientPath)
	}
	r.Get("/fcaptcha.js", func(w http.ResponseWriter, r *http.Request) {
		if clientPath == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		http.ServeFile(w, r, clientPath)
	})
	r.Handle("/demo/*", http.StripPrefix("/demo/", http.FileServer(http.Dir("./static/demo"))))

	// Routes
	r.Get("/health", healthHandler)
	r.Post("/api/verify", verifyHandler(engine))
	r.Post("/api/score", invisibleScoreHandler(engine))
	r.Post("/api/token/verify", tokenVerifyHandler(engine))
	r.Get("/api/pow/challenge", powChallengeHandler(engine))
	r.Get("/api/challenge", challengeHandler(engine))

	// Server
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// pprof debug server on localhost:3001 (not exposed externally)
	go func() {
		if err := http.ListenAndServe("127.0.0.1:3001", nil); err != nil {
			log.Printf("pprof server error: %v", err)
		}
	}()

	// Graceful shutdown
	go func() {
		log.Printf("FCaptcha server starting on port %s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// PowTiming from client (separate from committed signals)
type PowTiming struct {
	Duration   float64 `json:"duration"`
	Iterations int     `json:"iterations"`
	Difficulty int     `json:"difficulty"`
}

// VerifyRequest is the request body for verification
type VerifyRequest struct {
	SiteKey     string                 `json:"siteKey"`
	Signals     map[string]interface{} `json:"signals"`
	SignalsJson string                 `json:"signalsJson,omitempty"`
	PowSolution *PoWSolution           `json:"powSolution,omitempty"`
	PowTiming   *PowTiming             `json:"powTiming,omitempty"`
}

// VerifyResponse is the response for verification
type VerifyResponse struct {
	Success        bool               `json:"success"`
	Score          float64            `json:"score"`
	Token          string             `json:"token,omitempty"`
	Timestamp      int64              `json:"timestamp"`
	Recommendation string             `json:"recommendation"`
	CategoryScores map[string]float64 `json:"categoryScores,omitempty"`
	Detections     []DetectionInfo    `json:"detections,omitempty"`
}

type DetectionInfo struct {
	Category   string  `json:"category"`
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

func verifyHandler(engine *ScoringEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		ip := r.RemoteAddr
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			ip = realIP
		} else if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			// Take the first IP in the chain
			parts := strings.Split(forwardedFor, ",")
			ip = strings.TrimSpace(parts[0])
		}

		userAgent := r.Header.Get("User-Agent")

		// Collect headers for analysis
		headers := make(map[string]string)
		for key, values := range r.Header {
			if len(values) > 0 {
				headers[strings.ToLower(key)] = values[0]
			}
		}

		// JA3 hash (if provided by reverse proxy like nginx or Cloudflare)
		ja3Hash := r.Header.Get("X-JA3-Hash")

		// Verify signal commitment
		signals := req.Signals
		clientSignalsHash := ""
		if req.PowSolution != nil {
			clientSignalsHash = req.PowSolution.SignalsHash
		}
		extraDetections := make([]DetectionResult, 0)
		if req.SignalsJson != "" && clientSignalsHash != "" {
			computedHash := sha256.Sum256([]byte(req.SignalsJson))
			computedHashHex := hex.EncodeToString(computedHash[:])
			if computedHashHex != clientSignalsHash {
				extraDetections = append(extraDetections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.95,
					Confidence: 0.95,
					Reason:     "Signals tampered after PoW (signalsHash mismatch)",
				})
			}
			// Use signalsJson as the canonical signals source
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(req.SignalsJson), &parsed); err == nil {
				signals = parsed
			}
		}

		// Inject powTiming into signals.temporal.pow
		if req.PowTiming != nil {
			temporal, ok := signals["temporal"].(map[string]interface{})
			if !ok {
				temporal = make(map[string]interface{})
				signals["temporal"] = temporal
			}
			temporal["pow"] = map[string]interface{}{
				"duration":   req.PowTiming.Duration,
				"iterations": float64(req.PowTiming.Iterations),
				"difficulty": float64(req.PowTiming.Difficulty),
			}
		}

		result := engine.VerifyWithHeaders(signals, ip, req.SiteKey, userAgent, headers, ja3Hash, req.PowSolution)

		// Add signal commitment detections to results
		if len(extraDetections) > 0 {
			result.Detections = append(extraDetections, result.Detections...)
		}

		// Convert detections
		detections := make([]DetectionInfo, 0, len(result.Detections))
		for _, d := range result.Detections {
			detections = append(detections, DetectionInfo{
				Category:   string(d.Category),
				Score:      d.Score,
				Confidence: d.Confidence,
				Reason:     d.Reason,
			})
		}

		resp := VerifyResponse{
			Success:        result.Success,
			Score:          result.Score,
			Token:          result.Token,
			Timestamp:      result.Timestamp,
			Recommendation: result.Recommendation,
			CategoryScores: result.CategoryScores,
			Detections:     detections,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// InvisibleScoreRequest for background scoring
type InvisibleScoreRequest struct {
	SiteKey     string                 `json:"siteKey"`
	Signals     map[string]interface{} `json:"signals"`
	SignalsJson string                 `json:"signalsJson,omitempty"`
	Action      string                 `json:"action"`
	PowSolution *PoWSolution           `json:"powSolution,omitempty"`
	PowTiming   *PowTiming             `json:"powTiming,omitempty"`
}

func invisibleScoreHandler(engine *ScoringEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req InvisibleScoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		ip := r.RemoteAddr
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			ip = realIP
		}

		userAgent := r.Header.Get("User-Agent")

		// Collect headers for analysis
		scoreHeaders := make(map[string]string)
		for key, values := range r.Header {
			if len(values) > 0 {
				scoreHeaders[strings.ToLower(key)] = values[0]
			}
		}
		ja3 := r.Header.Get("X-JA3-Hash")

		// Verify signal commitment
		signals := req.Signals
		clientSigHash := ""
		if req.PowSolution != nil {
			clientSigHash = req.PowSolution.SignalsHash
		}
		scoreExtraDetections := make([]DetectionResult, 0)
		if req.SignalsJson != "" && clientSigHash != "" {
			cHash := sha256.Sum256([]byte(req.SignalsJson))
			cHashHex := hex.EncodeToString(cHash[:])
			if cHashHex != clientSigHash {
				scoreExtraDetections = append(scoreExtraDetections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.95,
					Confidence: 0.95,
					Reason:     "Signals tampered after PoW (signalsHash mismatch)",
				})
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(req.SignalsJson), &parsed); err == nil {
				signals = parsed
			}
		}

		// Inject powTiming
		if req.PowTiming != nil {
			temporal, ok := signals["temporal"].(map[string]interface{})
			if !ok {
				temporal = make(map[string]interface{})
				signals["temporal"] = temporal
			}
			temporal["pow"] = map[string]interface{}{
				"duration":   req.PowTiming.Duration,
				"iterations": float64(req.PowTiming.Iterations),
				"difficulty": float64(req.PowTiming.Difficulty),
			}
		}

		result := engine.VerifyWithHeaders(signals, ip, req.SiteKey, userAgent, scoreHeaders, ja3, req.PowSolution)
		if len(scoreExtraDetections) > 0 {
			result.Detections = append(scoreExtraDetections, result.Detections...)
		}

		resp := map[string]interface{}{
			"success":        result.Success,
			"score":          result.Score,
			"token":          result.Token,
			"action":         req.Action,
			"recommendation": result.Recommendation,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// TokenVerifyRequest for server-side token verification
type TokenVerifyRequest struct {
	Token  string `json:"token"`
	Secret string `json:"secret"`
}

func tokenVerifyHandler(engine *ScoringEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TokenVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Extract client IP for verification
		ip := r.RemoteAddr
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			ip = realIP
		} else if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			parts := strings.Split(forwardedFor, ",")
			ip = strings.TrimSpace(parts[0])
		}

		result := engine.VerifyTokenWithIP(req.Token, ip)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// PoWChallengeResponse for the PoW challenge endpoint
type PoWChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Prefix      string `json:"prefix"`
	Difficulty  int    `json:"difficulty"`
	ExpiresAt   int64  `json:"expiresAt"`
	Nonce       string `json:"nonce"`
	Sig         string `json:"sig"`
}

func powChallengeHandler(engine *ScoringEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		siteKey := r.URL.Query().Get("siteKey")
		if siteKey == "" {
			siteKey = "default"
		}

		ip := r.RemoteAddr
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			ip = realIP
		} else if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			parts := strings.Split(forwardedFor, ",")
			ip = strings.TrimSpace(parts[0])
		}

		isDatacenter := IsDatacenterIP(ip)
		challenge := engine.GeneratePoWChallenge(siteKey, ip, isDatacenter)

		resp := PoWChallengeResponse{
			ChallengeID: challenge.ID,
			Prefix:      challenge.Prefix,
			Difficulty:  challenge.Difficulty,
			ExpiresAt:   challenge.ExpiresAt,
			Nonce:       challenge.Nonce,
			Sig:         challenge.Sig,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// ChallengeResponse for widget initialization
type ChallengeResponse struct {
	ChallengeID   string `json:"challengeId"`
	PoWDifficulty int    `json:"powDifficulty"`
	Expires       int64  `json:"expires"`
}

func challengeHandler(engine *ScoringEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challenge := engine.GenerateChallenge()

		resp := ChallengeResponse{
			ChallengeID:   challenge.ID,
			PoWDifficulty: challenge.Difficulty,
			Expires:       challenge.Expires,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
