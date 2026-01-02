package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

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
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
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

	// Routes
	r.Get("/health", healthHandler)
	r.Post("/api/verify", verifyHandler(engine))
	r.Post("/api/score", invisibleScoreHandler(engine))
	r.Post("/api/token/verify", tokenVerifyHandler(engine))
	r.Get("/api/challenge", challengeHandler(engine))

	// Server
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

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

// VerifyRequest is the request body for verification
type VerifyRequest struct {
	SiteKey string                 `json:"siteKey"`
	Signals map[string]interface{} `json:"signals"`
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

		result := engine.VerifyWithHeaders(req.Signals, ip, req.SiteKey, userAgent, headers, ja3Hash)

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
	SiteKey string                 `json:"siteKey"`
	Signals map[string]interface{} `json:"signals"`
	Action  string                 `json:"action"`
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

		result := engine.Verify(req.Signals, ip, req.SiteKey, userAgent)

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
