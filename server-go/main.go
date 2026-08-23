package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	webbotauth "github.com/WebDecoy/web-bot-auth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

const maxRequestBodyBytes int64 = 64 * 1024

// limitRequestBody rejects oversized requests before JSON or form decoding.
// Reading at most limit+1 bytes keeps the memory bound explicit and lets every
// handler, including the compatibility endpoints, return the same 413 status.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxRequestBodyBytes {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(map[string]string{"error": "request_too_large"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

// resolveClientPath finds fcaptcha.js at startup so the widget can be served
// from the same origin as the API (matches the Node and Python servers).
// FCAPTCHA_CLIENT_PATH wins; otherwise probe the layouts this binary actually
// ships in.
//
// The `static/` entry is load-bearing: docker/Dockerfile copies the widget to
// /app/static/fcaptcha.js, and /demo/ is served from ./static/demo just below.
// This list and that Dockerfile have to agree, and a mismatch is silent — the
// widget endpoint simply returns 404 while the file sits in the image.
//
// docker-smoke.yml builds each image and fetches /fcaptcha.js so the two cannot
// drift apart unnoticed. If you move the widget in a Dockerfile, add its new
// location here.
func resolveClientPath() string {
	if p := os.Getenv("FCAPTCHA_CLIENT_PATH"); p != "" {
		return p
	}
	candidates := []string{
		"./client/fcaptcha.js",
		"../client/fcaptcha.js",
		"./static/fcaptcha.js", // docker/Dockerfile layout
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "client", "fcaptcha.js"),
			filepath.Join(dir, "..", "client", "fcaptcha.js"),
			filepath.Join(dir, "static", "fcaptcha.js"),
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

// pprofEnabled reports whether the optional pprof debug server should start,
// based on FCAPTCHA_PPROF (1/true/yes/on, case-insensitive). Off by default.
func pprofEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("FCAPTCHA_PPROF"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// verdictLoggingEnabled is set once at startup from FCAPTCHA_LOG_VERDICTS.
// Off by default: a self-hosted FCaptcha emits no per-request logs unless the
// operator opts in. When on, each /api/verify and /api/score request logs one
// privacy-safe JSON line (score, recommendation, category scores, and per-hit
// category/score/confidence) so operators can observe and tune detection.
//
// It deliberately omits IP address, user agent, and raw signal payloads — and by
// default the free-text detection Reason, which can interpolate visitor-derived
// data (reverse-DNS hostname, UA/header fragments, client field ids). Only the
// detection category enum and numeric score/confidence are logged.
var verdictLoggingEnabled bool

// verdictLogIncludeRaw additionally includes the free-text detection Reason in
// each logged verdict. Off by default and separate from verdictLoggingEnabled
// because reasons can carry visitor-derived data; only enable it in trusted,
// debugging contexts with no privacy obligations. Controlled by
// FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW.
var verdictLogIncludeRaw bool

// verdictLog writes pure JSON lines (no timestamp prefix) so they pipe cleanly
// into jq / log processors. The host platform supplies its own timestamps.
var verdictLog = log.New(os.Stdout, "", 0)

// envFlagEnabled reports whether an env var is set truthy (1/true/yes/on, case-insensitive).
func envFlagEnabled(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

const insecureDefaultSecret = "dev-secret-change-in-production"

func signingSecretFromEnv(getenv func(string) string) (string, error) {
	secret := strings.TrimSpace(getenv("FCAPTCHA_SECRET"))
	if secret != "" && secret != insecureDefaultSecret {
		return secret, nil
	}
	switch strings.ToLower(strings.TrimSpace(getenv("FCAPTCHA_INSECURE_DEV_MODE"))) {
	case "1", "true", "yes", "on":
		log.Printf("WARNING: FCAPTCHA_INSECURE_DEV_MODE enabled; tokens use a public signing key. Never expose this server to a network.")
		return insecureDefaultSecret, nil
	}
	return "", fmt.Errorf("FCAPTCHA_SECRET is required and must not be the public development key; for local-only development, explicitly set FCAPTCHA_INSECURE_DEV_MODE=1")
}

// logVerdict emits one privacy-safe JSON line describing a scoring outcome.
// No-op unless verdict logging is enabled. Omits IP, user agent, and raw signals;
// the free-text detection Reason is included only when verdictLogIncludeRaw is set.
func logVerdict(endpoint, siteKey string, result *VerificationResult) {
	if !verdictLoggingEnabled || result == nil {
		return
	}
	detections := make([]map[string]interface{}, 0, len(result.Detections))
	for _, d := range result.Detections {
		det := map[string]interface{}{
			"category":   string(d.Category),
			"score":      d.Score,
			"confidence": d.Confidence,
		}
		if verdictLogIncludeRaw {
			det["reason"] = d.Reason
		}
		detections = append(detections, det)
	}
	line, err := json.Marshal(map[string]interface{}{
		"event":          "verdict",
		"endpoint":       endpoint,
		"siteKey":        siteKey,
		"success":        result.Success,
		"score":          result.Score,
		"recommendation": result.Recommendation,
		"categoryScores": result.CategoryScores,
		"detections":     detections,
	})
	if err != nil {
		return
	}
	verdictLog.Println(string(line))
}

func main() {
	// Route stdlib logs to stdout. Go's log package defaults to stderr, which
	// some hosts (e.g. Railway) classify as error-level — making routine startup
	// and warning lines look like failures. Operational logs belong on stdout.
	log.SetOutput(os.Stdout)

	// Configuration
	secretKey, err := signingSecretFromEnv(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}

	// The credential a backend presents to validate a token. Defaults to the
	// signing key, which is what the README has always documented, but can be
	// separated: the signing key is a long-lived secret that must never leave
	// the server, while this one is handed to every backend that verifies.
	// Splitting them means a leaked verify credential does not let the holder
	// mint tokens.
	verifySecret := os.Getenv("FCAPTCHA_VERIFY_SECRET")
	if verifySecret == "" {
		verifySecret = secretKey
	}

	// Token verification used to accept anyone who could reach the endpoint: all
	// three servers read `secret` out of the body and dropped it. Enforcing it
	// is a breaking change for deployments that never sent one, so there is one
	// release of escape hatch before the parameter becomes mandatory outright.
	requireVerifySecret := !envFlagEnabled("FCAPTCHA_LEGACY_UNAUTH_VERIFY")
	if !requireVerifySecret {
		log.Printf("WARNING: FCAPTCHA_LEGACY_UNAUTH_VERIFY enabled — token verification accepts any caller. This escape hatch will be removed; send `secret` from your backend instead.")
	}

	verdictLoggingEnabled = envFlagEnabled("FCAPTCHA_LOG_VERDICTS")
	verdictLogIncludeRaw = envFlagEnabled("FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW")
	if verdictLoggingEnabled {
		log.Printf("verdict logging enabled (FCAPTCHA_LOG_VERDICTS); emitting privacy-safe JSON per verify/score")
		if verdictLogIncludeRaw {
			log.Printf("WARNING: FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW enabled — verdict logs include free-text detection reasons that may contain visitor-derived data (hostnames, UA/header fragments, field ids). Do not enable where you have privacy obligations.")
		}
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

	// Which peers may speak for another client. Must be resolved before the
	// handlers are mounted; see clientip.go.
	proxyTrust := ProxyTrustFromEnv()
	log.Printf("trusted proxies: %s", proxyTrust.Describe())

	// siteKey is client-supplied and validated against no registry, yet it is
	// the first component of every rate-limit, fingerprint and challenge
	// partition key. See sitekeys.go.
	siteKeys := SiteKeyGuardFromEnv()
	log.Printf("site keys: %s", siteKeys.Describe())

	// Holds a JA4 fingerprint per live connection, populated during the TLS
	// handshake. Stays empty unless this process terminates TLS — see ja4.go.
	ja4s := newJA4Store(maxTrackedJA4Conns)

	// Middleware
	//
	// Deliberately no middleware.RealIP: it overwrites r.RemoteAddr from
	// X-Forwarded-For/X-Real-IP for every caller, which would hand a spoofed
	// address to the datacenter, Tor/VPN and rate-limit checks and leave no
	// un-forged source to fall back on. ProxyTrust.ClientIP does the same job
	// gated on the peer.
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(limitRequestBody)

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
	// GET and HEAD both, because chi's r.Get registers GET alone and a bare HEAD
	// then answers 405. Caching proxies revalidate with HEAD and uptime monitors
	// commonly probe with it, so a 405 here reads as an outage on a working
	// server. http.ServeFile already omits the body for HEAD.
	serveClient := func(w http.ResponseWriter, r *http.Request) {
		if clientPath == "" {
			http.NotFound(w, r)
			return
		}
		// charset is not optional here. A classic script served without one is
		// decoded using the *document's* encoding, so the widget's translated
		// strings render as mojibake on any page that is not already UTF-8.
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		http.ServeFile(w, r, clientPath)
	}
	r.Get("/fcaptcha.js", serveClient)
	r.Head("/fcaptcha.js", serveClient)
	r.Handle("/demo/*", http.StripPrefix("/demo/", http.FileServer(http.Dir("./static/demo"))))

	// Routes
	r.Get("/health", healthHandler)
	r.Head("/health", healthHandler)
	r.Post("/api/verify", verifyHandler(engine, proxyTrust, siteKeys, ja4s))
	r.Post("/api/score", invisibleScoreHandler(engine, proxyTrust, siteKeys, ja4s))
	r.Post("/api/token/verify", tokenVerifyHandler(engine, proxyTrust, verifySecret, requireVerifySecret))
	r.Get("/api/pow/challenge", powChallengeHandler(engine, proxyTrust, siteKeys))
	r.Get("/api/challenge", challengeHandler(engine))

	// Turnstile / reCAPTCHA / hCaptcha drop-in compatibility.
	//
	// Same contract, three paths, because the path is hardcoded in the SDKs and
	// plugins we want to be usable against FCaptcha: pointing an existing
	// integration at this server should be a base-URL change and nothing else.
	// See siteverify.go for the adapter itself.
	log.Printf("allowed hostnames: %s", engine.allowedHostnames.Describe())
	compat := siteverifyHandler(engine, proxyTrust, NewIdempotencyStore(), verifySecret, requireVerifySecret)
	r.Post("/turnstile/v0/siteverify", compat)
	r.Post("/recaptcha/api/siteverify", compat)
	r.Post("/siteverify", compat)

	// Server
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Optional pprof debug server, off by default. Enable with FCAPTCHA_PPROF=1
	// (or true/yes/on). Binds to loopback unless FCAPTCHA_PPROF_ADDR overrides —
	// keep it loopback-only, the pprof endpoints expose memory/goroutine state.
	if pprofEnabled() {
		pprofAddr := os.Getenv("FCAPTCHA_PPROF_ADDR")
		if pprofAddr == "" {
			pprofAddr = "127.0.0.1:3001"
		}
		go func() {
			log.Printf("pprof debug server listening on %s", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				log.Printf("pprof server error: %v", err)
			}
		}()
	}

	// Optional direct TLS termination, off by default.
	//
	// Set FCAPTCHA_TLS_CERT and FCAPTCHA_TLS_KEY to have this process terminate
	// TLS itself, which is the only arrangement where a JA4 fingerprint can be
	// computed here — the ClientHello is consumed by whoever completes the
	// handshake. Behind Railway, Cloudflare or nginx that is not us, and the
	// TRUSTED_JA4_HEADERS path remains the way to get a fingerprint.
	certFile := os.Getenv("FCAPTCHA_TLS_CERT")
	keyFile := os.Getenv("FCAPTCHA_TLS_KEY")
	serveTLS := certFile != "" && keyFile != ""

	if serveTLS {
		srv.TLSConfig = TLSConfigWithJA4(&tls.Config{MinVersion: tls.VersionTLS12}, ja4s)
		log.Printf("native JA4: on (terminating TLS locally)")
	} else {
		trustedJA4 := GetTrustedJA4HeaderNames()
		if len(trustedJA4) > 0 {
			log.Printf("native JA4: off (not terminating TLS); reading %s from trusted proxies", strings.Join(trustedJA4, ", "))
		} else {
			log.Printf("native JA4: off (not terminating TLS, and no TRUSTED_JA4_HEADERS set) — no TLS fingerprint available")
		}
	}

	// Graceful shutdown
	go func() {
		log.Printf("FCaptcha server starting on port %s", port)
		var err error
		if serveTLS {
			err = srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
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
	Action      string                 `json:"action,omitempty"`
	CData       string                 `json:"cdata,omitempty"`
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
	Reason         string             `json:"reason,omitempty"`
}

type DetectionInfo struct {
	Category   string  `json:"category"`
	Score      float64 `json:"score"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// webBotAuthDetections cryptographically verifies a Web Bot Auth signed request
// and returns the resulting detections, or nil when the request carries no
// signature. Verification runs here, in the HTTP layer, because it needs the
// real *http.Request to rebuild the signature base accurately (see
// ScoringEngine.CheckWebBotAuth). Injected into the detection list the same way
// signal-commitment detections are.
func webBotAuthDetections(engine *ScoringEngine, r *http.Request) []DetectionResult {
	// Cheap gate: skip the work (and any directory fetch) unless the signature
	// pair is present. Signature-Agent may legitimately be absent when the key
	// is pre-shared, but these two are always required.
	if r.Header.Get("Signature") == "" || r.Header.Get("Signature-Input") == "" {
		return nil
	}

	// Reconstruct the scheme the client signed. Behind a TLS-terminating proxy
	// (e.g. Railway) r.TLS is nil though the client signed an https target, so
	// trust X-Forwarded-Proto when present.
	scheme := "https"
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = strings.ToLower(strings.TrimSpace(strings.Split(xfp, ",")[0]))
	} else if r.TLS == nil {
		scheme = "http"
	}

	ctx, cancel := context.WithTimeout(r.Context(), webBotAuthTimeout)
	defer cancel()
	return engine.CheckWebBotAuth(ctx, webbotauth.RequestFromHTTP(r, webbotauth.WithScheme(scheme)))
}

func verifyHandler(engine *ScoringEngine, trust *ProxyTrust, siteKeys *SiteKeyGuard, ja4s *ja4Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		ip := trust.ClientIP(r)
		// Bound the state an unvalidated siteKey can allocate (sitekeys.go).
		req.SiteKey = siteKeys.Normalize(req.SiteKey, ip)

		userAgent := r.Header.Get("User-Agent")

		// Collect headers for analysis. peerTrusted decides whether forwarding
		// headers (X-Forwarded-For and friends) count as anomalous: behind a
		// proxy we trust they are how the request is meant to arrive.
		peerTrusted := trust.PeerTrusted(r)
		headers := make(map[string]string)
		for key, values := range r.Header {
			if len(values) > 0 {
				headers[strings.ToLower(key)] = values[0]
			}
		}

		// JA3 hash, as computed by a reverse proxy like nginx or Cloudflare.
		// Only honoured from a trusted proxy — a client that can state its own
		// TLS fingerprint would just claim a stock Chrome one.
		ja3Hash := trust.TrustedHeader(r, "X-JA3-Hash")

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

		// Web Bot Auth: verify signed-agent requests against the signer's key
		// directory. Needs the real request, so it runs here, not in scoring;
		// passed as preDetections so the verified/forged verdict is scored.
		webBotAuth := webBotAuthDetections(engine, r)

		// This endpoint is reached by clicking a rendered widget, so the
		// client's click analysis is present and meaningful.
		SetInteractionMode(signals, true)

		result := engine.VerifyWithHeaders(signals, ip, req.SiteKey, userAgent, headers, ja3Hash, ja4s.Lookup(r.RemoteAddr), peerTrusted, webBotAuth, TokenBinding{Action: req.Action, CData: req.CData}, req.PowSolution)

		// Add signal commitment detections to results
		if len(extraDetections) > 0 {
			result.Detections = append(extraDetections, result.Detections...)
		}

		logVerdict("verify", req.SiteKey, result)

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
			Reason:         result.Reason,
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
	CData       string                 `json:"cdata,omitempty"`
	PowSolution *PoWSolution           `json:"powSolution,omitempty"`
	PowTiming   *PowTiming             `json:"powTiming,omitempty"`
}

func invisibleScoreHandler(engine *ScoringEngine, trust *ProxyTrust, siteKeys *SiteKeyGuard, ja4s *ja4Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req InvisibleScoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		ip := trust.ClientIP(r)
		// Bound the state an unvalidated siteKey can allocate (sitekeys.go).
		req.SiteKey = siteKeys.Normalize(req.SiteKey, ip)

		userAgent := r.Header.Get("User-Agent")

		// Collect headers for analysis (see verifyHandler on peerTrusted).
		peerTrusted := trust.PeerTrusted(r)
		scoreHeaders := make(map[string]string)
		for key, values := range r.Header {
			if len(values) > 0 {
				scoreHeaders[strings.ToLower(key)] = values[0]
			}
		}
		ja3 := trust.TrustedHeader(r, "X-JA3-Hash")

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

		// Web Bot Auth: verify signed-agent requests (see verifyHandler).
		webBotAuth := webBotAuthDetections(engine, r)

		// Invisible scoring: no widget, so no click analysis in the signals.
		SetInteractionMode(signals, false)

		result := engine.VerifyWithHeaders(signals, ip, req.SiteKey, userAgent, scoreHeaders, ja3, ja4s.Lookup(r.RemoteAddr), peerTrusted, webBotAuth, TokenBinding{Action: req.Action, CData: req.CData}, req.PowSolution)
		if len(scoreExtraDetections) > 0 {
			result.Detections = append(scoreExtraDetections, result.Detections...)
		}

		logVerdict("score", req.SiteKey, result)

		resp := map[string]interface{}{
			"success": result.Success,
			"score":   result.Score,
			"token":   result.Token,
			// Echo the sanitized form, not the raw input: this is what got
			// signed into the token, so a caller comparing the two sees the
			// same value.
			"action":         SanitizeAction(req.Action),
			"cdata":          SanitizeCData(req.CData),
			"recommendation": result.Recommendation,
		}
		if result.Reason != "" {
			resp["reason"] = result.Reason
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// TokenVerifyRequest for server-side token verification
type TokenVerifyRequest struct {
	Token    string `json:"token"`
	Secret   string `json:"secret"`
	RemoteIP string `json:"remoteip,omitempty"`
}

func tokenVerifyHandler(engine *ScoringEngine, trust *ProxyTrust, verifySecret string, requireSecret bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TokenVerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// The secret gate. This endpoint is the boundary between "a browser
		// finished a challenge" and "my backend believes it", so it is
		// server-to-server and needs a credential — without one, anyone who can
		// reach the host can spend a token they observed, and the single-use
		// guard then denies the real user.
		if requireSecret {
			w.Header().Set("Content-Type", "application/json")
			if req.Secret == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "reason": "missing_secret"})
				return
			}
			if !SecretMatches(req.Secret, verifySecret) {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]interface{}{"valid": false, "reason": "invalid_secret"})
				return
			}
		}

		// The caller is the integrating backend, not the visitor who received
		// the token. Bind only to an explicitly supplied visitor address.
		result := engine.VerifyTokenWithIP(req.Token, req.RemoteIP)

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
	// MinAgeMs tells the client how long to hold a solved challenge before
	// submitting it. Honouring it is how an ordinary visitor pays an elevated
	// cost as a short wait instead of as a worse score — which matters most for
	// people sharing an egress address with whatever earned the elevation.
	MinAgeMs int64 `json:"minAgeMs"`
}

func powChallengeHandler(engine *ScoringEngine, trust *ProxyTrust, siteKeys *SiteKeyGuard) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := trust.ClientIP(r)
		siteKey := siteKeys.Normalize(r.URL.Query().Get("siteKey"), ip)

		isDatacenter := IsDatacenterIP(ip)
		challenge := engine.GeneratePoWChallenge(siteKey, ip, isDatacenter)
		if challenge == nil {
			http.Error(w, `{"error":"state_unavailable"}`, http.StatusServiceUnavailable)
			return
		}

		resp := PoWChallengeResponse{
			ChallengeID: challenge.ID,
			Prefix:      challenge.Prefix,
			Difficulty:  challenge.Difficulty,
			ExpiresAt:   challenge.ExpiresAt,
			Nonce:       challenge.Nonce,
			Sig:         challenge.Sig,
			MinAgeMs:    challenge.MinAgeMs,
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
