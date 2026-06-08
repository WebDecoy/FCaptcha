package main

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// =============================================================================
// IP Intelligence
// =============================================================================

// Known datacenter/cloud ASN ranges (add more as needed)
// In production, use a proper IP intelligence database like MaxMind or IPinfo
var datacenterCIDRs = []string{
	// AWS
	"3.0.0.0/8", "13.0.0.0/8", "18.0.0.0/8", "34.0.0.0/8", "35.0.0.0/8",
	"52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8",
	// Google Cloud
	"34.64.0.0/10", "35.184.0.0/13", "104.154.0.0/15", "104.196.0.0/14",
	// Azure
	"13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.224.0.0/11",
	// DigitalOcean
	"64.225.0.0/16", "68.183.0.0/16", "104.131.0.0/16", "134.209.0.0/16",
	"138.68.0.0/16", "139.59.0.0/16", "142.93.0.0/16", "157.245.0.0/16",
	"159.65.0.0/16", "159.89.0.0/16", "161.35.0.0/16", "164.90.0.0/16",
	"165.22.0.0/16", "165.227.0.0/16", "167.71.0.0/16", "167.99.0.0/16",
	"174.138.0.0/16", "178.128.0.0/16", "178.62.0.0/16", "188.166.0.0/16",
	"192.241.0.0/16", "198.199.0.0/16", "206.189.0.0/16", "207.154.0.0/16",
	// Linode
	"45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "50.116.0.0/16",
	"66.175.0.0/16", "69.164.0.0/16", "72.14.176.0/20", "74.207.224.0/19",
	"96.126.96.0/19", "97.107.128.0/17", "139.162.0.0/16", "172.104.0.0/15",
	"173.230.128.0/17", "173.255.192.0/18", "178.79.128.0/17", "192.155.80.0/20",
	// Vultr
	"45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16",
	"66.42.0.0/16", "95.179.128.0/17", "104.156.224.0/19", "104.207.128.0/17",
	"108.61.0.0/16", "136.244.64.0/18", "140.82.0.0/16", "144.202.0.0/16",
	"149.28.0.0/16", "155.138.128.0/17", "207.148.0.0/17", "208.167.224.0/19",
	"209.250.224.0/19", "216.128.128.0/17",
	// Hetzner
	"5.9.0.0/16", "23.88.0.0/14", "46.4.0.0/14", "78.46.0.0/15",
	"88.99.0.0/16", "95.216.0.0/14", "116.202.0.0/15", "116.203.0.0/16",
	"135.181.0.0/16", "136.243.0.0/16", "138.201.0.0/16", "142.132.128.0/17",
	"144.76.0.0/16", "148.251.0.0/16", "157.90.0.0/16", "159.69.0.0/16",
	"162.55.0.0/16", "167.233.0.0/16", "168.119.0.0/16", "176.9.0.0/16",
	"178.63.0.0/16", "185.12.64.0/22", "188.40.0.0/16", "195.201.0.0/16",
	"213.133.96.0/19", "213.239.192.0/18",
	// OVH
	"51.38.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16",
	"51.79.0.0/16", "51.81.0.0/16", "51.83.0.0/16", "51.89.0.0/16",
	"51.91.0.0/16", "51.161.0.0/16", "54.36.0.0/16", "54.37.0.0/16",
	"54.38.0.0/16", "91.134.0.0/16", "92.222.0.0/16", "135.125.0.0/16",
	"137.74.0.0/16", "139.99.0.0/16", "141.94.0.0/16", "142.44.128.0/17",
	"144.217.0.0/16", "145.239.0.0/16", "147.135.0.0/16", "149.56.0.0/16",
	"151.80.0.0/16", "158.69.0.0/16", "164.132.0.0/16", "167.114.0.0/16",
	"176.31.0.0/16", "178.32.0.0/15", "188.165.0.0/16", "192.95.0.0/18",
	"192.99.0.0/16", "193.70.0.0/16", "198.27.64.0/18", "198.50.128.0/17",
	"198.100.144.0/20", "198.245.48.0/20", "213.32.0.0/17", "213.186.32.0/19",
	"213.251.128.0/18",
}

var datacenterNets []*net.IPNet

func init() {
	for _, cidr := range datacenterCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			datacenterNets = append(datacenterNets, ipNet)
		}
	}
}

// Known Tor exit node detection (simplified - use a proper list in production)
// In production, fetch from https://check.torproject.org/torbulkexitlist
var knownTorExitPorts = []int{9001, 9030, 9050, 9051, 9150}

// Common VPN/proxy indicators in reverse DNS
var vpnProxyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)vpn`),
	regexp.MustCompile(`(?i)proxy`),
	regexp.MustCompile(`(?i)tor-exit`),
	regexp.MustCompile(`(?i)exit-?node`),
	regexp.MustCompile(`(?i)anonymizer`),
	regexp.MustCompile(`(?i)hide-?my`),
	regexp.MustCompile(`(?i)tunnel`),
	regexp.MustCompile(`(?i)relay`),
}

// IsDatacenterIP checks if an IP belongs to a known datacenter
func IsDatacenterIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, ipNet := range datacenterNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckIPReputation returns detection results for IP-based threats
func (e *ScoringEngine) CheckIPReputation(ip string) []DetectionResult {
	var detections []DetectionResult

	// Check datacenter IP
	if IsDatacenterIP(ip) {
		detections = append(detections, DetectionResult{
			Category:   CategoryDatacenter,
			Score:      0.6,
			Confidence: 0.8,
			Reason:     "Request from known datacenter IP range",
			Details:    map[string]interface{}{"ip": ip},
		})
	}

	// Check reverse DNS for VPN/proxy patterns (2s timeout to avoid blocking request handlers)
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dnsCancel()
	names, err := net.DefaultResolver.LookupAddr(dnsCtx, ip)
	if err == nil {
		for _, name := range names {
			for _, pattern := range vpnProxyPatterns {
				if pattern.MatchString(name) {
					detections = append(detections, DetectionResult{
						Category:   CategoryTorVPN,
						Score:      0.5,
						Confidence: 0.6,
						Reason:     "Reverse DNS suggests VPN/proxy",
						Details:    map[string]interface{}{"hostname": name},
					})
					break
				}
			}
		}
	}

	return detections
}

// =============================================================================
// HTTP Header Analysis
// =============================================================================

// Standard header order for common browsers
var chromeHeaderOrder = []string{
	"host", "connection", "cache-control", "sec-ch-ua", "sec-ch-ua-mobile",
	"sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept",
	"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
	"accept-encoding", "accept-language",
}

var firefoxHeaderOrder = []string{
	"host", "user-agent", "accept", "accept-language", "accept-encoding",
	"connection", "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
	"sec-fetch-site", "sec-fetch-user",
}

// Suspicious headers that indicate automation
var suspiciousHeaders = map[string]bool{
	"x-requested-with":    true, // Often set by automation
	"x-forwarded-for":     true, // Proxy indicator
	"x-real-ip":           true, // Proxy indicator
	"via":                 true, // Proxy indicator
	"forwarded":           true, // Proxy indicator
	"x-originating-ip":    true, // Proxy indicator
	"cf-connecting-ip":    true, // Cloudflare (usually stripped)
	"true-client-ip":      true, // CDN header
	"x-cluster-client-ip": true, // Load balancer header
}

// Headers that should be present in a real browser
var expectedBrowserHeaders = map[string]bool{
	"accept":          true,
	"accept-language": true,
	"accept-encoding": true,
	"user-agent":      true,
}

// AnalyzeHeaders checks HTTP headers for bot indicators
func (e *ScoringEngine) AnalyzeHeaders(headers map[string]string) []DetectionResult {
	var detections []DetectionResult

	// Check for missing expected headers
	missingCount := 0
	for header := range expectedBrowserHeaders {
		if _, ok := headers[strings.ToLower(header)]; !ok {
			missingCount++
		}
	}
	if missingCount > 1 {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.4,
			Confidence: 0.5,
			Reason:     "Missing expected browser headers",
			Details:    map[string]interface{}{"missing_count": missingCount},
		})
	}

	// Check for suspicious headers
	for header := range headers {
		if suspiciousHeaders[strings.ToLower(header)] {
			detections = append(detections, DetectionResult{
				Category:   CategoryBot,
				Score:      0.3,
				Confidence: 0.4,
				Reason:     "Suspicious header present: " + header,
				Details:    map[string]interface{}{"header": header},
			})
		}
	}

	// Check Accept-Language (should have at least one language)
	if acceptLang, ok := headers["accept-language"]; ok {
		if acceptLang == "" || acceptLang == "*" {
			detections = append(detections, DetectionResult{
				Category:   CategoryBot,
				Score:      0.3,
				Confidence: 0.4,
				Reason:     "Invalid Accept-Language header",
			})
		}
	}

	// Check for inconsistent encoding support
	if acceptEnc, ok := headers["accept-encoding"]; ok {
		if !strings.Contains(acceptEnc, "gzip") && !strings.Contains(acceptEnc, "deflate") {
			detections = append(detections, DetectionResult{
				Category:   CategoryBot,
				Score:      0.2,
				Confidence: 0.3,
				Reason:     "Unusual Accept-Encoding",
			})
		}
	}

	return detections
}

// =============================================================================
// Browser Consistency Checks
// =============================================================================

// UABrowserInfo extracted from User-Agent
type UABrowserInfo struct {
	Browser   string
	Version   string
	OS        string
	IsMobile  bool
	IsBot     bool
	BotName   string
}

var botUAPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bot`),
	regexp.MustCompile(`(?i)spider`),
	regexp.MustCompile(`(?i)crawler`),
	regexp.MustCompile(`(?i)scraper`),
	regexp.MustCompile(`(?i)curl`),
	regexp.MustCompile(`(?i)wget`),
	regexp.MustCompile(`(?i)python`),
	regexp.MustCompile(`(?i)java\/`),
	regexp.MustCompile(`(?i)httpie`),
	regexp.MustCompile(`(?i)postman`),
	regexp.MustCompile(`(?i)insomnia`),
	regexp.MustCompile(`(?i)axios`),
	regexp.MustCompile(`(?i)node-fetch`),
	regexp.MustCompile(`(?i)go-http`),
	regexp.MustCompile(`(?i)okhttp`),
	regexp.MustCompile(`(?i)libwww`),
	regexp.MustCompile(`(?i)apache-httpclient`),
}

var chromePattern = regexp.MustCompile(`Chrome\/(\d+)`)
var firefoxPattern = regexp.MustCompile(`Firefox\/(\d+)`)
var safariPattern = regexp.MustCompile(`Safari\/(\d+)`)
var edgePattern = regexp.MustCompile(`Edg\/(\d+)`)

// ParseUserAgent extracts browser info from UA string
func ParseUserAgent(ua string) UABrowserInfo {
	info := UABrowserInfo{}

	// Check for bots first
	for _, pattern := range botUAPatterns {
		if match := pattern.FindString(ua); match != "" {
			info.IsBot = true
			info.BotName = match
			return info
		}
	}

	// Detect browser
	if match := edgePattern.FindStringSubmatch(ua); len(match) > 1 {
		info.Browser = "Edge"
		info.Version = match[1]
	} else if match := chromePattern.FindStringSubmatch(ua); len(match) > 1 {
		info.Browser = "Chrome"
		info.Version = match[1]
	} else if match := firefoxPattern.FindStringSubmatch(ua); len(match) > 1 {
		info.Browser = "Firefox"
		info.Version = match[1]
	} else if match := safariPattern.FindStringSubmatch(ua); len(match) > 1 {
		if !strings.Contains(ua, "Chrome") {
			info.Browser = "Safari"
			info.Version = match[1]
		}
	}

	// Detect OS
	if strings.Contains(ua, "Windows") {
		info.OS = "Windows"
	} else if strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "Macintosh") {
		info.OS = "macOS"
	} else if strings.Contains(ua, "Linux") {
		info.OS = "Linux"
	} else if strings.Contains(ua, "Android") {
		info.OS = "Android"
		info.IsMobile = true
	} else if strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") {
		info.OS = "iOS"
		info.IsMobile = true
	}

	// Detect mobile
	if strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android") {
		info.IsMobile = true
	}

	return info
}

// CheckBrowserConsistency verifies that claimed UA matches actual browser behavior
func (e *ScoringEngine) CheckBrowserConsistency(ua string, signals map[string]interface{}) []DetectionResult {
	var detections []DetectionResult

	uaInfo := ParseUserAgent(ua)

	// If UA is a known bot, flag it
	if uaInfo.IsBot {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.9,
			Confidence: 0.95,
			Reason:     "User-Agent indicates bot/automation tool",
			Details:    map[string]interface{}{"bot": uaInfo.BotName},
		})
		return detections
	}

	// Get environmental signals
	env := getMap(signals, "environmental")
	if env == nil {
		return detections
	}

	nav := getMap(env, "navigator")
	automation := getMap(env, "automationFlags")

	// Check platform consistency
	if nav != nil {
		platform := getString(nav, "platform")

		// UA says Windows but platform doesn't
		if uaInfo.OS == "Windows" && !strings.Contains(platform, "Win") {
			detections = append(detections, DetectionResult{
				Category:   CategoryBot,
				Score:      0.6,
				Confidence: 0.7,
				Reason:     "UA/platform mismatch: UA claims Windows",
				Details:    map[string]interface{}{"platform": platform, "ua_os": uaInfo.OS},
			})
		}

		// UA says Mac but platform doesn't
		if uaInfo.OS == "macOS" && !strings.Contains(platform, "Mac") {
			detections = append(detections, DetectionResult{
				Category:   CategoryBot,
				Score:      0.6,
				Confidence: 0.7,
				Reason:     "UA/platform mismatch: UA claims macOS",
				Details:    map[string]interface{}{"platform": platform, "ua_os": uaInfo.OS},
			})
		}

		// UA says Linux but platform doesn't
		if uaInfo.OS == "Linux" && !strings.Contains(platform, "Linux") {
			detections = append(detections, DetectionResult{
				Category:   CategoryBot,
				Score:      0.6,
				Confidence: 0.7,
				Reason:     "UA/platform mismatch: UA claims Linux",
				Details:    map[string]interface{}{"platform": platform, "ua_os": uaInfo.OS},
			})
		}
	}

	// Check mobile consistency
	var maxTouchPoints float64
	if nav != nil {
		maxTouchPoints = getFloat(nav, "maxTouchPoints")
	}
	if maxTouchPoints == 0 && automation != nil {
		maxTouchPoints = getFloat(automation, "maxTouchPoints")
	}

	// Claims mobile but no touch support
	if uaInfo.IsMobile && maxTouchPoints == 0 {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.5,
			Confidence: 0.6,
			Reason:     "UA claims mobile but no touch support",
		})
	}

	// Claims desktop but has touch (less suspicious, could be touchscreen laptop)
	// Don't flag this as it's common

	// Check Chrome-specific properties
	if uaInfo.Browser == "Chrome" && automation != nil {
		hasChrome := getBool(automation, "chrome")
		if !hasChrome {
			detections = append(detections, DetectionResult{
				Category:   CategoryBot,
				Score:      0.7,
				Confidence: 0.8,
				Reason:     "UA claims Chrome but window.chrome missing",
			})
		}
	}

	return detections
}

// =============================================================================
// TLS Fingerprinting (JA3)
// =============================================================================

// Known JA3 hashes for common bots/automation tools
// In production, maintain a database of these
var knownBotJA3Hashes = map[string]string{
	"3b5074b1b5d032e5620f69f9f700ff0e": "Python requests",
	"b32309a26951912be7dba376398abc3b": "Python urllib",
	"9e10692f1b7f78228b2d4e424db3a98c": "Go net/http",
	"473cd7cb9faa642487833865d516e578": "curl",
	"c12f54a3f91dc7bafd92cb59fe009a35": "Wget",
	"2d1eb5817ece335c24904f516ad5da2f": "Java HttpClient",
	"fc54fe03db02a25e1be5bb5a7678b7a4": "Node.js axios",
	"579ccef312d18482fc42e2b822ca2430": "Node.js node-fetch",
	"5d7974c9fe7862e0f9a3eb35a6a5d9c8": "Puppeteer default",
	"b4e2b7ee69d3c0a3c2c6d0d0d0d0d0d0": "Headless Chrome",
}

// CheckJA3Fingerprint checks if the TLS fingerprint matches known bots
// Note: JA3 must be calculated at the TLS layer, typically by a reverse proxy
// This function checks if a pre-calculated JA3 hash was passed in
func (e *ScoringEngine) CheckJA3Fingerprint(ja3Hash string) []DetectionResult {
	var detections []DetectionResult

	if ja3Hash == "" {
		return detections
	}

	if botName, ok := knownBotJA3Hashes[ja3Hash]; ok {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.8,
			Confidence: 0.9,
			Reason:     "TLS fingerprint matches known automation tool",
			Details:    map[string]interface{}{"ja3": ja3Hash, "tool": botName},
		})
	}

	return detections
}

// =============================================================================
// TLS Fingerprinting (JA4) — read from trusted reverse-proxy headers
// =============================================================================
//
// Unlike the client-supplied X-JA3-Hash (spoofable), JA4 fingerprints are
// computed from the TLS ClientHello by the reverse proxy and passed via a
// trusted header the server is configured to accept via TRUSTED_JA4_HEADERS.

// knownBotJA4Hashes holds observed automation fingerprints.
// Populate in production; entries below are placeholders.
// JA4 format: t##d####_####..._####
var knownBotJA4Hashes = map[string]string{
	// Example once identified:
	//   "t13d1516h2_8daaf6152771_02713d6af862": "Go default stdlib TLS",
}

// GetTrustedJA4HeaderNames reads TRUSTED_JA4_HEADERS env var (comma-separated).
func GetTrustedJA4HeaderNames() []string {
	env := os.Getenv("TRUSTED_JA4_HEADERS")
	if env == "" {
		return nil
	}
	names := []string{}
	for _, part := range strings.Split(env, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p != "" {
			names = append(names, p)
		}
	}
	return names
}

// ReadJA4FromHeaders returns the first non-empty value from the trusted header list.
func ReadJA4FromHeaders(headers map[string]string, trusted []string) string {
	if len(trusted) == 0 || headers == nil {
		return ""
	}
	lower := make(map[string]string, len(headers))
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}
	for _, name := range trusted {
		if v, ok := lower[name]; ok {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return ""
}

// CheckJA4Fingerprint matches a JA4 hash against known automation fingerprints.
func (e *ScoringEngine) CheckJA4Fingerprint(ja4 string) []DetectionResult {
	var detections []DetectionResult
	if ja4 == "" {
		return detections
	}
	if botName, ok := knownBotJA4Hashes[ja4]; ok {
		detections = append(detections, DetectionResult{
			Category:   CategoryFingerprint,
			Score:      0.8,
			Confidence: 0.9,
			Reason:     "TLS JA4 fingerprint matches known automation tool",
			Details:    map[string]interface{}{"ja4": ja4, "tool": botName},
		})
	}
	return detections
}

// =============================================================================
// Statistical Utility Functions (Keystroke Cadence Analysis)
// =============================================================================

func statMean(arr []float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range arr {
		sum += v
	}
	return sum / float64(len(arr))
}

func statStddev(arr []float64) float64 {
	if len(arr) < 2 {
		return 0
	}
	m := statMean(arr)
	variance := 0.0
	for _, v := range arr {
		d := v - m
		variance += d * d
	}
	variance /= float64(len(arr))
	return math.Sqrt(variance)
}

func statErf(x float64) float64 {
	sign := 1.0
	if x < 0 {
		sign = -1.0
	}
	x = math.Abs(x)
	t := 1.0 / (1.0 + 0.3275911*x)
	y := 1.0 - (((((1.061405429*t-1.453152027)*t)+1.421413741)*t-0.284496736)*t+0.254829592)*t*math.Exp(-x*x)
	return sign * y
}

func statNormalCDF(x, mu, sigma float64) float64 {
	if sigma <= 0 {
		if x >= mu {
			return 1.0
		}
		return 0.0
	}
	return 0.5 * (1.0 + statErf((x-mu)/(sigma*math.Sqrt2)))
}

func statKSTestStatistic(samples []float64, cdfFn func(float64) float64) float64 {
	n := len(samples)
	if n == 0 {
		return 0
	}
	sorted := make([]float64, n)
	copy(sorted, samples)
	sort.Float64s(sorted)
	maxD := 0.0
	for i := 0; i < n; i++ {
		empirical := float64(i+1) / float64(n)
		theoretical := cdfFn(sorted[i])
		d1 := math.Abs(empirical - theoretical)
		d2 := math.Abs(float64(i)/float64(n) - theoretical)
		if d1 > maxD {
			maxD = d1
		}
		if d2 > maxD {
			maxD = d2
		}
	}
	return maxD
}

func statShannonEntropy(arr []float64, bins int) float64 {
	if len(arr) == 0 {
		return 0
	}
	minV := arr[0]
	maxV := arr[0]
	for _, v := range arr {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	if maxV == minV {
		return 0
	}
	binWidth := (maxV - minV) / float64(bins)
	counts := make([]int, bins)
	for _, v := range arr {
		idx := int((v - minV) / binWidth)
		if idx >= bins {
			idx = bins - 1
		}
		counts[idx]++
	}
	n := float64(len(arr))
	entropy := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func statLag1Autocorrelation(arr []float64) float64 {
	if len(arr) < 3 {
		return 0
	}
	n := len(arr) - 1
	x := arr[:n]
	y := arr[1:]
	mx := statMean(x)
	my := statMean(y)
	num := 0.0
	dx2 := 0.0
	dy2 := 0.0
	for i := 0; i < n; i++ {
		dx := x[i] - mx
		dy := y[i] - my
		num += dx * dy
		dx2 += dx * dx
		dy2 += dy * dy
	}
	denom := math.Sqrt(dx2 * dy2)
	if denom == 0 {
		return 0
	}
	return num / denom
}

func getFloatSlice(m map[string]interface{}, key string) []float64 {
	if m == nil {
		return nil
	}
	arr, ok := m[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]float64, 0, len(arr))
	for _, v := range arr {
		switch val := v.(type) {
		case float64:
			result = append(result, val)
		case int:
			result = append(result, float64(val))
		}
	}
	return result
}

// =============================================================================
// Keystroke Cadence Analysis
// =============================================================================

func analyzeKeystrokeCadence(stats map[string]interface{}) *DetectionResult {
	keyCount := int(getFloat(stats, "keyCount"))
	intervals := getFloatSlice(stats, "intervals")
	dwellTimes := getFloatSlice(stats, "dwellTimes")
	rollovers := int(getFloat(stats, "rollovers"))

	// Gate on minimum data
	if keyCount < 20 || len(intervals) < 15 {
		return nil
	}

	metrics := map[string]interface{}{}
	totalWeight := 0.0
	weightedSum := 0.0
	activeMetricCount := 0

	// 1. Dwell Variance (weight 0.15)
	if len(dwellTimes) >= 10 {
		dSd := statStddev(dwellTimes)
		var score float64
		if dSd < 3 {
			score = 0
		} else if dSd < 10 {
			score = 0.35 * (dSd - 3) / 7
		} else if dSd < 20 {
			score = 0.35 + 0.65*(dSd-10)/10
		} else {
			score = 1.0
		}
		metrics["dwellVariance"] = score
		totalWeight += 0.15
		weightedSum += score * 0.15
		activeMetricCount++
	}

	// 2. Log-Normal Fit (weight 0.20)
	if len(intervals) >= 15 {
		logIntervals := make([]float64, 0, len(intervals))
		for _, v := range intervals {
			if v > 0 {
				logIntervals = append(logIntervals, math.Log(v))
			}
		}
		if len(logIntervals) >= 10 {
			mu := statMean(logIntervals)
			sigma := statStddev(logIntervals)
			D := statKSTestStatistic(logIntervals, func(x float64) float64 {
				return statNormalCDF(x, mu, sigma)
			})
			critical := 1.22 / math.Sqrt(float64(len(logIntervals)))
			var score float64
			if D <= critical*0.8 {
				score = 1.0
			} else if D <= critical {
				score = 0.7
			} else if D <= critical*1.5 {
				score = 0.3
			} else {
				score = 0
			}
			metrics["logNormalFit"] = score
			totalWeight += 0.20
			weightedSum += score * 0.20
			activeMetricCount++
		}
	}

	// 3. Uniformity Detection (weight 0.15)
	if len(intervals) >= 15 {
		minI := intervals[0]
		maxI := intervals[0]
		for _, v := range intervals {
			if v < minI {
				minI = v
			}
			if v > maxI {
				maxI = v
			}
		}
		if maxI > minI {
			rangeI := maxI - minI
			D := statKSTestStatistic(intervals, func(x float64) float64 {
				return (x - minI) / rangeI
			})
			var score float64
			if D < 0.05 {
				score = 0
			} else if D < 0.1 {
				score = 0.3
			} else if D < 0.15 {
				score = 0.6
			} else {
				score = 1.0
			}
			metrics["uniformity"] = score
			totalWeight += 0.15
			weightedSum += score * 0.15
			activeMetricCount++
		}
	}

	// 4. Lag-1 Autocorrelation (weight 0.15)
	if len(intervals) >= 15 {
		r := math.Abs(statLag1Autocorrelation(intervals))
		var score float64
		if r < 0.02 {
			score = 0.1
		} else if r < 0.1 {
			score = 0.1 + 0.4*(r-0.02)/0.08
		} else if r < 0.2 {
			score = 0.5 + 0.4*(r-0.1)/0.1
		} else if r <= 0.4 {
			score = 0.9
		} else if r <= 0.6 {
			score = 0.9 - 0.4*(r-0.4)/0.2
		} else {
			score = 0.5
		}
		metrics["autocorrelation"] = score
		totalWeight += 0.15
		weightedSum += score * 0.15
		activeMetricCount++
	}

	// 5. Burst Regularity (weight 0.10)
	burstGaps := make([]float64, 0)
	for _, v := range intervals {
		if v > 300 {
			burstGaps = append(burstGaps, v)
		}
	}
	if len(burstGaps) >= 3 {
		burstMean := statMean(burstGaps)
		burstSd := statStddev(burstGaps)
		cv := 0.0
		if burstMean > 0 {
			cv = burstSd / burstMean
		}
		var score float64
		if cv < 0.1 {
			score = 0.1
		} else if cv < 0.3 {
			score = 0.1 + 0.9*(cv-0.1)/0.2
		} else {
			score = 1.0
		}
		metrics["burstRegularity"] = score
		totalWeight += 0.10
		weightedSum += score * 0.10
		activeMetricCount++
	}

	// 6. Shannon Entropy (weight 0.15)
	if len(intervals) >= 15 {
		H := statShannonEntropy(intervals, 10)
		var score float64
		if H < 0.5 {
			score = 0.1
		} else if H < 1.5 {
			score = 0.1 + 0.5*(H-0.5)
		} else if H < 2.0 {
			score = 0.6 + 0.4*(H-1.5)/0.5
		} else if H <= 3.0 {
			score = 1.0
		} else if H <= 3.3 {
			score = 0.7
		} else {
			score = 0.4
		}
		metrics["entropy"] = score
		totalWeight += 0.15
		weightedSum += score * 0.15
		activeMetricCount++
	}

	// 7. Rollover Rate (weight 0.10)
	if keyCount >= 30 {
		rate := float64(rollovers) / float64(keyCount)
		var score float64
		if rate == 0 {
			score = 0.5
		} else if rate < 0.05 {
			score = 0.5 + 0.3*(rate/0.05)
		} else if rate < 0.15 {
			score = 0.8 + 0.2*((rate-0.05)/0.1)
		} else {
			score = 1.0
		}
		metrics["rolloverRate"] = score
		totalWeight += 0.10
		weightedSum += score * 0.10
		activeMetricCount++
	}

	if totalWeight == 0 {
		return nil
	}

	humanScore := weightedSum / totalWeight
	botScore := 1.0 - humanScore

	// Only emit detection when botScore > 0.55
	if botScore <= 0.55 {
		return nil
	}

	confidence := float64(activeMetricCount) / 7.0
	if confidence > 0.7 {
		confidence = 0.7
	}

	return &DetectionResult{
		Category:   CategoryBot,
		Score:      botScore * 0.7,
		Confidence: confidence,
		Reason:     "Keystroke cadence analysis indicates non-human typing pattern",
		Details:    map[string]interface{}{"metrics": metrics, "cadenceHumanScore": humanScore},
	}
}

// =============================================================================
// Form Interaction Analysis (Credential Stuffing & Spam Detection)
// =============================================================================

// AnalyzeFormInteraction checks form submission patterns for credential stuffing and spam
func (e *ScoringEngine) AnalyzeFormInteraction(formAnalysis map[string]interface{}) []DetectionResult {
	var detections []DetectionResult

	if formAnalysis == nil {
		return detections
	}

	submit := getMap(formAnalysis, "submit")

	// Check for programmatic form submission
	method := getString(submit, "method")
	if method == "programmatic" || method == "programmatic_click" {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.8,
			Confidence: 0.85,
			Reason:     fmt.Sprintf("Form submitted programmatically (%s)", method),
		})
	}

	// Check timing - too fast from page load to submit
	timeSinceLoad := getFloat(submit, "timeSincePageLoad")
	if timeSinceLoad > 0 && timeSinceLoad < 800 {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.7,
			Confidence: 0.75,
			Reason:     fmt.Sprintf("Form submitted too quickly after page load (%.0fms)", timeSinceLoad),
		})
	}

	// Check timing - too fast from page load to first interaction
	pageToFirst := getFloat(formAnalysis, "pageLoadToFirstInteraction")
	if pageToFirst > 0 && pageToFirst < 300 {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.6,
			Confidence: 0.65,
			Reason:     fmt.Sprintf("First interaction too fast after page load (%.0fms)", pageToFirst),
		})
	}

	// Check for no trigger event before submit
	eventsBeforeSubmit := int(getFloat(submit, "eventsBeforeSubmit"))
	if eventsBeforeSubmit == 0 && method != "" && method != "none" {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.9,
			Confidence: 0.9,
			Reason:     "Form submitted with no user interaction events",
		})
	}

	// Check for very low event count before submit
	if eventsBeforeSubmit > 0 && eventsBeforeSubmit < 3 && method != "" && method != "none" {
		detections = append(detections, DetectionResult{
			Category:   CategoryBot,
			Score:      0.5,
			Confidence: 0.6,
			Reason:     fmt.Sprintf("Very few events before submit (%d)", eventsBeforeSubmit),
		})
	}

	// Textarea keyboard analysis (spam detection)
	textareaData := getMap(formAnalysis, "textareaKeyboard")
	if textareaData != nil {
		for fieldId, statsInterface := range textareaData {
			stats, ok := statsInterface.(map[string]interface{})
			if !ok {
				continue
			}

			pasteCount := int(getFloat(stats, "pasteCount"))
			keyCount := int(getFloat(stats, "keyCount"))
			avgInterval := getFloat(stats, "avgKeyInterval")
			intervalVariance := getFloat(stats, "keyIntervalVariance")
			keydownUpRatio := getFloat(stats, "keydownUpRatio")

			// Check for paste-heavy input
			if pasteCount > 0 && keyCount < 5 {
				detections = append(detections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.6,
					Confidence: 0.6,
					Reason:     fmt.Sprintf("Textarea %q filled mostly by paste (%d pastes, %d keystrokes)", fieldId, pasteCount, keyCount),
				})
			}

			// Check for unnaturally consistent typing
			if keyCount > 10 && intervalVariance < 100 {
				detections = append(detections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.5,
					Confidence: 0.55,
					Reason:     fmt.Sprintf("Textarea %q has unnaturally consistent typing rhythm", fieldId),
				})
			}

			// Check for impossibly fast typing
			if keyCount > 10 && avgInterval > 0 && avgInterval < 50 {
				detections = append(detections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.7,
					Confidence: 0.7,
					Reason:     fmt.Sprintf("Textarea %q typing speed impossibly fast (%.0fms/key)", fieldId, avgInterval),
				})
			}

			// Check keydown/keyup ratio
			if keyCount > 10 && (keydownUpRatio < 0.8 || keydownUpRatio > 1.2) {
				detections = append(detections, DetectionResult{
					Category:   CategoryBot,
					Score:      0.4,
					Confidence: 0.5,
					Reason:     fmt.Sprintf("Textarea %q has abnormal keydown/keyup ratio (%.2f)", fieldId, keydownUpRatio),
				})
			}

			// Keystroke cadence analysis
			cadenceResult := analyzeKeystrokeCadence(stats)
			if cadenceResult != nil {
				detections = append(detections, *cadenceResult)
			}
		}
	}

	return detections
}
