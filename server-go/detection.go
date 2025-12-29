package main

import (
	"net"
	"regexp"
	"strings"
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

	// Check reverse DNS for VPN/proxy patterns
	names, err := net.LookupAddr(ip)
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
		}
	}

	return detections
}
