package main

import (
	"regexp"
	"strings"
)

// identity-coherence-v1 compares what a browser claims to be with properties
// measured independently of that claim. Each measurement is an axis that
// agrees, contradicts or knows nothing; unknown never counts. Observe-only:
// it has no enforcement selector, so FCAPTCHA_EXPERIMENTAL_BLOCKING cannot
// opt anyone into it.
//
// The value is in how axes relate, not in a weighted sum. One axis against the
// claim has ordinary explanations (a VM, a font pack). Measurements that agree
// with each other against the claim mean the claim was replaced. Measurements
// that disagree with each other cannot come from changing the claim alone.
const identityPolicy = "identity-coherence-v1"

// Canonical order keeps reasons and fixtures identical across the servers.
var identityOSOrder = []string{"windows", "macos", "ios", "android", "chromeos", "linux"}

var identityOSLabels = map[string]string{
	"windows": "Windows", "macos": "macOS", "ios": "iOS",
	"android": "Android", "chromeos": "ChromeOS", "linux": "Linux",
}

var identityEngineOrder = []string{"blink", "gecko", "webkit"}

var identityEngineLabels = map[string]string{
	"blink": "Blink", "gecko": "Gecko", "webkit": "WebKit",
}

var (
	// ANGLE names its backend in the renderer string. Direct3D exists only on
	// Windows and Metal only on Apple platforms. Deliberately absent: GPU model
	// names. An Apple GPU runs Linux under Asahi, and Adreno/Mali ship in Windows
	// laptops and Chromebooks, so a model name says nothing certain about the OS.
	identityDirect3D  = regexp.MustCompile(`(?i)direct3d|\bd3d(9|11|12)\b`)
	identityMetal     = regexp.MustCompile(`(?i)\bmetal\b`)
	identityBlinkUA   = regexp.MustCompile(`(?:Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|SamsungBrowser)/`)
	identityBlinkErr  = regexp.MustCompile(`(?i)Cannot read propert(?:y|ies) of null`)
	identityGeckoErr  = regexp.MustCompile(`(?i)null has no properties|can't access property ["']foo["'] of null`)
	identityWebKitErr = regexp.MustCompile(`(?i)null is not an object`)
)

// claimedOS returns the OS families the User-Agent is consistent with, or nil.
// iPadOS requests desktop sites with a macOS UA, which touch points betray.
func claimedOS(ua string, maxTouchPoints float64) []string {
	switch {
	case ua == "":
		return nil
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") || strings.Contains(ua, "iPod"):
		return []string{"ios"}
	case strings.Contains(ua, "Android"):
		return []string{"android"}
	case strings.Contains(ua, "CrOS"):
		return []string{"chromeos"}
	case strings.Contains(ua, "Windows"):
		return []string{"windows"}
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		if maxTouchPoints > 1 {
			return []string{"macos", "ios"}
		}
		return []string{"macos"}
	case strings.Contains(ua, "Linux") || strings.Contains(ua, "X11"):
		return []string{"linux"}
	}
	return nil
}

// claimedEngine returns the browser engine implied by the UA. All iOS
// browsers use WebKit, including CriOS/FxiOS/EdgiOS.
func claimedEngine(ua string, maxTouchPoints float64) []string {
	switch {
	case ua == "":
		return nil
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") || strings.Contains(ua, "iPod"):
		return []string{"webkit"}
	case (strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X")) && maxTouchPoints > 1:
		return []string{"webkit"}
	case strings.Contains(ua, "Firefox/"):
		return []string{"gecko"}
	case identityBlinkUA.MatchString(ua):
		return []string{"blink"}
	case strings.Contains(ua, "AppleWebKit/") && strings.Contains(ua, "Safari/"):
		return []string{"webkit"}
	}
	return nil
}

type identityAxis struct {
	id        string
	dimension string
	observed  []string // nil when the axis knows nothing
	subject   string   // fixed text naming the measurement, never raw visitor data
}

func gpuBackendAxis(env map[string]interface{}) identityAxis {
	axis := identityAxis{id: "gpu-backend-os-mismatch", dimension: "os"}
	webgl := getMap(env, "webglInfo")
	if webgl["supported"] == false {
		return axis
	}
	renderer, _ := webgl["renderer"].(string)
	d3d, metal := identityDirect3D.MatchString(renderer), identityMetal.MatchString(renderer)
	switch {
	case d3d && !metal:
		axis.observed, axis.subject = []string{"windows"}, "WebGL Direct3D backend"
	case metal && !d3d:
		axis.observed, axis.subject = []string{"macos", "ios"}, "WebGL Metal backend"
	}
	return axis
}

// fontSetAxis mirrors checkFontPlatformCoherence: a short list is a blocked
// enumeration, and a mixed list (Office on a Mac) proves nothing.
func fontSetAxis(env map[string]interface{}) identityAxis {
	axis := identityAxis{id: "font-set-os-mismatch", dimension: "os"}
	fonts := getMap(env, "fontsInfo")
	if fonts == nil || fonts["supported"] == false || getFloat(fonts, "count") < 3 {
		return axis
	}
	has := func(k string) bool { v, _ := fonts[k].(bool); return v }
	mac := has("hasSFPro") || has("hasMenlo")
	win := has("hasSegoeUI") || has("hasCalibri")
	switch {
	case win && !mac:
		axis.observed, axis.subject = []string{"windows"}, "Font set (Windows faces)"
	case mac && !win:
		axis.observed, axis.subject = []string{"macos", "ios"}, "Font set (macOS faces)"
	}
	return axis
}

func errorEngine(env map[string]interface{}) string {
	fingerprint := getMap(env, "errorFingerprint")
	if fingerprint == nil || fingerprint["supported"] == false {
		return ""
	}
	message, _ := fingerprint["typeError"].(string)
	switch {
	case identityBlinkErr.MatchString(message):
		return "blink"
	case identityGeckoErr.MatchString(message):
		return "gecko"
	case identityWebKitErr.MatchString(message):
		return "webkit"
	}
	return ""
}

func mathEngine(env map[string]interface{}) string {
	fingerprint := getMap(env, "mathFingerprint")
	if fingerprint == nil || fingerprint["supported"] == false {
		return ""
	}
	hash, _ := fingerprint["hash"].(string)
	return map[string]string{"6256c877": "blink", "97ad9": "gecko", "-1128d0aa": "webkit"}[hash]
}

func probeEngine(env map[string]interface{}) string {
	probes := getMap(env, "engineProbes")
	if probes == nil || probes["supported"] == false {
		return ""
	}
	candidates := []string{}
	if probes["errorCaptureStackTrace"] == true {
		candidates = append(candidates, "blink")
	}
	if probes["mozAppearance"] == true {
		candidates = append(candidates, "gecko")
	}
	if probes["webkitTouchCallout"] == true {
		candidates = append(candidates, "webkit")
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return ""
}

func jsEngineAxis(env map[string]interface{}) identityAxis {
	axis := identityAxis{id: "js-engine-mismatch", dimension: "engine"}
	measured := []string{}
	for _, engine := range []string{errorEngine(env), mathEngine(env), probeEngine(env)} {
		if engine != "" {
			measured = append(measured, engine)
		}
	}
	if len(measured) < 2 {
		return axis
	}
	for _, engine := range measured[1:] {
		if engine != measured[0] {
			return axis
		}
	}
	axis.observed = []string{measured[0]}
	axis.subject = "JavaScript engine (" + identityEngineLabels[measured[0]] + ")"
	return axis
}

func identityOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func identityLabel(dimension string, set []string) string {
	order, names := identityOSOrder, identityOSLabels
	if dimension == "engine" {
		order, names = identityEngineOrder, identityEngineLabels
	}
	labels := make([]string, 0, len(set))
	for _, value := range order {
		for _, s := range set {
			if s == value {
				labels = append(labels, names[value])
			}
		}
	}
	return strings.Join(labels, "/")
}

func identityObservation(signals map[string]interface{}) ExperimentalObservation {
	result := ExperimentalObservation{Mode: "observe", Status: "unknown", Detections: []ExperimentalDetection{}}
	env := getMap(signals, "environmental")
	nav := getMap(env, "navigator")
	ua, _ := nav["userAgent"].(string)
	touch, _ := nav["maxTouchPoints"].(float64)
	claims := map[string][]string{"os": claimedOS(ua, touch), "engine": claimedEngine(ua, touch)}

	known := make([]identityAxis, 0, 3)
	for _, axis := range []identityAxis{gpuBackendAxis(env), fontSetAxis(env), jsEngineAxis(env)} {
		if axis.observed != nil && claims[axis.dimension] != nil {
			known = append(known, axis)
		}
	}
	if len(known) == 0 {
		return result
	}

	contradicting := make([]identityAxis, 0, len(known))
	for _, axis := range known {
		claim := claims[axis.dimension]
		if !identityOverlap(axis.observed, claim) {
			contradicting = append(contradicting, axis)
			claimedSubject := "OS"
			if axis.dimension == "engine" {
				claimedSubject = "browser engine"
			}
			result.Detections = append(result.Detections, ExperimentalDetection{
				ID:     axis.id,
				Reason: axis.subject + " contradicts claimed " + claimedSubject + " (" + identityLabel(axis.dimension, claim) + ")",
			})
		}
	}
	disagree := false
	for i := range known {
		for j := i + 1; j < len(known); j++ {
			if known[i].dimension == known[j].dimension && !identityOverlap(known[i].observed, known[j].observed) {
				disagree = true
			}
		}
	}
	switch {
	case disagree:
		result.Detections = append(result.Detections, ExperimentalDetection{
			ID: "identity-axes-disagree", Reason: "Measured properties disagree with each other",
		})
	case identityContradictionsAgree(contradicting):
		result.Detections = append(result.Detections, ExperimentalDetection{
			ID:     "identity-claim-contradicted",
			Reason: "Several measured properties agree with each other and contradict the claimed OS",
		})
	}

	result.Status = "clear"
	if len(result.Detections) > 0 {
		result.Status = "detected"
	}
	return result
}

func identityContradictionsAgree(axes []identityAxis) bool {
	for i := range axes {
		for j := i + 1; j < len(axes); j++ {
			if axes[i].dimension == axes[j].dimension && identityOverlap(axes[i].observed, axes[j].observed) {
				return true
			}
		}
	}
	return false
}
