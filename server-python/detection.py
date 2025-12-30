"""
FCaptcha Detection Module - Additional Detection Capabilities

IP Reputation, Header Analysis, Browser Consistency, TLS Fingerprinting
"""

import re
import socket
import ipaddress
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# =============================================================================
# Datacenter IP Ranges
# =============================================================================

DATACENTER_CIDRS = [
    # AWS
    "3.0.0.0/8", "13.0.0.0/8", "18.0.0.0/8", "34.0.0.0/8", "35.0.0.0/8",
    "52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8",
    # Google Cloud
    "34.64.0.0/10", "35.184.0.0/13", "104.154.0.0/15", "104.196.0.0/14",
    # Azure
    "13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.224.0.0/11",
    # DigitalOcean
    "64.225.0.0/16", "68.183.0.0/16", "104.131.0.0/16", "134.209.0.0/16",
    "138.68.0.0/16", "139.59.0.0/16", "142.93.0.0/16", "157.245.0.0/16",
    "159.65.0.0/16", "159.89.0.0/16", "161.35.0.0/16", "164.90.0.0/16",
    # Linode
    "45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "50.116.0.0/16",
    "139.162.0.0/16", "172.104.0.0/15",
    # Vultr
    "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16",
    "108.61.0.0/16", "149.28.0.0/16",
    # Hetzner
    "5.9.0.0/16", "46.4.0.0/14", "78.46.0.0/15", "88.99.0.0/16",
    "95.216.0.0/14", "135.181.0.0/16", "136.243.0.0/16",
    # OVH
    "51.38.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16",
    "51.79.0.0/16", "51.81.0.0/16", "51.89.0.0/16", "51.91.0.0/16",
    "137.74.0.0/16", "139.99.0.0/16", "144.217.0.0/16", "149.56.0.0/16",
    "158.69.0.0/16", "167.114.0.0/16",
]

DATACENTER_NETWORKS = [ipaddress.ip_network(cidr) for cidr in DATACENTER_CIDRS]

VPN_PROXY_PATTERNS = [
    re.compile(r'(?i)vpn'),
    re.compile(r'(?i)proxy'),
    re.compile(r'(?i)tor-exit'),
    re.compile(r'(?i)exit-?node'),
    re.compile(r'(?i)anonymizer'),
    re.compile(r'(?i)tunnel'),
]

def is_datacenter_ip(ip_str: str) -> bool:
    """Check if IP belongs to a known datacenter."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in DATACENTER_NETWORKS)
    except ValueError:
        return False


def check_ip_reputation(ip: str) -> List[Dict]:
    """Check IP reputation for threats."""
    detections = []

    # Datacenter check
    if is_datacenter_ip(ip):
        detections.append({
            "category": "datacenter",
            "score": 0.6,
            "confidence": 0.8,
            "reason": "Request from known datacenter IP range"
        })

    # Reverse DNS check for VPN/proxy patterns
    try:
        hostnames = socket.gethostbyaddr(ip)[0]
        for pattern in VPN_PROXY_PATTERNS:
            if pattern.search(hostnames):
                detections.append({
                    "category": "tor_vpn",
                    "score": 0.5,
                    "confidence": 0.6,
                    "reason": f"Reverse DNS suggests VPN/proxy: {hostnames}"
                })
                break
    except (socket.herror, socket.gaierror):
        pass

    return detections


# =============================================================================
# HTTP Header Analysis
# =============================================================================

SUSPICIOUS_HEADERS = {
    "x-requested-with", "x-forwarded-for", "x-real-ip", "via",
    "forwarded", "x-originating-ip", "cf-connecting-ip",
    "true-client-ip", "x-cluster-client-ip"
}

EXPECTED_BROWSER_HEADERS = {"accept", "accept-language", "accept-encoding", "user-agent"}

def analyze_headers(headers: Dict[str, str]) -> List[Dict]:
    """Analyze HTTP headers for bot indicators."""
    detections = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check for missing expected headers
    missing_count = sum(1 for h in EXPECTED_BROWSER_HEADERS if h not in headers_lower)
    if missing_count > 1:
        detections.append({
            "category": "bot",
            "score": 0.4,
            "confidence": 0.5,
            "reason": f"Missing {missing_count} expected browser headers"
        })

    # Check for suspicious headers
    for header in headers_lower:
        if header in SUSPICIOUS_HEADERS:
            detections.append({
                "category": "bot",
                "score": 0.3,
                "confidence": 0.4,
                "reason": f"Suspicious header present: {header}"
            })

    # Check Accept-Language
    accept_lang = headers_lower.get("accept-language", "")
    if accept_lang in ("", "*"):
        detections.append({
            "category": "bot",
            "score": 0.3,
            "confidence": 0.4,
            "reason": "Invalid Accept-Language header"
        })

    # Check Accept-Encoding
    accept_enc = headers_lower.get("accept-encoding", "")
    if accept_enc and "gzip" not in accept_enc and "deflate" not in accept_enc:
        detections.append({
            "category": "bot",
            "score": 0.2,
            "confidence": 0.3,
            "reason": "Unusual Accept-Encoding"
        })

    return detections


# =============================================================================
# Browser Consistency Checks
# =============================================================================

BOT_UA_PATTERNS = [
    re.compile(r'(?i)bot'), re.compile(r'(?i)spider'), re.compile(r'(?i)crawler'),
    re.compile(r'(?i)scraper'), re.compile(r'(?i)curl'), re.compile(r'(?i)wget'),
    re.compile(r'(?i)python'), re.compile(r'(?i)java\/'), re.compile(r'(?i)httpie'),
    re.compile(r'(?i)postman'), re.compile(r'(?i)insomnia'), re.compile(r'(?i)axios'),
    re.compile(r'(?i)node-fetch'), re.compile(r'(?i)go-http'), re.compile(r'(?i)okhttp'),
]

def parse_user_agent(ua: str) -> Dict[str, Any]:
    """Parse user agent string."""
    info = {"browser": None, "os": None, "is_mobile": False, "is_bot": False, "bot_name": None}

    # Check for bots
    for pattern in BOT_UA_PATTERNS:
        match = pattern.search(ua)
        if match:
            info["is_bot"] = True
            info["bot_name"] = match.group(0)
            return info

    # Detect browser
    if "Edg/" in ua:
        info["browser"] = "Edge"
    elif "Chrome/" in ua:
        info["browser"] = "Chrome"
    elif "Firefox/" in ua:
        info["browser"] = "Firefox"
    elif "Safari/" in ua and "Chrome" not in ua:
        info["browser"] = "Safari"

    # Detect OS
    if "Windows" in ua:
        info["os"] = "Windows"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        info["os"] = "macOS"
    elif "Linux" in ua:
        info["os"] = "Linux"
    elif "Android" in ua:
        info["os"] = "Android"
        info["is_mobile"] = True
    elif "iPhone" in ua or "iPad" in ua:
        info["os"] = "iOS"
        info["is_mobile"] = True

    if "Mobile" in ua:
        info["is_mobile"] = True

    return info


def check_browser_consistency(ua: str, signals: Dict) -> List[Dict]:
    """Verify UA matches actual browser behavior."""
    detections = []
    ua_info = parse_user_agent(ua)

    # If UA is a known bot
    if ua_info["is_bot"]:
        detections.append({
            "category": "bot",
            "score": 0.9,
            "confidence": 0.95,
            "reason": f"User-Agent indicates bot: {ua_info['bot_name']}"
        })
        return detections

    env = signals.get("environmental", {})
    nav = env.get("navigator", {})
    automation = env.get("automationFlags", {})

    # Check platform consistency
    platform = nav.get("platform", "") or automation.get("platform", "")

    if ua_info["os"] == "Windows" and "Win" not in platform:
        detections.append({
            "category": "bot",
            "score": 0.6,
            "confidence": 0.7,
            "reason": f"UA/platform mismatch: UA claims Windows, platform={platform}"
        })

    if ua_info["os"] == "macOS" and "Mac" not in platform:
        detections.append({
            "category": "bot",
            "score": 0.6,
            "confidence": 0.7,
            "reason": f"UA/platform mismatch: UA claims macOS, platform={platform}"
        })

    if ua_info["os"] == "Linux" and "Linux" not in platform:
        detections.append({
            "category": "bot",
            "score": 0.6,
            "confidence": 0.7,
            "reason": f"UA/platform mismatch: UA claims Linux, platform={platform}"
        })

    # Check mobile consistency
    max_touch = nav.get("maxTouchPoints", 0) or automation.get("maxTouchPoints", 0)
    if ua_info["is_mobile"] and max_touch == 0:
        detections.append({
            "category": "bot",
            "score": 0.5,
            "confidence": 0.6,
            "reason": "UA claims mobile but no touch support"
        })

    # Check Chrome-specific properties
    if ua_info["browser"] == "Chrome":
        has_chrome = automation.get("chrome", False)
        if not has_chrome:
            detections.append({
                "category": "bot",
                "score": 0.7,
                "confidence": 0.8,
                "reason": "UA claims Chrome but window.chrome missing"
            })

    return detections


# =============================================================================
# TLS Fingerprinting (JA3)
# =============================================================================

KNOWN_BOT_JA3_HASHES = {
    "3b5074b1b5d032e5620f69f9f700ff0e": "Python requests",
    "b32309a26951912be7dba376398abc3b": "Python urllib",
    "9e10692f1b7f78228b2d4e424db3a98c": "Go net/http",
    "473cd7cb9faa642487833865d516e578": "curl",
    "c12f54a3f91dc7bafd92cb59fe009a35": "Wget",
    "2d1eb5817ece335c24904f516ad5da2f": "Java HttpClient",
    "fc54fe03db02a25e1be5bb5a7678b7a4": "Node.js axios",
    "579ccef312d18482fc42e2b822ca2430": "Node.js node-fetch",
    "5d7974c9fe7862e0f9a3eb35a6a5d9c8": "Puppeteer default",
}

def check_ja3_fingerprint(ja3_hash: Optional[str]) -> List[Dict]:
    """Check TLS fingerprint against known bots."""
    if not ja3_hash:
        return []

    if ja3_hash in KNOWN_BOT_JA3_HASHES:
        return [{
            "category": "bot",
            "score": 0.8,
            "confidence": 0.9,
            "reason": f"TLS fingerprint matches: {KNOWN_BOT_JA3_HASHES[ja3_hash]}"
        }]

    return []


# =============================================================================
# Form Interaction Analysis (Credential Stuffing & Spam Detection)
# =============================================================================

def analyze_form_interaction(form_analysis: Optional[Dict]) -> List[Dict]:
    """Analyze form submission patterns for credential stuffing and spam."""
    if not form_analysis:
        return []

    detections = []
    submit = form_analysis.get("submit", {})

    # Check for programmatic form submission (credential stuffing)
    method = submit.get("method", "")
    if method in ("programmatic", "programmatic_click"):
        detections.append({
            "category": "bot",
            "score": 0.8,
            "confidence": 0.85,
            "reason": f"Form submitted programmatically ({method})"
        })

    # Check timing - too fast from page load to submit
    time_since_load = submit.get("timeSincePageLoad")
    if time_since_load is not None and time_since_load < 800:
        detections.append({
            "category": "bot",
            "score": 0.7,
            "confidence": 0.75,
            "reason": f"Form submitted too quickly after page load ({int(time_since_load)}ms)"
        })

    # Check timing - too fast from page load to first interaction
    page_to_first = form_analysis.get("pageLoadToFirstInteraction")
    if page_to_first is not None and page_to_first < 300:
        detections.append({
            "category": "bot",
            "score": 0.6,
            "confidence": 0.65,
            "reason": f"First interaction too fast after page load ({int(page_to_first)}ms)"
        })

    # Check for no trigger event before submit
    events_before = submit.get("eventsBeforeSubmit", 0)
    if events_before == 0 and method != "none":
        detections.append({
            "category": "bot",
            "score": 0.9,
            "confidence": 0.9,
            "reason": "Form submitted with no user interaction events"
        })

    # Check for very low event count before submit
    if 0 < events_before < 3 and method != "none":
        detections.append({
            "category": "bot",
            "score": 0.5,
            "confidence": 0.6,
            "reason": f"Very few events before submit ({events_before})"
        })

    # Textarea keyboard analysis (spam detection)
    textarea_data = form_analysis.get("textareaKeyboard")
    if textarea_data:
        for field_id, stats in textarea_data.items():
            paste_count = stats.get("pasteCount", 0)
            key_count = stats.get("keyCount", 0)
            avg_interval = stats.get("avgKeyInterval", 0)
            interval_variance = stats.get("keyIntervalVariance", 0)
            keydown_up_ratio = stats.get("keydownUpRatio", 1.0)

            # Check for paste-heavy input (spam bots often paste content)
            if paste_count > 0 and key_count < 5:
                detections.append({
                    "category": "bot",
                    "score": 0.6,
                    "confidence": 0.6,
                    "reason": f'Textarea "{field_id}" filled mostly by paste ({paste_count} pastes, {key_count} keystrokes)'
                })

            # Check for unnaturally consistent typing (bots have perfect timing)
            if key_count > 10 and interval_variance < 100:
                detections.append({
                    "category": "bot",
                    "score": 0.5,
                    "confidence": 0.55,
                    "reason": f'Textarea "{field_id}" has unnaturally consistent typing rhythm'
                })

            # Check for impossibly fast typing (< 50ms between keys = 1200+ WPM)
            if key_count > 10 and 0 < avg_interval < 50:
                detections.append({
                    "category": "bot",
                    "score": 0.7,
                    "confidence": 0.7,
                    "reason": f'Textarea "{field_id}" typing speed impossibly fast ({int(avg_interval)}ms/key)'
                })

            # Check keydown/keyup ratio (should be ~1.0 for real typing)
            if key_count > 10 and (keydown_up_ratio < 0.8 or keydown_up_ratio > 1.2):
                detections.append({
                    "category": "bot",
                    "score": 0.4,
                    "confidence": 0.5,
                    "reason": f'Textarea "{field_id}" has abnormal keydown/keyup ratio ({keydown_up_ratio:.2f})'
                })

    return detections


# =============================================================================
# CDP Detection
# =============================================================================

def detect_cdp(signals: Dict) -> List[Dict]:
    """Detect Chrome DevTools Protocol (CDP) automation artifacts."""
    detections = []
    env = signals.get("environmental", {})
    cdp = env.get("cdp", {})

    if not cdp.get("detected"):
        return detections

    signal_list = cdp.get("signals", [])
    signal_count = len(signal_list)

    if signal_count == 0:
        return detections

    # High-confidence signals
    high_conf_signals = ['chromedriver_cdc', 'puppeteer_eval', 'cdp_script_injection']
    has_high_conf = any(s in high_conf_signals for s in signal_list)

    signals_joined = ', '.join(signal_list)

    if has_high_conf:
        detections.append({
            "category": "cdp",
            "score": 0.9,
            "confidence": 0.95,
            "reason": f"CDP automation detected: {signals_joined}"
        })
    elif signal_count >= 2:
        detections.append({
            "category": "cdp",
            "score": 0.8,
            "confidence": 0.85,
            "reason": f"Multiple CDP indicators: {signals_joined}"
        })
    else:
        detections.append({
            "category": "cdp",
            "score": 0.6,
            "confidence": 0.7,
            "reason": f"CDP indicator: {signals_joined}"
        })

    return detections
