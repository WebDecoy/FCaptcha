"""
FCaptcha Server - Python/FastAPI Implementation

Run: uvicorn server:app --host 0.0.0.0 --port 3000
"""

import os
import time
import hmac
import hashlib
import base64
import json
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="FCaptcha", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("FCAPTCHA_SECRET", "dev-secret-change-in-production")


# =============================================================================
# Models
# =============================================================================

class PoWSolution(BaseModel):
    challengeId: str
    nonce: int
    hash: str

class VerifyRequest(BaseModel):
    siteKey: str
    signals: Dict[str, Any]
    powSolution: Optional[PoWSolution] = None

class ScoreRequest(BaseModel):
    siteKey: str
    signals: Dict[str, Any]
    action: str = ""
    powSolution: Optional[PoWSolution] = None

class TokenVerifyRequest(BaseModel):
    token: str
    secret: str


# =============================================================================
# Threat Categories
# =============================================================================

class ThreatCategory(str, Enum):
    VISION_AI = "vision_ai"
    HEADLESS = "headless"
    AUTOMATION = "automation"
    CDP = "cdp"
    BOT = "bot"
    CAPTCHA_FARM = "captcha_farm"
    BEHAVIORAL = "behavioral"
    FINGERPRINT = "fingerprint"
    RATE_LIMIT = "rate_limit"


@dataclass
class Detection:
    category: ThreatCategory
    score: float
    confidence: float
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Rate Limiter (In-Memory - Use Redis in production)
# =============================================================================

class RateLimiter:
    def __init__(self):
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def check(self, key: str, window: int = 60, max_requests: int = 10) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - window

        self.requests[key] = [t for t in self.requests[key] if t > cutoff]
        count = len(self.requests[key])

        if count >= max_requests:
            return True, count

        self.requests[key].append(now)
        return False, count + 1


class FingerprintStore:
    def __init__(self):
        self.fingerprints: Dict[str, Dict] = {}
        self.ip_fingerprints: Dict[str, set] = defaultdict(set)

    def record(self, fp: str, ip: str, site_key: str):
        key = f"{site_key}:{fp}"
        if key not in self.fingerprints:
            self.fingerprints[key] = {"count": 0, "ips": set()}
        self.fingerprints[key]["count"] += 1
        self.fingerprints[key]["ips"].add(ip)
        self.ip_fingerprints[ip].add(fp)

    def get_ip_fp_count(self, ip: str) -> int:
        return len(self.ip_fingerprints.get(ip, set()))

    def get_fp_ip_count(self, fp: str, site_key: str) -> int:
        key = f"{site_key}:{fp}"
        return len(self.fingerprints.get(key, {}).get("ips", set()))


class PoWChallengeStore:
    """Manages PoW challenges and verifies solutions."""
    def __init__(self):
        self.challenges: Dict[str, Dict] = {}
        self.used_solutions: set = set()

    def generate(self, site_key: str, ip: str, is_datacenter: bool = False) -> Dict:
        import secrets
        challenge_id = secrets.token_hex(16)
        now = int(time.time() * 1000)
        expires_at = now + (5 * 60 * 1000)  # 5 minutes

        # Difficulty scaling
        difficulty = 4  # Default: ~100-500ms on average hardware
        if is_datacenter:
            difficulty = 5  # Harder for datacenter IPs

        # Check rate for this IP
        rate_key = f"pow:{site_key}:{ip}"
        _, count = rate_limiter.check(rate_key, 60, 20)
        if count > 10:
            difficulty = min(6, difficulty + 1)

        prefix = f"{challenge_id}:{now}:{difficulty}"

        challenge = {
            "id": challenge_id,
            "siteKey": site_key,
            "prefix": prefix,
            "difficulty": difficulty,
            "timestamp": now,
            "expiresAt": expires_at,
            "ip": ip
        }

        # Sign the challenge
        sig_data = json.dumps({
            "id": challenge_id,
            "siteKey": site_key,
            "timestamp": now,
            "expiresAt": expires_at,
            "difficulty": difficulty,
            "prefix": prefix
        }, sort_keys=True)
        sig = hmac.new(SECRET_KEY.encode(), sig_data.encode(), hashlib.sha256).hexdigest()[:16]
        challenge["sig"] = sig

        # Store challenge
        self.challenges[challenge_id] = challenge

        # Cleanup old challenges periodically
        if len(self.challenges) % 10 == 0:
            self._cleanup()

        return {
            "challengeId": challenge_id,
            "prefix": prefix,
            "difficulty": difficulty,
            "expiresAt": expires_at,
            "sig": sig
        }

    def verify(self, solution: PoWSolution, site_key: str) -> Dict:
        if not solution or not solution.challengeId:
            return {"valid": False, "reason": "no_solution"}

        challenge = self.challenges.get(solution.challengeId)
        if not challenge:
            return {"valid": False, "reason": "challenge_not_found"}

        now = int(time.time() * 1000)
        if now > challenge["expiresAt"]:
            del self.challenges[solution.challengeId]
            return {"valid": False, "reason": "challenge_expired"}

        if challenge["siteKey"] != site_key:
            return {"valid": False, "reason": "site_key_mismatch"}

        # Check if solution was already used
        solution_key = f"{solution.challengeId}:{solution.nonce}"
        if solution_key in self.used_solutions:
            return {"valid": False, "reason": "solution_already_used"}

        # Verify the hash
        input_str = f"{challenge['prefix']}:{solution.nonce}"
        expected_hash = hashlib.sha256(input_str.encode()).hexdigest()

        if solution.hash != expected_hash:
            return {"valid": False, "reason": "invalid_hash"}

        # Check difficulty (hash must start with N zeros)
        target = "0" * challenge["difficulty"]
        if not solution.hash.startswith(target):
            return {"valid": False, "reason": "insufficient_difficulty"}

        # Mark solution as used
        self.used_solutions.add(solution_key)

        # Delete challenge (one-time use)
        del self.challenges[solution.challengeId]

        return {"valid": True, "difficulty": challenge["difficulty"]}

    def _cleanup(self):
        now = int(time.time() * 1000)
        expired = [cid for cid, c in self.challenges.items() if now > c["expiresAt"]]
        for cid in expired:
            del self.challenges[cid]

        # Clear used solutions if too many
        if len(self.used_solutions) > 10000:
            self.used_solutions.clear()


rate_limiter = RateLimiter()
fingerprint_store = FingerprintStore()
pow_store = PoWChallengeStore()

AUTOMATION_UA_PATTERNS = [
    re.compile(p, re.I) for p in [
        r'headless', r'phantomjs', r'selenium', r'webdriver',
        r'puppeteer', r'playwright', r'cypress', r'nightwatch',
        r'zombie', r'electron', r'chromium.*headless'
    ]
]

WEIGHTS = {
    ThreatCategory.VISION_AI: 0.15,
    ThreatCategory.HEADLESS: 0.15,
    ThreatCategory.AUTOMATION: 0.10,
    ThreatCategory.CDP: 0.12,
    ThreatCategory.BEHAVIORAL: 0.18,
    ThreatCategory.FINGERPRINT: 0.10,
    ThreatCategory.RATE_LIMIT: 0.10,
    ThreatCategory.BOT: 0.10,
}


# =============================================================================
# Detection Functions
# =============================================================================

def get_nested(d: dict, *keys, default=None):
    """Safely get nested dict values."""
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key, default)
        else:
            return default
    return d


def detect_vision_ai(signals: Dict) -> List[Detection]:
    detections = []
    b = signals.get("behavioral", {})
    t = signals.get("temporal", {})

    # PoW timing
    pow_data = t.get("pow", {})
    if pow_data:
        duration = pow_data.get("duration", 0)
        iterations = pow_data.get("iterations", 0)

        if iterations > 0:
            expected_min = (iterations / 500000) * 1000
            expected_max = (iterations / 50000) * 1000

            if duration < expected_min * 0.5:
                detections.append(Detection(
                    ThreatCategory.VISION_AI, 0.8, 0.7,
                    "PoW completed impossibly fast",
                    {"duration": duration, "expected_min": expected_min}
                ))
            elif duration > expected_max * 3:
                detections.append(Detection(
                    ThreatCategory.VISION_AI, 0.6, 0.5,
                    "PoW timing suggests external processing"
                ))

    # Micro-tremor
    micro_tremor = b.get("microTremorScore", 0.5)
    if micro_tremor < 0.15:
        detections.append(Detection(
            ThreatCategory.VISION_AI, 0.7, 0.6,
            "Mouse movement lacks natural micro-tremor",
            {"microTremorScore": micro_tremor}
        ))

    # Approach directness
    approach = b.get("approachDirectness", 0.5)
    if approach > 0.95:
        detections.append(Detection(
            ThreatCategory.VISION_AI, 0.5, 0.5,
            "Mouse path to target is unnaturally direct"
        ))

    # Click precision
    precision = b.get("clickPrecision", 10)
    if 0 < precision < 2:
        detections.append(Detection(
            ThreatCategory.VISION_AI, 0.4, 0.5,
            "Click precision is unnaturally accurate"
        ))

    # Exploration
    exploration = b.get("explorationRatio", 0.3)
    trajectory = b.get("trajectoryLength", 0)
    if exploration < 0.05 and trajectory > 50:
        detections.append(Detection(
            ThreatCategory.VISION_AI, 0.4, 0.4,
            "No exploratory mouse movement before click"
        ))

    return detections


def detect_headless(signals: Dict, user_agent: str) -> List[Detection]:
    detections = []
    env = signals.get("environmental", {})
    headless = env.get("headlessIndicators", {})
    automation = env.get("automationFlags", {})

    # WebDriver
    if env.get("webdriver"):
        detections.append(Detection(
            ThreatCategory.HEADLESS, 0.95, 0.95,
            "WebDriver detected (navigator.webdriver = true)"
        ))

    # Automation flags
    if automation:
        if automation.get("plugins", 1) == 0:
            detections.append(Detection(
                ThreatCategory.HEADLESS, 0.6, 0.6,
                "No browser plugins detected"
            ))
        if not automation.get("languages"):
            detections.append(Detection(
                ThreatCategory.HEADLESS, 0.5, 0.5,
                "No navigator.languages"
            ))

    # Headless indicators
    if headless:
        if not headless.get("hasOuterDimensions"):
            detections.append(Detection(
                ThreatCategory.HEADLESS, 0.7, 0.7,
                "Window lacks outer dimensions"
            ))
        if headless.get("innerEqualsOuter"):
            detections.append(Detection(
                ThreatCategory.HEADLESS, 0.4, 0.5,
                "Viewport equals window size"
            ))
        if headless.get("notificationPermission") == "denied":
            detections.append(Detection(
                ThreatCategory.HEADLESS, 0.3, 0.4,
                "Notifications pre-denied"
            ))

    # User-Agent patterns
    for pattern in AUTOMATION_UA_PATTERNS:
        if pattern.search(user_agent):
            detections.append(Detection(
                ThreatCategory.HEADLESS, 0.9, 0.9,
                "Automation pattern in User-Agent"
            ))
            break

    # WebGL renderer
    webgl = env.get("webglInfo", {})
    renderer = (webgl.get("renderer") or "").lower()
    if "swiftshader" in renderer or "llvmpipe" in renderer:
        detections.append(Detection(
            ThreatCategory.HEADLESS, 0.8, 0.8,
            "Software WebGL renderer detected"
        ))

    return detections


def detect_automation(signals: Dict) -> List[Detection]:
    detections = []
    env = signals.get("environmental", {})
    b = signals.get("behavioral", {})

    # JS execution timing
    js_time = get_nested(env, "jsExecutionTime", "mathOps", default=0)
    if js_time > 0:
        if js_time < 0.1:
            detections.append(Detection(
                ThreatCategory.AUTOMATION, 0.4, 0.3,
                "JS execution unusually fast"
            ))
        elif js_time > 50:
            detections.append(Detection(
                ThreatCategory.AUTOMATION, 0.3, 0.3,
                "JS execution unusually slow"
            ))

    # RAF consistency
    raf = env.get("rafConsistency", {})
    if raf and raf.get("frameTimeVariance", 1) < 0.1:
        detections.append(Detection(
            ThreatCategory.AUTOMATION, 0.5, 0.4,
            "RequestAnimationFrame timing too consistent"
        ))

    # Event timing
    event_var = b.get("eventDeltaVariance", 10)
    total_points = b.get("totalPoints", 0)
    if event_var < 2 and total_points > 10:
        detections.append(Detection(
            ThreatCategory.AUTOMATION, 0.6, 0.6,
            "Mouse event timing unnaturally consistent"
        ))

    return detections


def detect_cdp(signals: Dict) -> List[Detection]:
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
        detections.append(Detection(
            ThreatCategory.CDP, 0.9, 0.95,
            f"CDP automation detected: {signals_joined}"
        ))
    elif signal_count >= 2:
        detections.append(Detection(
            ThreatCategory.CDP, 0.8, 0.85,
            f"Multiple CDP indicators: {signals_joined}"
        ))
    else:
        detections.append(Detection(
            ThreatCategory.CDP, 0.6, 0.7,
            f"CDP indicator: {signals_joined}"
        ))

    return detections


def detect_behavioral(signals: Dict) -> List[Detection]:
    detections = []
    b = signals.get("behavioral", {})
    t = signals.get("temporal", {})

    # Velocity variance
    vel_var = b.get("velocityVariance", 1)
    trajectory = b.get("trajectoryLength", 0)
    if vel_var < 0.02 and trajectory > 50:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.6, 0.6,
            "Mouse velocity too consistent"
        ))

    # Overshoot
    overshoots = b.get("overshootCorrections", 0)
    if overshoots == 0 and trajectory > 200:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.4, 0.4,
            "No overshoot corrections on long trajectory"
        ))

    # Interaction speed
    interaction_time = b.get("interactionDuration", 1000)
    if 0 < interaction_time < 200:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.7, 0.7,
            "Interaction completed too quickly"
        ))
    elif interaction_time > 60000:
        detections.append(Detection(
            ThreatCategory.CAPTCHA_FARM, 0.3, 0.3,
            "Unusually long interaction time"
        ))

    # First interaction timing
    first_int = t.get("pageLoadToFirstInteraction")
    if first_int is not None and 0 < first_int < 100:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.5, 0.5,
            "First interaction too soon after page load"
        ))

    # Mouse event rate
    event_rate = b.get("mouseEventRate", 60)
    if event_rate > 200:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.6, 0.5,
            "Mouse event rate abnormally high"
        ))
    elif 0 < event_rate < 10:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.4, 0.4,
            "Mouse event rate abnormally low"
        ))

    # Straight line ratio
    straight = b.get("straightLineRatio", 0)
    if straight > 0.8 and trajectory > 100:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.5, 0.5,
            "Mouse movements too straight"
        ))

    # Direction changes
    dir_changes = b.get("directionChanges", 10)
    total_points = b.get("totalPoints", 0)
    if total_points > 50 and dir_changes < 3:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.4, 0.4,
            "Too few direction changes"
        ))

    return detections


def detect_fingerprint(signals: Dict, ip: str, site_key: str) -> List[Detection]:
    detections = []
    env = signals.get("environmental", {})
    automation = env.get("automationFlags", {})

    # Generate fingerprint
    components = [
        str(get_nested(env, "canvasHash", "hash", default="")),
        str(get_nested(env, "webglInfo", "renderer", default="")),
        str(automation.get("platform", "")),
        str(automation.get("hardwareConcurrency", ""))
    ]
    fp = hashlib.sha256("|".join(components).encode()).hexdigest()[:16]

    fingerprint_store.record(fp, ip, site_key)

    # IP fingerprint count
    ip_fp_count = fingerprint_store.get_ip_fp_count(ip)
    if ip_fp_count > 5:
        detections.append(Detection(
            ThreatCategory.FINGERPRINT, 0.6, 0.6,
            "IP has used many different fingerprints",
            {"count": ip_fp_count}
        ))

    # Fingerprint IP count
    fp_ip_count = fingerprint_store.get_fp_ip_count(fp, site_key)
    if fp_ip_count > 10:
        detections.append(Detection(
            ThreatCategory.FINGERPRINT, 0.5, 0.5,
            "Fingerprint seen from many IPs",
            {"count": fp_ip_count}
        ))

    # Canvas issues
    canvas = env.get("canvasHash", {})
    if canvas.get("error") or not canvas.get("supported"):
        detections.append(Detection(
            ThreatCategory.FINGERPRINT, 0.4, 0.4,
            "Canvas fingerprinting blocked or failed"
        ))

    return detections


def detect_rate_abuse(ip: str, site_key: str) -> List[Detection]:
    detections = []
    key = f"{site_key}:{ip}"

    exceeded, count = rate_limiter.check(key, 60, 10)
    if exceeded:
        detections.append(Detection(
            ThreatCategory.RATE_LIMIT, 0.8, 0.9,
            "Rate limit exceeded",
            {"count": count}
        ))
    elif count > 5:
        detections.append(Detection(
            ThreatCategory.RATE_LIMIT, 0.3, 0.5,
            "High request rate",
            {"count": count}
        ))

    return detections


# =============================================================================
# Scoring
# =============================================================================

def calculate_category_scores(detections: List[Detection]) -> Dict[str, float]:
    category_data: Dict[ThreatCategory, List[tuple]] = defaultdict(list)

    for d in detections:
        category_data[d.category].append((d.score, d.confidence))

    result = {}
    for cat, scores in category_data.items():
        if scores:
            total_weight = sum(conf for _, conf in scores)
            if total_weight > 0:
                weighted_sum = sum(score * conf for score, conf in scores)
                result[cat.value] = min(1.0, weighted_sum / total_weight)

    # Fill missing
    for cat in ThreatCategory:
        if cat.value not in result:
            result[cat.value] = 0.0

    return result


def calculate_final_score(category_scores: Dict[str, float]) -> float:
    total = 0.0
    for cat, weight in WEIGHTS.items():
        total += category_scores.get(cat.value, 0.0) * weight
    return min(1.0, total)


def generate_token(ip: str, site_key: str, score: float) -> str:
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:8]
    data = {
        "site_key": site_key,
        "timestamp": int(time.time()),
        "score": round(score, 3),
        "ip_hash": ip_hash
    }
    payload = json.dumps(data, sort_keys=True)
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    data["sig"] = sig
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def verify_token(token: str) -> Dict:
    try:
        decoded = json.loads(base64.urlsafe_b64decode(token).decode())

        # Check expiration
        if time.time() - decoded.get("timestamp", 0) > 300:
            return {"valid": False, "reason": "expired"}

        sig = decoded.pop("sig", "")
        payload = json.dumps(decoded, sort_keys=True)
        expected_sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]

        if not hmac.compare_digest(sig, expected_sig):
            return {"valid": False, "reason": "invalid_signature"}

        return {
            "valid": True,
            "site_key": decoded.get("site_key"),
            "timestamp": decoded.get("timestamp"),
            "score": decoded.get("score")
        }
    except Exception as e:
        return {"valid": False, "reason": str(e)}


def run_verification(
    signals: Dict,
    ip: str,
    site_key: str,
    user_agent: str,
    headers: Dict[str, str] = None,
    ja3_hash: str = None,
    pow_solution: PoWSolution = None
) -> Dict:
    from detection import (
        check_ip_reputation, analyze_headers,
        check_browser_consistency, check_ja3_fingerprint,
        analyze_form_interaction
    )

    detections = []

    # Verify PoW if provided
    if pow_solution:
        pow_result = pow_store.verify(pow_solution, site_key)
        if not pow_result["valid"]:
            detections.append(Detection(
                ThreatCategory.BOT, 0.7, 0.8,
                f"PoW verification failed: {pow_result['reason']}"
            ))
    else:
        # No PoW solution provided - suspicious
        detections.append(Detection(
            ThreatCategory.BOT, 0.5, 0.6,
            "No PoW solution provided"
        ))

    # Behavioral detectors
    detections.extend(detect_vision_ai(signals))
    detections.extend(detect_headless(signals, user_agent))
    detections.extend(detect_automation(signals))
    detections.extend(detect_cdp(signals))
    detections.extend(detect_behavioral(signals))
    detections.extend(detect_fingerprint(signals, ip, site_key))
    detections.extend(detect_rate_abuse(ip, site_key))

    # Network/infrastructure detectors
    for d in check_ip_reputation(ip):
        detections.append(Detection(
            ThreatCategory(d["category"]) if d["category"] in [e.value for e in ThreatCategory] else ThreatCategory.BOT,
            d["score"], d["confidence"], d["reason"]
        ))

    for d in check_browser_consistency(user_agent, signals):
        detections.append(Detection(
            ThreatCategory.BOT, d["score"], d["confidence"], d["reason"]
        ))

    # HTTP-level detectors
    if headers:
        for d in analyze_headers(headers):
            detections.append(Detection(
                ThreatCategory.BOT, d["score"], d["confidence"], d["reason"]
            ))

    # TLS fingerprint
    if ja3_hash:
        for d in check_ja3_fingerprint(ja3_hash):
            detections.append(Detection(
                ThreatCategory.BOT, d["score"], d["confidence"], d["reason"]
            ))

    # Form interaction analysis (credential stuffing & spam detection)
    form_analysis = signals.get("formAnalysis")
    if form_analysis:
        for d in analyze_form_interaction(form_analysis):
            detections.append(Detection(
                ThreatCategory.BOT, d["score"], d["confidence"], d["reason"]
            ))

    category_scores = calculate_category_scores(detections)
    final_score = calculate_final_score(category_scores)

    if final_score < 0.3:
        recommendation = "allow"
    elif final_score < 0.6:
        recommendation = "challenge"
    else:
        recommendation = "block"

    success = final_score < 0.5
    token = generate_token(ip, site_key, final_score) if success else None

    return {
        "success": success,
        "score": final_score,
        "token": token,
        "timestamp": int(time.time()),
        "recommendation": recommendation,
        "categoryScores": category_scores,
        "detections": [
            {
                "category": d.category.value,
                "score": d.score,
                "confidence": d.confidence,
                "reason": d.reason
            }
            for d in detections
        ]
    }


# =============================================================================
# Routes
# =============================================================================

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/verify")
async def verify(req: VerifyRequest, request: Request):
    ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    user_agent = request.headers.get("User-Agent", "")
    ja3_hash = request.headers.get("X-JA3-Hash", "")

    # Collect headers for analysis
    headers = {k.lower(): v for k, v in request.headers.items()}

    result = run_verification(req.signals, ip, req.siteKey, user_agent, headers, ja3_hash, req.powSolution)
    return result


@app.post("/api/score")
async def score(req: ScoreRequest, request: Request):
    ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    user_agent = request.headers.get("User-Agent", "")
    ja3_hash = request.headers.get("X-JA3-Hash", "")
    headers = {k.lower(): v for k, v in request.headers.items()}

    result = run_verification(req.signals, ip, req.siteKey, user_agent, headers, ja3_hash, req.powSolution)
    return {
        "success": result["success"],
        "score": result["score"],
        "token": result["token"],
        "action": req.action,
        "recommendation": result["recommendation"]
    }


@app.post("/api/token/verify")
async def token_verify(req: TokenVerifyRequest):
    return verify_token(req.token)


@app.get("/api/pow/challenge")
async def pow_challenge(request: Request, siteKey: str = "default"):
    from detection import is_datacenter_ip

    ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    is_datacenter = is_datacenter_ip(ip)

    challenge = pow_store.generate(siteKey, ip, is_datacenter)
    return challenge


@app.get("/api/challenge")
async def challenge():
    """Legacy challenge endpoint for backward compatibility."""
    challenge_id = hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:32]
    return {
        "challengeId": challenge_id,
        "powDifficulty": 4,
        "expires": int(time.time()) + 300
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 3000))
    uvicorn.run(app, host="0.0.0.0", port=port)
