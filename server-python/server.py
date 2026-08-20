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
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from clientip import ProxyTrust
from sitekeys import SiteKeyGuard
from siteverify import (
    HostnameAllowlist,
    IdempotencyStore,
    request_hostname,
    sanitize_action,
    sanitize_cdata,
    secret_matches,
    siteverify,
)
from inputforensics import detect_input_forensics
from suspicion import (
    SuspicionLedger,
    compute_challenge_cost,
    BASE_MIN_AGE_MS,
)

# Keep in sync with server-node/package.json and client/fcaptcha.js on release.
app = FastAPI(title="FCaptcha", version="1.26.0")

# Which peers may speak for another client via X-Forwarded-For / X-Real-IP and
# the TLS-fingerprint headers. See clientip.py.
PROXY_TRUST = ProxyTrust.from_env()
print(f"Trusted proxies: {PROXY_TRUST.describe()}", flush=True)

# site_key is client-supplied and validated against no registry, yet it is the
# first component of every rate-limit, fingerprint and challenge partition key.
# See sitekeys.py.
SITE_KEYS = SiteKeyGuard.from_env()
print(f"Site keys: {SITE_KEYS.describe()}", flush=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("FCAPTCHA_SECRET", "dev-secret-change-in-production")

# The credential a backend presents to validate a token. Defaults to the signing
# key, which is what the README has always documented, but can be separated: the
# signing key is a long-lived secret that must never leave the server, while this
# one is handed to every backend that verifies. Splitting them means a leaked
# verify credential does not let the holder mint tokens.
VERIFY_SECRET = os.getenv("FCAPTCHA_VERIFY_SECRET") or SECRET_KEY

# Verdict logging is off by default: a self-hosted FCaptcha emits no per-request
# logs unless the operator opts in via FCAPTCHA_LOG_VERDICTS (1/true/yes/on).
# When on, each /api/verify and /api/score logs one privacy-safe JSON line
# (score, recommendation, category scores, and per-hit category/score/confidence)
# for observability and tuning. It deliberately omits IP, user agent, raw
# signals, and the free-text detection reason, which can interpolate
# visitor-derived data (reverse-DNS hostname, UA/header fragments, field ids).
#
# FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW additionally includes that free-text reason.
# Separate and off by default because reasons can carry visitor-derived data —
# only enable in trusted debugging contexts with no privacy obligations.
def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


VERDICT_LOGGING_ENABLED = _env_flag("FCAPTCHA_LOG_VERDICTS")
VERDICT_LOG_INCLUDE_RAW = _env_flag("FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW")

# Token verification used to accept anyone who could reach the endpoint: all
# three servers read `secret` out of the body and dropped it. Enforcing it is a
# breaking change for deployments that never sent one, so there is one release of
# escape hatch before the parameter becomes mandatory outright.
REQUIRE_VERIFY_SECRET = not _env_flag("FCAPTCHA_LEGACY_UNAUTH_VERIFY")

# Optional: restrict which page origins may mint tokens. Off by default so
# zero-config self-hosting keeps working. See siteverify.py.
ALLOWED_HOSTNAMES = HostnameAllowlist.from_env()

# Lets a caller retry a validation that timed out without burning the token.
IDEMPOTENCY = IdempotencyStore()
if VERDICT_LOGGING_ENABLED and VERDICT_LOG_INCLUDE_RAW:
    print(
        "WARNING: FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW enabled — verdict logs include "
        "free-text detection reasons that may contain visitor-derived data "
        "(hostnames, UA/header fragments, field ids). Do not enable where you have "
        "privacy obligations.",
        flush=True,
    )


def log_verdict(endpoint: str, site_key: str, result: Dict) -> None:
    """Emit one privacy-safe JSON line describing a scoring outcome (no-op unless enabled).

    Logs the detection category enum and numeric score/confidence. The free-text
    reason (which can carry visitor-derived data) is included only when
    FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW is set.
    """
    if not VERDICT_LOGGING_ENABLED or not result:
        return
    detections = []
    for d in result.get("detections", []):
        det = {"category": d.get("category"), "score": d.get("score"), "confidence": d.get("confidence")}
        if VERDICT_LOG_INCLUDE_RAW:
            det["reason"] = d.get("reason")
        detections.append(det)
    print(json.dumps({
        "event": "verdict",
        "endpoint": endpoint,
        "siteKey": site_key,
        "success": result.get("success"),
        "score": result.get("score"),
        "recommendation": result.get("recommendation"),
        "categoryScores": result.get("categoryScores"),
        "detections": detections,
    }), flush=True)

# Serve the browser widget alongside the API so deployments expose a single
# origin to integrators (the implicit contract behind <serverUrl>/fcaptcha.js).
# Set FCAPTCHA_SERVE_CLIENT=false to opt out — useful when hosting the widget
# on a separate CDN / edge cache. Set FCAPTCHA_CLIENT_PATH=/abs/path/fcaptcha.js
# to override the default lookup when server-python is deployed standalone.
CLIENT_PATH = os.getenv(
    "FCAPTCHA_CLIENT_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client", "fcaptcha.js"),
)

if os.getenv("FCAPTCHA_SERVE_CLIENT", "true").lower() != "false":
    # GET and HEAD both: Starlette registers only the listed methods, so a bare
    # HEAD answers 405. Caching proxies revalidate with HEAD and uptime monitors
    # commonly probe with it, so a 405 here reads as an outage on a working
    # server.
    @app.api_route("/fcaptcha.js", methods=["GET", "HEAD"])
    async def fcaptcha_js():
        # charset is not optional here. A classic script served without one is
        # decoded using the *document's* encoding, so the widget's translated
        # strings render as mojibake on any page that is not already UTF-8.
        return FileResponse(
            CLIENT_PATH, media_type="application/javascript; charset=utf-8"
        )


# =============================================================================
# Models
# =============================================================================

class PoWSolution(BaseModel):
    challengeId: str
    nonce: int
    hash: str
    signalsHash: Optional[str] = None

class PowTiming(BaseModel):
    duration: Optional[float] = None
    iterations: Optional[int] = None
    difficulty: Optional[int] = None

class VerifyRequest(BaseModel):
    siteKey: str
    signals: Dict[str, Any]
    signalsJson: Optional[str] = None
    action: str = ""
    cdata: str = ""
    powSolution: Optional[PoWSolution] = None
    powTiming: Optional[PowTiming] = None

class ScoreRequest(BaseModel):
    siteKey: str
    signals: Dict[str, Any]
    signalsJson: Optional[str] = None
    action: str = ""
    cdata: str = ""
    powSolution: Optional[PoWSolution] = None
    powTiming: Optional[PowTiming] = None

class TokenVerifyRequest(BaseModel):
    token: str
    # Declared but never checked until now: see the token_verify handler.
    secret: str = ""


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
    DECLARED_AI = "declared_ai"


@dataclass
class Detection:
    category: ThreatCategory
    score: float
    confidence: float
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

    # Marks a signal a browser cannot produce without being automated, as
    # opposed to one that merely correlates with automation. Triggers
    # DISPOSITIVE_FLOOR - see apply_dispositive_floor.
    dispositive: bool = False


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
        nonce = secrets.token_hex(16)
        now = int(time.time() * 1000)
        expires_at = now + (5 * 60 * 1000)  # 5 minutes

        # Cost scaling. See suspicion.py for why the escalation lands almost
        # entirely on min_age_ms rather than on difficulty.
        rate_key = f"pow:{site_key}:{ip}"
        exceeded, count = rate_limiter.check(rate_key, 60, 20)
        difficulty, min_age_ms = compute_challenge_cost(
            suspicion_ledger.count(site_key, ip), is_datacenter, count, exceeded
        )

        prefix = f"{challenge_id}:{now}:{difficulty}"

        challenge = {
            "id": challenge_id,
            "siteKey": site_key,
            "prefix": prefix,
            "difficulty": difficulty,
            "timestamp": now,
            "expiresAt": expires_at,
            "nonce": nonce,
            # How long the client must hold this challenge before submitting a
            # solution. Inside the signed payload so it cannot be talked down.
            "minAgeMs": min_age_ms,
            "ip": ip
        }

        # Sign the challenge
        sig_data = json.dumps({
            "id": challenge_id,
            "siteKey": site_key,
            "timestamp": now,
            "expiresAt": expires_at,
            "difficulty": difficulty,
            "prefix": prefix,
            "minAgeMs": min_age_ms
        }, sort_keys=True)
        sig = hmac.new(SECRET_KEY.encode(), sig_data.encode(), hashlib.sha256).hexdigest()
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
            "nonce": nonce,
            "sig": sig,
            # Tells the client how long to hold a solved challenge before
            # submitting. Honouring it is how an ordinary visitor pays an
            # elevated cost as a short wait instead of as a worse score.
            "minAgeMs": min_age_ms
        }

    def verify(self, solution: PoWSolution, site_key: str, signals_hash: str = None) -> Dict:
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

        # Verify the hash (with optional signalsHash binding)
        if signals_hash:
            input_str = f"{challenge['prefix']}:{signals_hash}:{solution.nonce}"
        else:
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

        # Calculate server-side elapsed time (un-spoofable)
        server_elapsed = now - challenge["timestamp"]

        # Delete challenge (one-time use)
        del self.challenges[solution.challengeId]

        return {
            "valid": True,
            "difficulty": challenge["difficulty"],
            "serverElapsed": server_elapsed,
            "nonce": challenge.get("nonce"),
            # Fall back for challenges issued before adaptive cost existed.
            "minAgeMs": challenge.get("minAgeMs") or BASE_MIN_AGE_MS,
        }

    def _cleanup(self):
        now = int(time.time() * 1000)
        expired = [cid for cid, c in self.challenges.items() if now > c["expiresAt"]]
        for cid in expired:
            del self.challenges[cid]

        # Clear used solutions if too many
        if len(self.used_solutions) > 10000:
            self.used_solutions.clear()


class TokenStore:
    """Prevents token replay attacks by tracking used tokens."""
    def __init__(self):
        self.used_tokens: Dict[str, float] = {}  # sig -> timestamp when used

    def is_used(self, sig: str) -> bool:
        return sig in self.used_tokens

    def mark_used(self, sig: str) -> bool:
        if sig in self.used_tokens:
            return False  # Already used
        self.used_tokens[sig] = time.time()

        # Cleanup old tokens periodically (tokens expire in 5 min anyway)
        if len(self.used_tokens) > 1000 and len(self.used_tokens) % 100 == 0:
            cutoff = time.time() - 600  # 10 minutes
            self.used_tokens = {s: t for s, t in self.used_tokens.items() if t > cutoff}

        return True


rate_limiter = RateLimiter()

# Recent strong verdicts per source, used to price the next challenge that
# source asks for. Bounded and short-lived; see suspicion.py.
suspicion_ledger = SuspicionLedger()
fingerprint_store = FingerprintStore()
pow_store = PoWChallengeStore()
token_store = TokenStore()

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
    ThreatCategory.AUTOMATION: 0.08,
    ThreatCategory.CDP: 0.12,
    ThreatCategory.BEHAVIORAL: 0.18,
    ThreatCategory.FINGERPRINT: 0.08,
    ThreatCategory.RATE_LIMIT: 0.01,
    ThreatCategory.BOT: 0.13,
    ThreatCategory.DECLARED_AI: 0.02,
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


def _has_human_presence(b: Dict[str, Any]) -> bool:
    """Whether the visitor independently demonstrated they were at the keyboard.

    A real pointer trajectory or a touch. Not a humanity verdict, just evidence
    that someone was there, which is enough to change how an otherwise ambiguous
    form fill reads.
    """
    return _num_or(b.get("totalPoints"), 0) >= 5 or _num_or(b.get("touchEvents"), 0) >= 1


def _num_or(value: Any, default: float) -> float:
    if isinstance(value, bool):
        return default
    return float(value) if isinstance(value, (int, float)) else default


def _has_human_movement_markers(b: Dict[str, Any]) -> bool:
    """Movement that carries independent evidence of a human hand.


    A slow pointer is the thing two of these checks look for, and it is also
    exactly what an elderly or motor-impaired visitor produces. The bench human
    panel caught both firing on them: "Mouse event rate abnormally low" on the
    elderly and motor-slow personas, "Mouse velocity too consistent" on motor-slow.

    Slowness alone cannot separate those users from an agent, but it does not have
    to. The same captures carry markers no low-effort automation produces:
    saturated micro-tremor, dozens of direction changes, corrective overshoots. On
    the bench corpus the split is total - every human persona clears this bar
    (tremor 1.00, 22-49 direction changes, 1-4 corrections) and every agent misses
    it (tremor 0.04-0.16, 0-1 direction changes, 0 corrections).

    So: do not read slowness as automation when the movement independently looks
    like a hand. An agent can of course fake all three, but faking three correlated
    properties of human motion is a materially harder job than running slowly,
    which is the point.
    """
    tremor = b.get("microTremorScore", 0.5)
    corrections = b.get("overshootCorrections", 0)
    changes = b.get("directionChanges", 0)
    return tremor >= 0.5 and (corrections >= 1 or changes >= 10)


def _is_touch_modality(b: Dict[str, Any]) -> bool:
    """Whether this visitor is using a touch or pen device, and so should be
    exempt from the mouse-trajectory detections.

    The old rule was `touch_events >= 3`, which a mobile user who simply taps the
    checkbox does not meet: the client records touchstart and touchmove, and a
    clean tap on a page short enough not to need scrolling produces exactly one
    event. The bench human panel captured precisely that - `touchEvents: 1` - and
    the visitor collected three agent detections for it, including
    "Zero mouse, touch, or keyboard events recorded" at confidence 0.9.

    One touch event is enough to establish modality. Corroborating it with the
    pointer type keeps a bare forged count from claiming the exemption on its
    own - though note this is a soft check either way, since every input here is
    client-supplied and an agent willing to claim `touchEvents: 1` was equally
    willing to claim 3.
    """
    touch_events = b.get("touchEvents", 0)
    touch_points = b.get("touchTotalPoints", 0)
    if touch_events >= 3:
        return True
    return (touch_events >= 1 or touch_points >= 1) and b.get("pointerHasNonMouseType") is True


def detect_vision_ai(signals: Dict) -> List[Detection]:
    detections = []
    b = signals.get("behavioral", {})
    t = signals.get("temporal", {})

    # Zero/minimal mouse movement - strong indicator of AI agent or programmatic click
    # Exempt: touch users (mobile) and keyboard-only users (accessibility)
    total_points = b.get("totalPoints", 0)
    trajectory = b.get("trajectoryLength", 0)
    approach_pts = b.get("approachPoints", 0)
    touch_events = b.get("touchEvents", 0)
    key_events = b.get("keyEvents", 0)
    is_touch_user = _is_touch_modality(b)
    is_keyboard_user = key_events >= 2 and total_points == 0

    if total_points < 5 and trajectory < 10 and not is_touch_user and not is_keyboard_user:
        detections.append(Detection(
            ThreatCategory.VISION_AI, 0.9, 0.85,
            "No mouse movement detected before click (AI agent pattern)",
            {"totalPoints": total_points, "trajectoryLength": trajectory}
        ))

    if approach_pts == 0 and not is_touch_user and not is_keyboard_user:
        detections.append(Detection(
            ThreatCategory.VISION_AI, 0.7, 0.8,
            "No approach trajectory to target"
        ))

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
    # Micro-tremor. Like the approach-directness check below, this fires on a
    # measurement that does not exist for someone who never moved a mouse - the
    # client itself reports 0.5 as its "no mouse data" sentinel. Require real
    # mouse movement before judging its texture, and apply the same exemptions
    # as the surrounding checks.
    micro_tremor = b.get("microTremorScore", 0.5)
    has_mouse_movement = total_points >= 5
    if has_mouse_movement and not is_touch_user and not is_keyboard_user and micro_tremor < 0.15:
        detections.append(Detection(
            ThreatCategory.VISION_AI, 0.7, 0.6,
            "Mouse movement lacks natural micro-tremor",
            {"microTremorScore": micro_tremor}
        ))

    # Approach directness.
    #
    # The client reports directness 1 (perfectly straight) when there is no
    # approach path to measure at all, so this check used to fire on every
    # keyboard-only, screen-reader and touch user - the populations the
    # surrounding checks go out of their way to exempt. Found by the bench
    # human panel: keyboard-only, screen-reader and touch all reported
    # approachPoints 0 with approachDirectness 1.
    #
    # Require an actual path before judging its shape, and apply the same
    # exemptions as its neighbours.
    approach = b.get("approachDirectness", 0.5)
    has_approach_path = approach_pts >= 5
    if has_approach_path and not is_touch_user and not is_keyboard_user and approach > 0.95:
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

    # Input-event forensics: teleport clicks and agent think-time cadence.
    fcs = b.get("inputForensics")
    if fcs:
        teleports = fcs.get("teleportClicks", 0)
        if teleports >= 1 and not is_touch_user:
            detections.append(Detection(
                ThreatCategory.VISION_AI, 0.7, 0.7,
                f"Click injected with no pointer trajectory ({int(teleports)} teleport clicks)"
            ))
        # Bursts of activity separated by multi-second perfect silence — the agent
        # act -> screenshot -> inference loop. Low confidence (slow humans idle too);
        # requires silence to dominate. Keyboard-only users are exempt.
        if (not is_keyboard_user
                and fcs.get("cadenceEvents", 0) >= 12
                and fcs.get("cadenceSilentGaps", 0) >= 3
                and fcs.get("cadenceGapCV", 0) > 2.5
                and fcs.get("cadenceSilentRatio", 0) > 0.6):
            detections.append(Detection(
                ThreatCategory.VISION_AI, 0.6, 0.5,
                "Interaction cadence matches agent act/think loop (bursts + dead air)"
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
            "WebDriver detected (navigator.webdriver = true)",
            dispositive=True,  # navigator.webdriver === true - see apply_dispositive_floor
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

    # Playwright-specific detection
    playwright = env.get("playwright", {})
    if playwright.get("detected"):
        score_map = {
            "playwright_globals": 0.95,
            "webdriver_deleted": 0.8,
            "webdriver_configurable": 0.7,
            "chrome_runtime_missing": 0.6,
        }
        # Signals a genuine browser also produces, and therefore not evidence of
        # anything. Ignored here as well as in the client, because clients already
        # deployed will keep sending them.
        #
        # Measured in Chrome 150 with navigator.webdriver === False:
        #   webdriver_configurable  descriptor present and configurable - WebIDL
        #                           defines the attribute that way
        #   chrome_runtime_missing  window.chrome present, chrome.runtime absent,
        #                           on any page without a matching
        #                           externally_connectable extension
        #
        # They fired together on ordinary Chrome, so they cannot corroborate each
        # other either.
        inert_signals = {"webdriver_configurable", "chrome_runtime_missing"}

        for sig in playwright.get("signals", []):
            if sig in inert_signals:
                continue
            sig_score = score_map.get(sig, 0.7)
            detections.append(Detection(
                ThreatCategory.HEADLESS, sig_score, 0.8,
                f"Playwright artifact detected: {sig}"
            ))


    return detections


def detect_stealth_artifacts(signals: Dict) -> List[Detection]:
    """Flag anti-detection patch traces collected by the client.

    FALSE-POSITIVE-SAFE: a genuine browser never produces these — they are
    internal contradictions / native-function tampering, not environment-shape
    heuristics (which would misfire on real Linux/VPN users). Targets stealth
    agents (e.g. Manus AI) driving real-but-patched Chromium. Only the two
    FP-safe signals are scored; the client also collects privacy-extension-
    ambiguous artifacts (patched_*) for observability that are intentionally NOT
    scored. Keep in sync with server-go and server-node.
    """
    detections = []
    env = signals.get("environmental", {})

    # Function.prototype.toString proxied — the signature move of stealth
    # frameworks (used to make their other native overrides look untouched).
    artifact_signals = (env.get("stealthArtifacts") or {}).get("signals", []) or []
    if "tostring_proxied" in artifact_signals:
        detections.append(Detection(
            ThreatCategory.HEADLESS, 0.9, 0.85,
            "Function.prototype.toString is proxied (stealth automation patch)"
        ))

    # Notification.permission == "denied" while the Permissions API reports
    # "prompt": a state a real browser cannot reach (classic headless tell).
    if (env.get("permissionProbe") or {}).get("contradiction") is True:
        detections.append(Detection(
            ThreatCategory.HEADLESS, 0.85, 0.85,
            "Notification permission contradicts Permissions API (headless/stealth tell)"
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

    # Input-event forensics: catch CDP-injected input that reports isTrusted=true
    # and so evades the global-based checks below. Touch users are exempt.
    b = signals.get("behavioral", {})
    is_touch_user = b.get("touchEvents", 0) >= 3
    fcs = b.get("inputForensics")
    if fcs and not is_touch_user:
        # Real mice coalesce several hardware samples per frame; a stream of
        # pointermoves that NEVER coalesced is synthetic injection.
        if fcs.get("coalescedSamples", 0) >= 20 and fcs.get("coalescedMax", 0) <= 1:
            detections.append(Detection(
                ThreatCategory.CDP, 0.8, 0.6,
                "Pointer moves never coalesced across many samples (synthetic/CDP input)"
            ))
        # movementX/Y incoherent with actual position deltas across most moves.
        if fcs.get("pointerMoveSamples", 0) >= 20 and fcs.get("pointerMoveZeroRatio", 0) > 0.9:
            detections.append(Detection(
                ThreatCategory.CDP, 0.6, 0.5,
                "Pointer movement deltas incoherent with position (synthetic input)"
            ))

    # CDP Runtime/DevTools console consumer attached. Low confidence: a developer
    # with DevTools open also trips this, so it contributes rather than blocks.
    if env.get("cdpRuntime", {}).get("consoleAttached"):
        detections.append(Detection(
            ThreatCategory.CDP, 0.6, 0.5,
            "CDP/DevTools console consumer attached (automation protocol or open DevTools)"
        ))

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
            f"CDP automation detected: {signals_joined}",
            dispositive=True,  # driver-injected globals - see apply_dispositive_floor
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

    # Insufficient mouse data - critical check for zero-click bots
    # Exempt: touch users (mobile) and keyboard-only users (accessibility)
    total_points = b.get("totalPoints", 0)
    trajectory = b.get("trajectoryLength", 0)
    touch_events = b.get("touchEvents", 0)
    key_events = b.get("keyEvents", 0)
    is_touch_user = _is_touch_modality(b)
    is_keyboard_user = key_events >= 2 and total_points == 0

    if total_points == 0 and not is_touch_user and not is_keyboard_user:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.8, 0.9,
            "Zero mouse, touch, or keyboard events recorded"
        ))
    elif total_points < 10 and not is_touch_user and not is_keyboard_user and trajectory < 30:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.6, 0.7,
            "Insufficient mouse movement before interaction",
            {"totalPoints": total_points, "trajectoryLength": trajectory}
        ))

    # Velocity variance
    vel_var = b.get("velocityVariance", 1)
    if vel_var < 0.02 and trajectory > 50 and not _has_human_movement_markers(b):
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
    elif 0 < event_rate < 10 and not _has_human_movement_markers(b):
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


# =============================================================================
# Mobile-native detectors (touch authenticity, sensor entropy, touch kinematics)
# UA-gated on mobile. Non-mobile UAs: no-op. Designed never to penalize iOS
# Safari without DeviceMotion permission (absence treated as neutral).
# =============================================================================

_MOBILE_UA_PATTERN = re.compile(r"mobile|android|iphone|ipad|ipod", re.IGNORECASE)


def _is_mobile_ua(user_agent: str) -> bool:
    return bool(_MOBILE_UA_PATTERN.search(user_agent or ""))


def detect_touch_authenticity(signals: Dict, user_agent: str) -> List[Detection]:
    detections: List[Detection] = []
    if not _is_mobile_ua(user_agent):
        return detections

    b = signals.get("behavioral", {}) or {}
    touch_points = b.get("touchTotalPoints") or b.get("touchEvents") or 0
    if touch_points < 3:
        return detections

    force_variance = b.get("touchForceVariance", 0) or 0
    radius_variance = b.get("touchRadiusVariance", 0) or 0
    force_all_one = b.get("touchForceAllOne") is True
    unique_ids = b.get("touchUniqueIdentifiers", 0) or 0
    force_max = b.get("touchForceMax", 0) or 0
    radius_max = b.get("touchRadiusMax", 0) or 0

    # Uniform non-zero force across all events → synthetic injection.
    # Older Android returning all-zero is legitimate — only penalize uniformity
    # when max > 0.
    if force_variance == 0 and force_max > 0 and touch_points >= 5:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.75, 0.85,
            "Touch force is identical across all events (synthetic touch)"
        ))

    if force_all_one and touch_points >= 5:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.8, 0.9,
            "All touches report force=1.0 exactly (synthetic pattern)"
        ))

    if radius_variance == 0 and radius_max > 0 and touch_points >= 5:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.7, 0.8,
            "Touch contact radius identical across all events"
        ))

    if touch_points >= 5 and unique_ids == 0:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.6, 0.7,
            "Mobile touches lack identifier tracking (synthetic injection)"
        ))

    return detections


def detect_sensor_entropy(signals: Dict, user_agent: str) -> List[Detection]:
    detections: List[Detection] = []
    if not _is_mobile_ua(user_agent):
        return detections

    env = signals.get("environmental", {}) or {}
    sensor = env.get("sensor", {}) or {}
    motion_count = sensor.get("motionEventCount", 0) or 0
    motion_variance = sensor.get("motionAccelVariance", 0) or 0
    orientation_count = sensor.get("orientationEventCount", 0) or 0
    orientation_variance = sensor.get("orientationVariance", 0) or 0

    if motion_count >= 10 and motion_variance < 0.01:
        detections.append(Detection(
            ThreatCategory.HEADLESS, 0.7, 0.8,
            f"Motion sensor active but flat (variance={motion_variance:.4f}) — likely emulator"
        ))

    if orientation_count >= 10 and orientation_variance < 0.01:
        detections.append(Detection(
            ThreatCategory.HEADLESS, 0.6, 0.7,
            "Orientation sensor active but completely flat — likely emulator"
        ))

    # motion_count == 0 is NEUTRAL (iOS without permission is common).
    return detections


def detect_touch_kinematics(signals: Dict) -> List[Detection]:
    detections: List[Detection] = []
    b = signals.get("behavioral", {}) or {}
    touch_points = b.get("touchTotalPoints", 0) or 0
    if touch_points < 10:
        return detections

    straight_line = b.get("touchStraightLineRatio", 0) or 0
    tremor = b.get("touchMicroTremorScore", 0) or 0
    dir_changes = b.get("touchDirectionChanges", 0) or 0

    if straight_line > 0.85 and touch_points >= 20:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.65, 0.75,
            f"Touch path too straight (ratio={straight_line:.2f}) — automation pattern"
        ))

    if tremor < 0.05 and touch_points >= 30:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.55, 0.65,
            "Touch path has no micro-tremor (unnaturally smooth)"
        ))

    if dir_changes == 0 and touch_points >= 30:
        detections.append(Detection(
            ThreatCategory.BEHAVIORAL, 0.5, 0.6,
            "Touch path has zero direction changes over long trajectory"
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
    """Combine the detections within each category into a category score.

    Why this is not a mean
    ----------------------
    It used to be a confidence-weighted mean, which had a property nobody
    intended: corroborating evidence *lowered* the verdict. A visitor whose
    browser reported navigator.webdriver = true and nothing else scored 0.95 in
    the headless category. The same visitor, additionally caught with no
    plugins, a software renderer, a viewport equal to its window and three more
    automation tells, scored 0.686 - because each additional signal, being
    individually weaker than the first, pulled the average down. Seven pieces of
    corroboration made the case weaker than one.

    Noisy-OR fixes that. Each detection is independent evidence of strength
    score x confidence, and the category is the probability at least one is
    right::

        category = 1 - PRODUCT(1 - score_i * confidence_i)

    Evidence now accumulates: adding a signal can only raise a category, never
    lower it. And it is *more* forgiving of isolated weak evidence than the mean
    was - one detection at score 0.4, confidence 0.5 contributes 0.20 rather
    than setting the whole category to 0.40 - which is the right treatment for a
    lone low-confidence hit on a real user.

    Measured on the bench corpus (bench/tools/compare-aggregation.js): human
    median 0.182 -> 0.097 and human max 0.260 -> 0.171, while agent median rose
    0.517 -> 0.570. Both populations moved in the direction they should.
    """
    # Probability that every detection in a category is wrong; the category
    # score is one minus that.
    survives: Dict[ThreatCategory, float] = {}

    for d in detections:
        strength = max(0.0, min(1.0, d.score * d.confidence))
        survives[d.category] = survives.get(d.category, 1.0) * (1 - strength)

    result = {}
    for cat, s_val in survives.items():
        result[cat.value] = min(1.0, 1 - s_val)

    # Fill missing
    for cat in ThreatCategory:
        if cat.value not in result:
            result[cat.value] = 0.0

    return result


# Score below which a self-declared automated browser cannot fall.
#
# Why a floor exists at all
# -------------------------
# The final score is a weighted sum across all eleven categories, so a category
# can contribute at most its own weight no matter how certain it is. A local
# automated browser trips at most the six categories reachable without a
# datacenter IP, a reused fingerprint or a rate-limit hit - about 0.81 of the
# weight - and in practice lands near 0.5. The bench measured exactly that: a
# Playwright browser reporting navigator.webdriver = true, no plugins, a
# software renderer and four more automation tells scored 0.549, i.e.
# "challenge", not "block".
#
# That is the weighted sum working as designed. It expresses "what fraction of
# the total suspicion budget did this visitor consume", and no single fact can
# consume most of that budget. The trouble is that some facts are not
# probabilistic evidence at all - they are the browser saying so.
#
# What qualifies
# --------------
# Only detections marked dispositive, and the bar for that mark is that a
# browser cannot produce the signal without being automated:
#
#   - navigator.webdriver = true - a W3C-specified flag whose sole purpose is to
#     tell the page it is under automation.
#   - ChromeDriver / Puppeteer injected globals (chromedriver_cdc,
#     puppeteer_eval, cdp_script_injection), which exist in no ordinary browsing
#     session.
#
# Deliberately excluded, though both look tempting: the "console consumer
# attached" CDP check, because the bench human panel proves it fires on a
# developer with DevTools open; and the Playwright webdriver_configurable
# artifact, which relies on a property-descriptor detail no specification
# guarantees.
#
# What this does not do
# ---------------------
# It does not catch a stealth agent, which patches navigator.webdriver before
# the page ever sees it. That is not a regression - such an agent scores the
# same as it did before - and it is the reason the behavioural workstreams still
# matter. The floor closes the case where an agent is not even trying to hide,
# which was previously being waved through with a "challenge".
DISPOSITIVE_FLOOR = 0.9


def apply_dispositive_floor(score: float, detections: List[Detection]) -> float:
    if any(d.dispositive for d in detections):
        return max(score, DISPOSITIVE_FLOOR)
    return score


def calculate_final_score(category_scores: Dict[str, float]) -> float:
    total = 0.0
    for cat, weight in WEIGHTS.items():
        total += category_scores.get(cat.value, 0.0) * weight
    return min(1.0, total)


def _canonical_payload(data: Dict) -> str:
    """The exact bytes a token signature covers.

    Sorted keys and no whitespace, byte-identical to Node's
    ``JSON.stringify(data, Object.keys(data).sort())`` and Go's
    ``json.Marshal`` of a map. The three servers sign the same claims, so they
    must serialise them the same way or a token minted by one is rejected by the
    others.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _decode_token_base64(token: str) -> bytes:
    """Decode a token in either padding convention.

    Python emitted padded base64url historically and emits unpadded now, so both
    are in circulation during a rolling deploy and for one token lifetime after
    it. Re-adding the padding costs nothing and removes the only reason a valid
    token would be rejected across a version boundary.
    """
    stripped = token.rstrip("=")
    padding = "=" * (-len(stripped) % 4)
    return base64.urlsafe_b64decode(stripped + padding)


def generate_token(
    ip: str,
    site_key: str,
    score: float,
    binding: Optional[Dict[str, str]] = None,
) -> str:
    """Mint a signed token bound to the source, the site, the score, and - via
    ``binding`` - the page that minted it and the action it was minted for.

    The binding is what lets a backend reject a token that is valid but was not
    issued for what it is being spent on: an ``action=login`` token replayed
    against a password-reset endpoint, or a token minted on a site that lifted
    the key.

    Empty strings rather than omitted keys: the signing payload is a sorted-key
    JSON serialisation, so a token whose key set varied with what the browser
    happened to send would be a second payload shape to keep in sync across three
    languages. Fixed shape, empty when unknown.
    """
    binding = binding or {}
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:8]
    data = {
        "site_key": site_key,
        "timestamp": int(time.time()),
        "score": round(score, 3),
        "ip_hash": ip_hash,
        "hostname": binding.get("hostname", ""),
        "action": binding.get("action", ""),
        "cdata": binding.get("cdata", "")
    }
    payload = _canonical_payload(data)
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    data["sig"] = sig
    # Unpadded base64url, matching server-node and server-go.
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def verify_token(token: str, ip: str = None) -> Dict:
    try:
        decoded = json.loads(_decode_token_base64(token).decode())

        # Check expiration
        if time.time() - decoded.get("timestamp", 0) > 300:
            return {"valid": False, "reason": "expired"}

        sig = decoded.pop("sig", "")
        ip_hash = decoded.get("ip_hash", "")

        # Accept both the compact payload and the legacy spaced one. Python used
        # json.dumps' default separators, which put a space after every ':' and
        # ',' and made its signatures disagree with Node's and Go's over
        # identical claims. Tokens minted before the fix are still in flight for
        # one token lifetime after a deploy, so both are honoured here.
        if not any(
            hmac.compare_digest(
                sig,
                hmac.new(SECRET_KEY.encode(), candidate.encode(), hashlib.sha256).hexdigest(),
            )
            for candidate in (
                _canonical_payload(decoded),
                json.dumps(decoded, sort_keys=True),
            )
        ):
            return {"valid": False, "reason": "invalid_signature"}

        # Check for token replay (single-use tokens)
        if token_store.is_used(sig):
            return {"valid": False, "reason": "token_already_used"}

        # Verify IP matches (if provided)
        if ip:
            expected_ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:8]
            if ip_hash != expected_ip_hash:
                return {"valid": False, "reason": "ip_mismatch"}

        # Mark token as used (prevents replay)
        token_store.mark_used(sig)

        # hostname/action/cdata default to "" so a token minted before they
        # existed still verifies and reports the same shape. The signature covers
        # whatever keys the token actually carries, so old four-key tokens
        # validate unchanged - this is additive, not a format break.
        return {
            "valid": True,
            "site_key": decoded.get("site_key"),
            "timestamp": decoded.get("timestamp"),
            "score": decoded.get("score"),
            "ip_hash": ip_hash,
            "hostname": decoded.get("hostname", ""),
            "action": decoded.get("action", ""),
            "cdata": decoded.get("cdata", "")
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
    pow_solution: PoWSolution = None,
    signals_json: str = None,
    pow_timing: PowTiming = None,
    peer_trusted: bool = False,
    action: str = "",
    cdata: str = ""
) -> Dict:
    from detection import (
        check_ip_reputation, analyze_headers,
        check_browser_consistency, check_ja3_fingerprint,
        check_ja4_fingerprint, get_trusted_ja4_header_names, read_ja4_from_headers,
        analyze_form_interaction, check_declared_ai_agent
    )

    detections = []

    # Verify signal commitment (signalsJson hash must match powSolution.signalsHash)
    client_signals_hash = pow_solution.signalsHash if pow_solution else None
    if signals_json and client_signals_hash:
        computed_hash = hashlib.sha256(signals_json.encode()).hexdigest()
        if computed_hash != client_signals_hash:
            detections.append(Detection(
                ThreatCategory.BOT, 0.95, 0.95,
                "Signals tampered after PoW (signalsHash mismatch)"
            ))
        # Use signalsJson as the canonical signals source
        try:
            signals = json.loads(signals_json)
        except json.JSONDecodeError:
            pass  # Fall back to parsed signals

    # Inject powTiming into signals.temporal.pow for detection functions
    if pow_timing:
        if "temporal" not in signals:
            signals["temporal"] = {}
        signals["temporal"]["pow"] = {
            "duration": pow_timing.duration,
            "iterations": pow_timing.iterations,
            "difficulty": pow_timing.difficulty
        }

    # Verify PoW if provided.
    #
    # pow_satisfied records whether the caller actually completed the challenge
    # this server issued. It gates token issuance below rather than only feeding
    # the score, because a proof of work is a precondition, not evidence: the
    # widget solves one on every path and aborts rather than submit without it,
    # so a request that arrives without a valid solution did not come from the
    # widget at all.
    #
    # Scoring it alone was not enough. The final score is a weighted sum, so the
    # bot category contributes at most its 0.13 weight - every PoW failure firing
    # at once reached 0.1298 against a 0.5 threshold, and a bare `curl` with no
    # solution and no signals was issued a valid token. The detections were all
    # correct; the aggregation discarded them.
    pow_satisfied = False
    if pow_solution:
        pow_result = pow_store.verify(pow_solution, site_key, client_signals_hash)
        if not pow_result["valid"]:
            detections.append(Detection(
                ThreatCategory.BOT, 0.7, 0.8,
                f"PoW verification failed: {pow_result['reason']}",
                # A solution that does not verify against a challenge this
                # server issued is not weak evidence of automation, it is proof
                # the challenge was not completed. See apply_dispositive_floor.
                dispositive=True
            ))
        else:
            pow_satisfied = True

        # Verify challenge nonce binding
        if pow_result["valid"] and pow_result.get("nonce"):
            client_nonce = signals.get("meta", {}).get("challengeNonce")
            if not client_nonce or client_nonce != pow_result["nonce"]:
                # The solution verifies but the signals it commits to are not
                # the ones presented, so the work was done for a different
                # payload. Revokes the pass granted above.
                pow_satisfied = False
                detections.append(Detection(
                    ThreatCategory.BOT, 0.9, 0.9,
                    "Challenge nonce mismatch (signals not bound to challenge)",
                    dispositive=True
                ))

        # Server-side timing, the one cost an attacker cannot buy their way out
        # of. Two thresholds, because they mean different things.
        if pow_result["valid"]:
            elapsed = pow_result.get("serverElapsed", 99999)
            min_age = pow_result.get("minAgeMs") or BASE_MIN_AGE_MS
            if elapsed < BASE_MIN_AGE_MS:
                # Under the universal baseline nothing legitimate can have
                # happened - no human completes an interaction that fast.
                detections.append(Detection(
                    ThreatCategory.BOT, 0.8, 0.85,
                    f"Challenge solved too fast ({elapsed}ms server-side)"
                ))
            elif elapsed < min_age:
                # Between the baseline and this source's own elevated floor is
                # weaker evidence: a client predating adaptive cost, or one
                # served from a stale cache, does not know to wait. It
                # contributes rather than deciding.
                detections.append(Detection(
                    ThreatCategory.BOT, 0.5, 0.5,
                    f"Challenge submitted before the required delay for this "
                    f"source ({elapsed}ms of {min_age}ms)"
                ))
    else:
        # No PoW solution provided - hard fail
        detections.append(Detection(
            ThreatCategory.BOT, 0.9, 0.95,
            "No PoW solution provided",
            dispositive=True
        ))

    # Behavioral detectors
    detections.extend(detect_vision_ai(signals))
    detections.extend(detect_headless(signals, user_agent))
    detections.extend(detect_stealth_artifacts(signals))
    detections.extend(detect_automation(signals))
    detections.extend(detect_cdp(signals))
    detections.extend(detect_behavioral(signals))
    detections.extend(detect_touch_authenticity(signals, user_agent))
    detections.extend(detect_sensor_entropy(signals, user_agent))
    detections.extend(detect_touch_kinematics(signals))
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

    # Flag declared/verified AI agents (self-identifying UA or Web Bot Auth signature)
    for d in check_declared_ai_agent(user_agent, headers):
        detections.append(Detection(
            ThreatCategory.DECLARED_AI, d["score"], d["confidence"], d["reason"]
        ))

    # Input forensics v2 (PRD workstream C): typing cadence and modality, the
    # paste-shortcut/platform contradiction, scroll morphology, font coherence.
    for d in detect_input_forensics(signals):
        detections.append(Detection(
            ThreatCategory(d["category"]), d["score"], d["confidence"], d["reason"]
        ))

    # HTTP-level detectors
    if headers:
        for d in analyze_headers(headers, peer_trusted):
            detections.append(Detection(
                ThreatCategory.BOT, d["score"], d["confidence"], d["reason"]
            ))

    # TLS fingerprint (JA3) — client-supplied, spoofable
    if ja3_hash:
        for d in check_ja3_fingerprint(ja3_hash):
            detections.append(Detection(
                ThreatCategory.BOT, d["score"], d["confidence"], d["reason"]
            ))

    # TLS fingerprint (JA4) — trusted reverse-proxy header, un-spoofable by client
    trusted_ja4_headers = get_trusted_ja4_header_names()
    if headers and trusted_ja4_headers:
        ja4 = read_ja4_from_headers(headers, trusted_ja4_headers)
        if ja4:
            for d in check_ja4_fingerprint(ja4):
                cat = d["category"]
                if cat in [e.value for e in ThreatCategory]:
                    category = ThreatCategory(cat)
                else:
                    category = ThreatCategory.FINGERPRINT
                detections.append(Detection(
                    category, d["score"], d["confidence"], d["reason"]
                ))

    # Form interaction analysis (credential stuffing & spam detection)
    form_analysis = signals.get("formAnalysis")
    if form_analysis:
        for d in analyze_form_interaction(form_analysis, _has_human_presence(signals.get('behavioral') or {})):
            detections.append(Detection(
                ThreatCategory.BOT, d["score"], d["confidence"], d["reason"]
            ))

    category_scores = calculate_category_scores(detections)
    final_score = apply_dispositive_floor(calculate_final_score(category_scores), detections)

    if final_score < 0.3:
        recommendation = "allow"
    elif final_score < 0.6:
        recommendation = "challenge"
    else:
        recommendation = "block"

    # The hostname comes from the request headers rather than the request body:
    # it is what the browser reported about the page, not what the page claimed
    # about itself.
    hostname = request_hostname(headers)

    # An unlisted hostname withholds the token but does not touch the score. The
    # visitor is not the problem - a key registered to another site is - so the
    # detection layer has nothing to say about it and the refusal is reported as
    # its own reason rather than smuggled in as a bot verdict.
    hostname_allowed = ALLOWED_HOSTNAMES.permits(hostname)

    # Three independent conditions, deliberately not folded into the score.
    #
    # pow_satisfied is the one that matters most: a score threshold answers "how
    # suspicious is this visitor", which is the wrong question to ask of someone
    # who never completed the challenge. Gating here means no future reweighting
    # can reopen the bypass, and it holds even if the dispositive floor is
    # lowered or removed.
    success = final_score < 0.5 and hostname_allowed and pow_satisfied

    # Name the failed precondition whenever one fails, not only when the score
    # would otherwise have allowed. Gating it on the score made the PoW case
    # unreachable - a PoW failure is dispositive, so it floors the score at 0.9
    # and the branch never fired - which is exactly the case a caller most needs
    # explained.
    withheld_reason = ""
    if not pow_satisfied:
        withheld_reason = "pow_not_satisfied"
    elif not hostname_allowed:
        withheld_reason = "hostname_not_allowed"

    token = generate_token(ip, site_key, final_score, {
        "hostname": hostname,
        "action": sanitize_action(action),
        "cdata": sanitize_cdata(cdata),
    }) if success else None

    # Feed the ledger so the next challenge this source asks for is priced on
    # what it just did.
    suspicion_ledger.record(site_key, ip, final_score)

    return {
        "success": success,
        "score": final_score,
        "token": token,
        "timestamp": int(time.time()),
        "recommendation": recommendation,
        **({"reason": withheld_reason} if withheld_reason else {}),
        **({} if hostname_allowed else {"hostname": hostname}),
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

@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return {"status": "ok"}


def collect_headers(request: Request) -> Dict[str, str]:
    """Lowercase the request headers for the detectors, dropping the
    TLS-fingerprint headers when the peer is not a proxy we trust.

    TRUSTED_JA4_HEADERS is an allowlist of header *names*, which says nothing
    about who set them - without this gate a client could send cf-ja4 itself and
    present a clean fingerprint.
    """
    from detection import get_trusted_ja4_header_names

    peer_trusted = PROXY_TRUST.peer_trusted(request)
    ja4_headers = () if peer_trusted else tuple(get_trusted_ja4_header_names())
    return {
        k.lower(): v
        for k, v in request.headers.items()
        if k.lower() not in ja4_headers
    }


@app.post("/api/verify")
async def verify(req: VerifyRequest, request: Request):
    ip = PROXY_TRUST.client_ip(request)
    # Bound the state an unvalidated site_key can allocate (sitekeys.py).
    req.siteKey = SITE_KEYS.normalize(req.siteKey, ip)
    user_agent = request.headers.get("User-Agent", "")
    ja3_hash = PROXY_TRUST.trusted_header(request, "X-JA3-Hash")

    # Collect headers for analysis
    headers = collect_headers(request)

    result = run_verification(req.signals, ip, req.siteKey, user_agent, headers, ja3_hash, req.powSolution, req.signalsJson, req.powTiming, PROXY_TRUST.peer_trusted(request), req.action, req.cdata)
    log_verdict("verify", req.siteKey, result)
    return result


@app.post("/api/score")
async def score(req: ScoreRequest, request: Request):
    ip = PROXY_TRUST.client_ip(request)
    # Bound the state an unvalidated site_key can allocate (sitekeys.py).
    req.siteKey = SITE_KEYS.normalize(req.siteKey, ip)
    user_agent = request.headers.get("User-Agent", "")
    ja3_hash = PROXY_TRUST.trusted_header(request, "X-JA3-Hash")
    headers = collect_headers(request)

    result = run_verification(req.signals, ip, req.siteKey, user_agent, headers, ja3_hash, req.powSolution, req.signalsJson, req.powTiming, PROXY_TRUST.peer_trusted(request), req.action, req.cdata)
    log_verdict("score", req.siteKey, result)
    return {
        "success": result["success"],
        "score": result["score"],
        "token": result["token"],
        # Echo the sanitized form, not the raw input: this is what got signed
        # into the token, so a caller comparing the two sees the same value.
        "action": sanitize_action(req.action),
        "cdata": sanitize_cdata(req.cdata),
        "recommendation": result["recommendation"],
        # Parity with /api/verify and with the Go server: a caller denied a
        # token needs to know which precondition failed.
        **({"reason": result["reason"]} if result.get("reason") else {}),
    }


@app.post("/api/token/verify")
async def token_verify(req: TokenVerifyRequest, request: Request):
    # The secret gate. This endpoint is the boundary between "a browser finished
    # a challenge" and "my backend believes it", so it is server-to-server and
    # needs a credential - without one, anyone who can reach the host can spend a
    # token they observed, and the single-use guard then denies the real user.
    if REQUIRE_VERIFY_SECRET:
        if not req.secret:
            return JSONResponse(
                status_code=401, content={"valid": False, "reason": "missing_secret"}
            )
        if not secret_matches(req.secret, VERIFY_SECRET):
            return JSONResponse(
                status_code=401, content={"valid": False, "reason": "invalid_secret"}
            )

    # Extract client IP for verification
    ip = PROXY_TRUST.client_ip(request)
    return verify_token(req.token, ip)


# Turnstile / reCAPTCHA / hCaptcha drop-in compatibility.
#
# Same contract, three paths, because the path is hardcoded in the SDKs and
# plugins we want to be usable against FCaptcha: pointing an existing integration
# at this server should be a base-URL change and nothing else. See siteverify.py
# for the adapter itself.
async def _read_siteverify_body(request: Request) -> Any:
    """Decode either encoding the contract allows.

    Callers in the wild are split: PHP and Python examples overwhelmingly post
    form-encoded, Node and Go examples post JSON.
    """
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type == "application/json":
        try:
            return await request.json()
        except Exception:
            return None
    form = await request.form()
    return dict(form)


async def _siteverify_route(request: Request):
    body = await _read_siteverify_body(request)
    return siteverify(
        body=body,
        # Bind to this server's token store, so replay state is shared with the
        # native endpoint rather than kept in a parallel universe.
        verify_token=verify_token,
        expected_secret=VERIFY_SECRET,
        idempotency_store=IDEMPOTENCY,
        require_secret=REQUIRE_VERIFY_SECRET,
    )


app.post("/turnstile/v0/siteverify")(_siteverify_route)
app.post("/recaptcha/api/siteverify")(_siteverify_route)
app.post("/siteverify")(_siteverify_route)


@app.get("/api/pow/challenge")
async def pow_challenge(request: Request, siteKey: str = "default"):
    from detection import is_datacenter_ip

    ip = PROXY_TRUST.client_ip(request)
    siteKey = SITE_KEYS.normalize(siteKey, ip)
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

    # proxy_headers=False is required, not a preference.
    #
    # uvicorn enables its own X-Forwarded-For handling by default: when the real
    # peer is in forwarded_allow_ips (default 127.0.0.1), it rewrites
    # request.client from the header. FCaptcha then sees the *claimed* address
    # where it expects the socket peer, so ProxyTrust ends up evaluating the
    # visitor's IP against the trusted-proxy list instead of the proxy's - which
    # is the resolution ProxyTrust exists to do, done again, on different rules,
    # underneath it.
    #
    # Concretely, with a reverse proxy on the same host (the normal shape), every
    # request logged "ignoring forwarding headers from untrusted peer <visitor
    # IP>" and scored a spurious suspicious-header detection, because the peer
    # FCaptcha inspected was never the proxy.
    #
    # This mirrors the same decision in the other two servers: server-go removed
    # chi's middleware.RealIP and server-node sets `trust proxy` to false, both
    # so that clientip.* is the only thing resolving a client address.
    #
    # Running uvicorn directly? Pass --no-proxy-headers. Under gunicorn, set
    # forwarded_allow_ips to nothing. See INSTALLATION.md.
    uvicorn.run(app, host="0.0.0.0", port=port, proxy_headers=False)
