"""identity-coherence-v1: claimed identity versus independent measurements.

Each measurement is an axis that agrees, contradicts or knows nothing; unknown
never counts. Observe-only: it has no enforcement selector, so
FCAPTCHA_EXPERIMENTAL_BLOCKING cannot opt anyone into it.

The value is in how axes relate, not in a weighted sum. One axis against the
claim has ordinary explanations (a VM, a font pack). Measurements that agree
with each other against the claim mean the claim was replaced. Measurements
that disagree with each other cannot come from changing the claim alone.
"""
import re
from typing import Dict, List, Optional

IDENTITY_POLICY = "identity-coherence-v1"

# Canonical order keeps reasons and fixtures identical across the servers.
OS_LABELS = {"windows": "Windows", "macos": "macOS", "ios": "iOS",
             "android": "Android", "chromeos": "ChromeOS", "linux": "Linux"}
ENGINE_LABELS = {"blink": "Blink", "gecko": "Gecko", "webkit": "WebKit"}

# ANGLE names its backend in the renderer string. Direct3D exists only on
# Windows and Metal only on Apple platforms. Deliberately absent: GPU model
# names. An Apple GPU runs Linux under Asahi, and Adreno/Mali ship in Windows
# laptops and Chromebooks, so a model name says nothing certain about the OS.
DIRECT3D = re.compile(r"direct3d|\bd3d(9|11|12)\b", re.IGNORECASE)
METAL = re.compile(r"\bmetal\b", re.IGNORECASE)


def claimed_os(ua, max_touch_points) -> Optional[List[str]]:
    """OS families the User-Agent is consistent with, or None. iPadOS requests
    desktop sites with a macOS UA, which touch points betray."""
    if not isinstance(ua, str) or not ua:
        return None
    if re.search(r"iPhone|iPad|iPod", ua):
        return ["ios"]
    if "Android" in ua:
        return ["android"]
    if "CrOS" in ua:
        return ["chromeos"]
    if "Windows" in ua:
        return ["windows"]
    if re.search(r"Macintosh|Mac OS X", ua):
        return ["macos", "ios"] if max_touch_points > 1 else ["macos"]
    if re.search(r"Linux|X11", ua):
        return ["linux"]
    return None


def claimed_engine(ua, max_touch_points=0) -> Optional[List[str]]:
    """Browser engine implied by the UA. Every iOS browser uses WebKit,
    including CriOS/FxiOS/EdgiOS."""
    if not isinstance(ua, str) or not ua:
        return None
    if re.search(r"iPhone|iPad|iPod", ua):
        return ["webkit"]
    if re.search(r"Macintosh|Mac OS X", ua) and max_touch_points > 1:
        return ["webkit"]
    if "Firefox/" in ua:
        return ["gecko"]
    if re.search(r"(?:Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|SamsungBrowser)/", ua):
        return ["blink"]
    if "AppleWebKit/" in ua and "Safari/" in ua:
        return ["webkit"]
    return None


def _number(value) -> float:
    return value if type(value) in (int, float) else 0


def _gpu_backend_axis(env: Dict) -> Dict:
    axis = {"id": "gpu-backend-os-mismatch", "dimension": "os", "observed": None}
    webgl = env.get("webglInfo")
    if not isinstance(webgl, dict) or webgl.get("supported") is False:
        return axis
    renderer = webgl.get("renderer")
    renderer = renderer if isinstance(renderer, str) else ""
    d3d, metal = bool(DIRECT3D.search(renderer)), bool(METAL.search(renderer))
    if d3d and not metal:
        return {**axis, "observed": ["windows"], "subject": "WebGL Direct3D backend"}
    if metal and not d3d:
        return {**axis, "observed": ["macos", "ios"], "subject": "WebGL Metal backend"}
    return axis


def _font_set_axis(env: Dict) -> Dict:
    """Mirrors check_font_platform_coherence: a short list is a blocked
    enumeration, and a mixed list (Office on a Mac) proves nothing."""
    axis = {"id": "font-set-os-mismatch", "dimension": "os", "observed": None}
    fonts = env.get("fontsInfo")
    if not isinstance(fonts, dict) or fonts.get("supported") is False or _number(fonts.get("count")) < 3:
        return axis
    mac = fonts.get("hasSFPro") is True or fonts.get("hasMenlo") is True
    win = fonts.get("hasSegoeUI") is True or fonts.get("hasCalibri") is True
    if win and not mac:
        return {**axis, "observed": ["windows"], "subject": "Font set (Windows faces)"}
    if mac and not win:
        return {**axis, "observed": ["macos", "ios"], "subject": "Font set (macOS faces)"}
    return axis


def _error_engine(env: Dict) -> Optional[str]:
    fingerprint = env.get("errorFingerprint")
    if not isinstance(fingerprint, dict) or fingerprint.get("supported") is False:
        return None
    message = fingerprint.get("typeError")
    message = message if isinstance(message, str) else ""
    if re.search(r"Cannot read propert(?:y|ies) of null", message, re.IGNORECASE):
        return "blink"
    if re.search(r"null has no properties|can't access property [\"']foo[\"'] of null", message, re.IGNORECASE):
        return "gecko"
    if re.search(r"null is not an object", message, re.IGNORECASE):
        return "webkit"
    return None


def _math_engine(env: Dict) -> Optional[str]:
    fingerprint = env.get("mathFingerprint")
    if not isinstance(fingerprint, dict) or fingerprint.get("supported") is False:
        return None
    return {"6256c877": "blink", "97ad9": "gecko", "-1128d0aa": "webkit"}.get(fingerprint.get("hash"))


def _probe_engine(env: Dict) -> Optional[str]:
    probes = env.get("engineProbes")
    if not isinstance(probes, dict) or probes.get("supported") is False:
        return None
    candidates = []
    if probes.get("errorCaptureStackTrace") is True:
        candidates.append("blink")
    if probes.get("mozAppearance") is True:
        candidates.append("gecko")
    if probes.get("webkitTouchCallout") is True:
        candidates.append("webkit")
    return candidates[0] if len(candidates) == 1 else None


def _js_engine_axis(env: Dict) -> Dict:
    axis = {"id": "js-engine-mismatch", "dimension": "engine", "observed": None}
    measured = [engine for engine in (_error_engine(env), _math_engine(env), _probe_engine(env)) if engine]
    if len(measured) < 2 or any(engine != measured[0] for engine in measured[1:]):
        return axis
    return {**axis, "observed": [measured[0]],
            "subject": f"JavaScript engine ({ENGINE_LABELS[measured[0]]})"}


def _overlap(a: List[str], b: List[str]) -> bool:
    return any(x in b for x in a)


def _label(dimension: str, claim: List[str]) -> str:
    labels = ENGINE_LABELS if dimension == "engine" else OS_LABELS
    return "/".join(label for name, label in labels.items() if name in claim)


def identity_observation(signals: Dict) -> Dict:
    result = {"mode": "observe", "status": "unknown", "detections": []}
    env = signals.get("environmental") if isinstance(signals, dict) else None
    env = env if isinstance(env, dict) else {}
    nav = env.get("navigator")
    nav = nav if isinstance(nav, dict) else {}
    claims = {
        "os": claimed_os(nav.get("userAgent"), _number(nav.get("maxTouchPoints"))),
        "engine": claimed_engine(nav.get("userAgent"), _number(nav.get("maxTouchPoints"))),
    }

    known = [a for a in (_gpu_backend_axis(env), _font_set_axis(env), _js_engine_axis(env))
             if a["observed"] and claims.get(a["dimension"])]
    if not known:
        return result

    contradicting = [a for a in known if not _overlap(a["observed"], claims[a["dimension"]])]
    for axis in contradicting:
        claimed_subject = "browser engine" if axis["dimension"] == "engine" else "OS"
        result["detections"].append({
            "id": axis["id"],
            "reason": f"{axis['subject']} contradicts claimed {claimed_subject} "
                      f"({_label(axis['dimension'], claims[axis['dimension']])})",
        })
    disagree = any(a["dimension"] == b["dimension"] and not _overlap(a["observed"], b["observed"])
                   for i, a in enumerate(known) for b in known[i + 1:])
    if disagree:
        result["detections"].append({"id": "identity-axes-disagree",
                                     "reason": "Measured properties disagree with each other"})
    elif any(a["dimension"] == b["dimension"] and _overlap(a["observed"], b["observed"])
             for i, a in enumerate(contradicting) for b in contradicting[i + 1:]):
        result["detections"].append({
            "id": "identity-claim-contradicted",
            "reason": "Several measured properties agree with each other and contradict the claimed OS",
        })
    result["status"] = "detected" if result["detections"] else "clear"
    return result
