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


def _overlap(a: List[str], b: List[str]) -> bool:
    return any(x in b for x in a)


def _label(claim: List[str]) -> str:
    return "/".join(label for os_name, label in OS_LABELS.items() if os_name in claim)


def identity_observation(signals: Dict) -> Dict:
    result = {"mode": "observe", "status": "unknown", "detections": []}
    env = signals.get("environmental") if isinstance(signals, dict) else None
    env = env if isinstance(env, dict) else {}
    nav = env.get("navigator")
    nav = nav if isinstance(nav, dict) else {}
    claim = claimed_os(nav.get("userAgent"), _number(nav.get("maxTouchPoints")))
    if not claim:
        return result

    known = [a for a in (_gpu_backend_axis(env), _font_set_axis(env)) if a["observed"]]
    if not known:
        return result

    contradicting = [a for a in known if not _overlap(a["observed"], claim)]
    for axis in contradicting:
        result["detections"].append({
            "id": axis["id"],
            "reason": f"{axis['subject']} contradicts claimed OS ({_label(claim)})",
        })
    disagree = any(a["dimension"] == b["dimension"] and not _overlap(a["observed"], b["observed"])
                   for i, a in enumerate(known) for b in known[i + 1:])
    if disagree:
        result["detections"].append({"id": "identity-axes-disagree",
                                     "reason": "Measured properties disagree with each other"})
    elif len(contradicting) >= 2:
        result["detections"].append({
            "id": "identity-claim-contradicted",
            "reason": "Several measured properties agree with each other and contradict the claimed OS",
        })
    result["status"] = "detected" if result["detections"] else "clear"
    return result
