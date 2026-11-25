"""Content-free canvas readback-stability evidence."""

from typing import Any, Dict, Optional


def canvas_stability_evidence(signals: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return canonical weak evidence only for an explicit boolean false.

    Older clients omit the field, and malformed client values must not become
    detections merely because they are falsey.
    """
    canvas = (signals.get("environmental") or {}).get("canvasHash") or {}
    if canvas.get("canvasStable") is not False:
        return None
    return {
        "category": "fingerprint",
        "score": 0.35,
        "confidence": 0.4,
        "reason": "Canvas readback changed between identical renders",
        "details": {"signal": "canvas_unstable"},
    }
