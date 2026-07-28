"""Input forensics v2 - PRD workstream C.

Four checks on *how* input arrived rather than how much of it there was: typing
cadence, typing modality, the paste-shortcut/platform contradiction, and scroll
morphology.

Every threshold here was measured, not assumed
----------------------------------------------
The PRD quotes FP-Agent's observations (Manus 1.39ms inter-key, Browser Use
5.31ms, Skyvern 9.52ms) and then warns, correctly, that they are *not*
constants: the paper found Browser Use programs an 18ms delay yet is observed at
5.31ms, because the renderer batches events. The numbers are a function of
browser version and machine load. Hardcoding them would be copying someone
else's laboratory conditions.

So the values below come from the bench corpus (bench/README.md), captured on
real hardware through a real browser::

    signal                 human                     scripted agent
    ---------------------  ------------------------  --------------------
    inter-key interval     min 114.6ms, med 226.9ms  max 25.9ms, med 7.9ms
    interval variance      4549                      8
    key hold (dwell)       min 41.4ms, med 82.0ms    max 25.5ms, med 7.8ms
    scroll max step        109px                     704px

The distributions do not overlap, so the thresholds sit in the empty space
between them with a wide margin on both sides rather than hugging either.

What is deliberately NOT here
-----------------------------
Keystroke overlap - the claim that humans press the next key before releasing
the current one and agents never do. An earlier PRD draft attributed it to
FP-Agent; the paper does not say it. It defines a keystroke as "a keydown event
followed by a keyup event" and its only overlap language is about modifier keys
in shortcuts. The hypothesis may well hold, but it has no source and no
measurement here, so it earns no weight.

Weighting
---------
All contributory, not decisive, per section 7.4: the coalesced-events signal
FCaptcha already ships is under active attack from stealth tooling that
synthesises it, and behavioural signals have a shelf life. The platform
contradiction scores higher because it is not a threshold at all - it is the
client disagreeing with itself.

Mirrors server-node/inputforensics.js and server-go/inputforensics.go.
"""

import re
from typing import Any, Dict, List, Optional

# 2.9x below the slowest human keystroke observed, 1.5x above the fastest agent one.
MAX_MACHINE_INTERKEY_MS = 40.0
# Human variance was 4549; the scripted agent's was 8.
MAX_MACHINE_INTERVAL_VARIANCE = 200.0
# Human holds bottomed out at 41ms; the agent never exceeded 25.5ms.
MAX_MACHINE_DWELL_MS = 35.0
# Enough keystrokes to be a typing sample at all. A paste registers as one or two
# keydowns, and at n=2 any cadence statistic is noise.
MIN_KEYS_FOR_CADENCE = 10
# Human scrolling never stepped more than 109px between events; scrollIntoView
# covered 704px in one.
MAX_HUMAN_SCROLL_STEP_PX = 400.0

MAC_PLATFORMS = re.compile(r"^(mac|iphone|ipad|ipod)", re.I)
WINDOWS_PLATFORMS = re.compile(r"^win", re.I)


def _num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _pasted(typing: Dict[str, Any]) -> bool:
    return _num(typing.get("pasteEvents")) > 0 or _num(typing.get("pasteInputs")) > 0


def check_typing_cadence(fields: Optional[Dict[str, Any]], typing: Dict[str, Any]) -> List[Dict]:
    """Flag a rhythm no hand produces.

    Gated hard, because the failure mode is punishing people who paste. Humans
    paste constantly - password managers, copied addresses, one-time codes - and
    a paste arrives as one or two keydowns microseconds apart, arithmetically
    indistinguishable from very fast typing. The bench's paste-by-human persona
    is exactly that shape: 2 keys, 0.8ms apart, variance 0.

    Hence three preconditions before the cadence is looked at: enough keys to be
    a sample, no paste anywhere on the page, and no paste into this field.
    """
    if not fields or _pasted(typing):
        return []

    for stats in fields.values():
        if not isinstance(stats, dict):
            continue
        if _num(stats.get("pasteCount")) > 0:
            continue
        if _num(stats.get("keyCount")) < MIN_KEYS_FOR_CADENCE:
            continue

        interval = _num(stats.get("avgKeyInterval"), float("inf"))
        variance = _num(stats.get("keyIntervalVariance"), float("inf"))

        dwells = stats.get("dwellTimes") or []
        avg_dwell = sum(dwells) / len(dwells) if dwells else float("inf")

        # Both the rhythm and the hold have to be inhuman. Either alone is a
        # machine that happens to be slow, or a fast typist on a bad keyboard.
        machine_rhythm = interval < MAX_MACHINE_INTERKEY_MS and variance < MAX_MACHINE_INTERVAL_VARIANCE
        machine_hold = avg_dwell < MAX_MACHINE_DWELL_MS

        if machine_rhythm and machine_hold:
            # One detection per request, however many fields were filled.
            return [{
                "category": "behavioral",
                "score": 0.6,
                "confidence": 0.6,
                "reason": "Typing cadence is mechanical (inter-key and hold both below human range)",
            }]
    return []


def check_paste_platform_coherence(typing: Dict[str, Any], platform: Optional[str]) -> List[Dict]:
    """Flag a paste shortcut that disagrees with the platform the client claims.

    macOS pastes with Meta+V; Windows and Linux paste with Control+V. These are
    not conventions a user can be halfway between - the other combination does
    nothing at all on that OS. So a client reporting MacIntel whose visitor
    pasted with Control+V has told us two incompatible things about itself.

    Requiring that the paste *landed* is what makes this safe. A Windows switcher
    on a new Mac really does fat-finger Ctrl+V - and on macOS nothing happens, so
    no paste event follows. Only a client whose real platform differs from its
    claimed one gets both the wrong shortcut and a completed paste.
    """
    if not platform or not _pasted(typing):
        return []

    ctrl = _num(typing.get("pasteShortcutControl"))
    meta = _num(typing.get("pasteShortcutMeta"))

    if MAC_PLATFORMS.match(platform) and ctrl > 0 and meta == 0:
        return [{
            "category": "automation",
            "score": 0.7,
            "confidence": 0.8,
            "reason": f"Paste shortcut contradicts platform (Control+V while claiming {platform})",
        }]
    if WINDOWS_PLATFORMS.match(platform) and meta > 0 and ctrl == 0:
        return [{
            "category": "automation",
            "score": 0.7,
            "confidence": 0.8,
            "reason": f"Paste shortcut contradicts platform (Meta+V while claiming {platform})",
        }]
    return []


def check_programmatic_fill(typing: Dict[str, Any]) -> List[Dict]:
    """Flag text that appeared without being typed or pasted.

    A genuine input event carries an inputType describing what the browser did; a
    synthetic one dispatched by script does not. Combined with no keystrokes and
    no paste, that is a value assigned straight into the DOM.

    Deliberately low confidence: browser autofill and some password managers also
    produce input events with no keystrokes behind them, and a check that
    punishes password-manager users is worse than no check. It contributes; it
    never decides.
    """
    if (
        _num(typing.get("inputsWithoutInputType")) > 0
        and _num(typing.get("inputsWithoutKeys")) > 0
        and not _pasted(typing)
    ):
        return [{
            "category": "automation",
            "score": 0.5,
            "confidence": 0.4,
            "reason": "Field populated without keystrokes or paste (synthetic input event)",
        }]
    return []


def check_scroll_morphology(behavioral: Dict[str, Any]) -> List[Dict]:
    """Flag a page that moved further in one event than a hand can move it.

    A wheel notch or trackpad flick advances tens of pixels and emits an event
    each time, so covering a long page takes dozens of them. scrollIntoView
    covers the same distance in one, because it is aiming at an element rather
    than turning a wheel. Measured: human scrolling never exceeded 109px between
    consecutive events; the agent's jump was 704px.

    Gated on there being no keyboard activity, because PageDown, End and Space
    are legitimate one-event jumps of roughly a viewport. A visitor using the
    keyboard to scroll is doing something a hand does; a DOM agent has no keys.
    """
    m = behavioral.get("scrollMorphology")
    if not isinstance(m, dict):
        return []
    if _num(behavioral.get("keyEvents")) > 0:
        return []
    if _num(m.get("samples")) < 2:
        return []

    if _num(m.get("maxStep")) > MAX_HUMAN_SCROLL_STEP_PX:
        return [{
            "category": "automation",
            "score": 0.5,
            "confidence": 0.5,
            "reason": "Page scrolled by API rather than by gesture (single-event jump)",
        }]
    return []


def check_font_platform_coherence(fonts: Optional[Dict[str, Any]], platform: Optional[str]) -> List[Dict]:
    """Flag a font list that contradicts the claimed operating system.

    Scores the *contradiction*, never the enumeration. A short font list means a
    privacy extension, a minimal Linux install or a locked-down corporate image -
    all ordinary. A list full of Windows-only faces under a macOS claim is not
    ordinary, it is two different machines' worth of evidence in one payload.
    """
    if not fonts or not platform or fonts.get("supported") is False:
        return []
    # An empty or near-empty list is a blocked enumeration, not a contradiction.
    if _num(fonts.get("count")) < 3:
        return []

    mac_fonts = fonts.get("hasSFPro") is True or fonts.get("hasMenlo") is True
    win_fonts = fonts.get("hasSegoeUI") is True or fonts.get("hasCalibri") is True

    if MAC_PLATFORMS.match(platform) and win_fonts and not mac_fonts:
        return [{
            "category": "automation",
            "score": 0.5,
            "confidence": 0.5,
            "reason": f"Font set contradicts platform (Windows faces while claiming {platform})",
        }]
    if WINDOWS_PLATFORMS.match(platform) and mac_fonts and not win_fonts:
        return [{
            "category": "automation",
            "score": 0.5,
            "confidence": 0.5,
            "reason": f"Font set contradicts platform (macOS faces while claiming {platform})",
        }]
    return []


def detect_input_forensics(signals: Dict[str, Any]) -> List[Dict]:
    """Run every workstream-C check."""
    behavioral = signals.get("behavioral") or {}
    form = signals.get("formAnalysis") or {}
    env = signals.get("environmental") or {}
    typing = form.get("typing") or {}
    platform = (env.get("navigator") or {}).get("platform")
    if isinstance(platform, str):
        platform = platform.strip()

    return [
        *check_typing_cadence(form.get("textareaKeyboard"), typing),
        *check_paste_platform_coherence(typing, platform),
        *check_programmatic_fill(typing),
        *check_scroll_morphology(behavioral),
        *check_font_platform_coherence(env.get("fontsInfo"), platform),
    ]
