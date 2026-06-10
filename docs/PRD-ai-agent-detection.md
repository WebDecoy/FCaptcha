# PRD: AI Agent Detection

**Status:** Draft
**Owner:** Detection
**Created:** 2026-06-09
**Target baseline:** v1.10.2

---

## 1. Summary

FCaptcha today is strong against *legacy* automation (Selenium/Puppeteer globals,
headless Chrome env tells, known automation UA strings) and has a solid behavioral
core (`detectVisionAI`, `detectBehavioral`, micro-tremor, approach directness). It
is **weak against the way modern AI agents actually drive browsers**: hosted
"computer-use" agents (OpenAI Operator, Claude in Chrome, Gemini), CDP-injected
input that reports `isTrusted: true`, and DOM/accessibility-tree readers that never
touch a pixel.

This PRD specifies six detection workstreams, ordered by ROI, each with concrete
client- and server-side detection snippets that extend the existing collectors and
`detect*` functions.

> **Sync rule (from CLAUDE.md):** every server-side detection added here must land
> in **all three** server implementations — `server-go/`, `server-node/`,
> `server-python/`. Snippets below are written for Go (`detection.go` /
> `scoring.go`) and the client (`client/fcaptcha.js`); port the Go logic to Node
> and Python with the same weights, reasons, and category names.

---

## 2. Goals / Non-goals

### Goals
- Detect **declared** AI agents (self-identifying UAs, signed agent requests) with
  near-zero false positives, and expose a *policy* knob (allow polite/verified
  agents vs. block).
- Detect **undeclared** AI agents driving a real browser via CDP / computer-use,
  using input-event forensics and LLM "think-time" cadence.
- Detect **hosted** agents running headless Chromium in datacenters/containers.
- Detect **DOM-reading** agents via accessibility-tree honeypots.
- Strengthen **cross-session correlation** so agents that defeat point-in-time
  checks are caught over time.

### Non-goals
- Reimplementing IP/ASN/GeoIP/rDNS/DNSBL enrichment — that belongs to the sibling
  **webdecoy enrichment** project; FCaptcha *consumes* it.
- Blocking all bots indiscriminately. Verified/declared agents should be a policy
  decision, not a hard block.
- 100% defeat of fully source-patched browsers (CloakBrowser). The goal there is
  to raise cost and catch via behavioral + correlation signals (§7).

### Success metrics
- **TPR**: ≥ 90% of hosted computer-use agents (Operator/Claude-in-Chrome class)
  flagged ≥ 0.8 score on a labeled corpus.
- **FPR**: < 0.5% on a human panel that includes screen-reader, keyboard-only, and
  touch users (regression guard — see §8).
- **Declared-agent recall**: 100% of agents sending a known UA or valid
  `Signature-Agent` header are identified.

---

## 3. Threat model — how modern agents differ

| Class | Example | Tells it leaves | Tells it scrubs |
|---|---|---|---|
| Declared crawler/agent | `ClaudeBot`, `GPTBot`, `ChatGPT-User` | self-identifying UA, datacenter IP, sometimes signed | nothing — it's honest |
| Hosted computer-use | OpenAI Operator, Gemini | datacenter IP, software GPU, CDP input, LLM think-time | UA can look normal |
| Local CDP agent | Claude in Chrome (chrome.debugger), Playwright stealth | CDP attach side-effects, synthetic input internals | navigator.webdriver, globals |
| DOM/a11y reader | LLM "read_page" tools | reads accessibility tree, fills hidden labeled fields | mouse trajectory entirely |
| Source-patched | CloakBrowser | residual behavioral micro-signatures, IP reputation | all JS-observable env flags |

---

## 4. Workstream 1 — Declared agents (UA + IP + Web Bot Auth)

**Why first:** ~10 lines, near-zero FP risk, immediate coverage of every honest
agent. Adds a *policy surface* (allow vs. block) rather than just a score.

### 4.1 New category

```go
// scoring.go — add to the ThreatCategory block
const (
    // ... existing ...
    CategoryDeclaredAI ThreatCategory = "declared_ai"
)
```

Add to the weights map (keep the full map summing to 1.0 — rebalance the existing
`bot`/`tor_vpn` slack; see §9):

```go
weights: map[ThreatCategory]float64{
    // ... existing ...
    CategoryDeclaredAI: 0.02,
}
```

### 4.2 Known AI agent user-agents

```go
// detection.go
// Declared AI agents/crawlers. These self-identify; matching is high-confidence
// but LOW-severity by default so operators can choose to allow polite agents.
var declaredAIAgentPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(?i)\bClaudeBot\b`),
    regexp.MustCompile(`(?i)\bClaude-User\b`),
    regexp.MustCompile(`(?i)\bClaude-SearchBot\b`),
    regexp.MustCompile(`(?i)\banthropic-ai\b`),
    regexp.MustCompile(`(?i)\bGPTBot\b`),
    regexp.MustCompile(`(?i)\bChatGPT-User\b`),
    regexp.MustCompile(`(?i)\bOAI-SearchBot\b`),
    regexp.MustCompile(`(?i)\bPerplexityBot\b`),
    regexp.MustCompile(`(?i)\bPerplexity-User\b`),
    regexp.MustCompile(`(?i)\bGoogle-Extended\b`),
    regexp.MustCompile(`(?i)\bGoogleOther\b`),
    regexp.MustCompile(`(?i)\bCCBot\b`),
    regexp.MustCompile(`(?i)\bBytespider\b`),
    regexp.MustCompile(`(?i)\bmeta-externalagent\b`),
    regexp.MustCompile(`(?i)\bAmazonbot\b`),
    regexp.MustCompile(`(?i)\bcohere-ai\b`),
    regexp.MustCompile(`(?i)\bDiffbot\b`),
    regexp.MustCompile(`(?i)\bYouBot\b`),
    regexp.MustCompile(`(?i)\bAppleBot-Extended\b`),
}

// CheckDeclaredAIAgent flags self-identifying AI agents. Severity is intentionally
// low (operator decides via policy); confidence is high (UA is explicit).
func (e *ScoringEngine) CheckDeclaredAIAgent(userAgent string, headers map[string]string) []DetectionResult {
    results := make([]DetectionResult, 0)
    for _, re := range declaredAIAgentPatterns {
        if re.MatchString(userAgent) {
            results = append(results, DetectionResult{
                Category:   CategoryDeclaredAI,
                Score:      0.5, // not a hard block — see policy knob §4.4
                Confidence: 0.99,
                Reason:     "Declared AI agent user-agent: " + re.FindString(userAgent),
                Details:    map[string]interface{}{"matched": re.String()},
            })
            break
        }
    }
    return results
}
```

Wire it into `VerifyWithHeaders` next to the existing UA check:

```go
detections = append(detections, e.CheckDeclaredAIAgent(userAgent, headers)...)
```

### 4.3 Web Bot Auth (HTTP Message Signatures, RFC 9421)

The emerging standard for *cryptographically verified* agents. OpenAI signs
Operator/agent traffic; Cloudflare promotes it as the canonical "verified bot"
mechanism. Presence of `Signature` + `Signature-Agent` headers lets us identify
the agent **without heuristics** and apply policy.

```go
// detection.go
// CheckWebBotAuth detects RFC 9421 HTTP Message Signatures used by verified
// agents (Web Bot Auth). v1: detect + identify. v2: verify the signature against
// the agent's published JWKS (keyId in the Signature-Input) before trusting it.
func (e *ScoringEngine) CheckWebBotAuth(headers map[string]string) []DetectionResult {
    sigAgent, hasAgent := headers["signature-agent"]
    _, hasSig := headers["signature"]
    _, hasInput := headers["signature-input"]
    if !hasAgent || !hasSig || !hasInput {
        return nil
    }
    return []DetectionResult{{
        Category:   CategoryDeclaredAI,
        Score:      0.4,
        Confidence: 0.95,
        Reason:     "Signed agent request (Web Bot Auth): " + sigAgent,
        Details: map[string]interface{}{
            "signatureAgent": sigAgent,
            "verified":       false, // set true once JWKS verification lands (v2)
        },
    }}
}
```

> **v2 (signature verification):** parse `Signature-Input` for the `keyid`/`tag`,
> fetch the agent's directory/JWKS (cache it), and verify the `Signature` over the
> covered components (`@authority`, `signature-agent`, `@method`, …). Only then set
> `verified: true` and let policy *allow* the agent. Until verified, treat as a
> declared-but-unverified agent.

### 4.4 Policy knob

Declared/verified agents are a **business decision**, not a hard block. Expose
config so a site can allow polite/verified agents while still blocking undeclared
automation:

```go
type AIAgentPolicy struct {
    AllowDeclared  bool // honor robots-style polite agents (UA match)
    AllowVerified  bool // honor Web Bot Auth after signature verification
    BlockDatacenter bool
}
```

When `AllowVerified` and a Web Bot Auth signature verifies, short-circuit to
`Success: true` with a `recommendation: "allow_verified_agent"` instead of scoring.

### 4.5 IP/ASN — consume enrichment, don't hardcode

Hosted agents egress from OpenAI/Anthropic/cloud ranges. Per the project boundary,
do **not** grow a CIDR list in FCaptcha. Instead let `CheckIPReputation` read the
webdecoy enrichment result (ASN → org name) and map e.g. `Anthropic`,
`OpenAI`/`Azure-OpenAI`, `Google Cloud`, `AWS` to a datacenter/hosted-agent signal.

```go
// detection.go (sketch — enrichment is injected, not computed here)
if enr := e.enrichment.Lookup(ip); enr != nil {
    if org := strings.ToLower(enr.ASNOrg); strings.Contains(org, "anthropic") ||
        strings.Contains(org, "openai") {
        results = append(results, DetectionResult{
            Category: CategoryDeclaredAI, Score: 0.6, Confidence: 0.9,
            Reason:  "Egress IP belongs to AI provider ASN: " + enr.ASNOrg,
        })
    }
}
```

---

## 5. Workstream 2 — Input-event forensics (CDP-injected input)

**Why:** modern agents (Claude in Chrome via `chrome.debugger`, Operator via
Playwright/CDP) dispatch input through `Input.dispatchMouseEvent`, producing
`isTrusted: true` events that the existing global-based CDP check misses. The
*shape* of those events still betrays them.

### 5.1 Coalesced events (strongest modern signal)

Real pointer movement produces coalesced batches; CDP-injected moves don't.

```javascript
// client/fcaptcha.js — BehavioralCollector, attach during mousemove tracking
_initCoalescedTracking() {
  this._coalesced = { samples: 0, empty: 0, totalCoalesced: 0 };
  window.addEventListener('pointermove', (e) => {
    if (typeof e.getCoalescedEvents !== 'function') return;
    const c = e.getCoalescedEvents();
    this._coalesced.samples++;
    if (c.length <= 1) this._coalesced.empty++;
    this._coalesced.totalCoalesced += c.length;
  }, { passive: true });
}

_getCoalescedStats() {
  const s = this._coalesced || { samples: 0, empty: 0, totalCoalesced: 0 };
  return {
    samples: s.samples,
    emptyRatio: s.samples ? s.empty / s.samples : 0,         // ~1.0 for synthetic
    avgCoalesced: s.samples ? s.totalCoalesced / s.samples : 0, // ~1.0 for synthetic
  };
}
```

```go
// scoring.go — inside detectVisionAI
if cs := getMap(behavioral, "coalescedStats"); cs != nil {
    samples := getFloat(cs, "samples")
    emptyRatio := getFloat(cs, "emptyRatio")
    avgCoalesced := getFloat(cs, "avgCoalesced")
    // Require enough samples; real mice coalesce, synthetic input does not.
    if samples >= 10 && emptyRatio > 0.95 && avgCoalesced < 1.1 && !isTouchUser {
        results = append(results, DetectionResult{
            Category:   CategoryCDP,
            Score:      0.85,
            Confidence: 0.8,
            Reason:     "Pointer moves have no coalesced events (synthetic/CDP input)",
            Details:    map[string]interface{}{"emptyRatio": emptyRatio, "avgCoalesced": avgCoalesced},
        })
    }
}
```

### 5.2 Pointer internals (movement coherence)

> **Implementation note (shipped in Phase 2):** the original draft below used
> `pressure` constancy as a sub-signal. That was dropped — a real mouse hovering
> (moving without a button held) reports `pressure === 0` on *every* move, so a
> constant-pressure check false-positives on all mouse users. The shipped signal
> keeps only **movement/position coherence**: the fraction of position-changing
> moves where `movementX === 0 && movementY === 0` (`pointerMoveZeroRatio`),
> fired conservatively (`>= 20` samples, ratio `> 0.9`, low confidence).

```javascript
// client/fcaptcha.js — sample on pointermove/pointerdown
_samplePointerInternals(e) {
  this._ptr = this._ptr || { n: 0, zeroPressure: 0, constPressure: 0, lastP: -1,
                             movementMismatch: 0, lastX: null, lastY: null };
  const p = this._ptr;
  p.n++;
  if (e.pressure === 0) p.zeroPressure++;
  if (e.pressure === p.lastP) p.constPressure++;
  p.lastP = e.pressure;
  // movementX/Y should track position deltas on real devices
  if (p.lastX !== null) {
    const dx = e.clientX - p.lastX, dy = e.clientY - p.lastY;
    if (Math.abs(dx - e.movementX) > 2 || Math.abs(dy - e.movementY) > 2) {
      p.movementMismatch++;
    }
  }
  p.lastX = e.clientX; p.lastY = e.clientY;
}

_getPointerInternals() {
  const p = this._ptr || { n: 0 };
  return p.n ? {
    samples: p.n,
    constPressureRatio: p.constPressure / p.n,   // synthetic: ~1.0
    movementMismatchRatio: p.movementMismatch / p.n,
  } : { samples: 0 };
}
```

```go
// scoring.go — detectVisionAI
if pi := getMap(behavioral, "pointerInternals"); pi != nil {
    if getFloat(pi, "samples") >= 10 &&
        getFloat(pi, "constPressureRatio") > 0.98 &&
        getFloat(pi, "movementMismatchRatio") > 0.5 && !isTouchUser {
        results = append(results, DetectionResult{
            Category: CategoryCDP, Score: 0.7, Confidence: 0.65,
            Reason: "Pointer pressure constant and movement deltas incoherent (synthetic input)",
        })
    }
}
```

### 5.3 CDP attach side-effect (catches any protocol client)

Attaching a CDP client makes the runtime serialize logged objects; we can observe
that via a getter trap. Catches Playwright, Puppeteer-stealth, and
`chrome.debugger` extensions even when JS globals are scrubbed.

```javascript
// client/fcaptcha.js — run once during environmental collect
_detectCDPSideEffect() {
  let triggered = false;
  const bait = new Error();
  Object.defineProperty(bait, 'stack', {
    configurable: true,
    get() { triggered = true; return ''; },
  });
  // When a CDP console domain is attached, the host serializes the logged value,
  // reading .stack. With no devtools/agent attached, the getter never fires.
  // eslint-disable-next-line no-console
  console.debug(bait);
  return { cdpConsoleAttached: triggered };
}
```

```go
// scoring.go — detectHeadless or detectCDP
if env := getMap(signals, "environmental"); env != nil {
    if se := getMap(env, "cdpSideEffect"); getBool(se, "cdpConsoleAttached") {
        results = append(results, DetectionResult{
            Category: CategoryCDP, Score: 0.9, Confidence: 0.85,
            Reason: "CDP console domain attached (DevTools/automation protocol active)",
        })
    }
}
```

> **FP note:** a human with DevTools open also trips §5.3. Weight it as a *signal*,
> not a verdict, and combine with input-forensics — a real user with DevTools open
> still produces coalesced pointer events and think-time noise.

---

## 6. Workstream 3 — LLM think-time cadence

**Why:** the single most distinctive thing about an agent loop is
**act → screenshot → inference (seconds of *perfect* silence) → act**. Humans idle
*noisily* (micro-moves, scroll, focus churn); agents idle perfectly.

### 6.1 Client: inter-event gap histogram + teleport clicks

```javascript
// client/fcaptcha.js — global event monitor across mouse/key/scroll/focus
_initCadence() {
  this._cad = { last: performance.now(), gaps: [], silentGaps: 0, teleports: 0,
                lastPos: null };
  const mark = (pos) => {
    const now = performance.now();
    const gap = now - this._cad.last;
    this._cad.gaps.push(gap);
    // "Dead air": >1.5s with no events at all = candidate think-time
    if (gap > 1500) this._cad.silentGaps++;
    this._cad.last = now;
    if (pos) this._cad.lastPos = pos;
  };
  ['mousemove','scroll','keydown','focus','wheel','pointermove']
    .forEach(t => window.addEventListener(t, () => mark(null), { passive: true, capture: true }));
  // Teleport click: mousedown far from last known pointer position, no moves between
  window.addEventListener('mousedown', (e) => {
    const lp = this._cad.lastPos;
    if (lp) {
      const d = Math.hypot(e.clientX - lp.x, e.clientY - lp.y);
      if (d > 200) this._cad.teleports++;
    }
    mark({ x: e.clientX, y: e.clientY });
  }, { capture: true });
  window.addEventListener('mousemove',
    (e) => { this._cad.lastPos = { x: e.clientX, y: e.clientY }; },
    { passive: true, capture: true });
}

_getCadence() {
  const c = this._cad || { gaps: [], silentGaps: 0, teleports: 0 };
  const gaps = c.gaps;
  // Coefficient of variation: agents alternate tight bursts + long dead air -> high CV
  const mean = gaps.reduce((a,b)=>a+b,0) / (gaps.length||1);
  const variance = gaps.reduce((a,b)=>a+(b-mean)**2,0) / (gaps.length||1);
  return {
    eventCount: gaps.length,
    silentGaps: c.silentGaps,            // # of multi-second dead-air gaps
    teleportClicks: c.teleports,
    gapCV: mean ? Math.sqrt(variance)/mean : 0,
  };
}
```

### 6.2 Server: bursty cadence + teleport scoring

```go
// scoring.go — detectVisionAI
if cad := getMap(behavioral, "cadence"); cad != nil {
    silentGaps := getFloat(cad, "silentGaps")
    teleports := getFloat(cad, "teleportClicks")
    gapCV := getFloat(cad, "gapCV")
    eventCount := getFloat(cad, "eventCount")

    // Agent loop: real interaction interspersed with multi-second perfect silence.
    if eventCount >= 8 && silentGaps >= 2 && gapCV > 2.0 && !isKeyboardUser {
        results = append(results, DetectionResult{
            Category: CategoryVisionAI, Score: 0.75, Confidence: 0.65,
            Reason:  "Interaction cadence matches agent act/think loop (bursts + dead air)",
            Details: map[string]interface{}{"silentGaps": silentGaps, "gapCV": gapCV},
        })
    }
    // Teleport clicks: action injected at coordinates with no approach trajectory.
    if teleports >= 1 && !isTouchUser {
        results = append(results, DetectionResult{
            Category: CategoryVisionAI, Score: 0.7, Confidence: 0.7,
            Reason:  fmt.Sprintf("Click(s) injected with no pointer trajectory (%d teleports)", int(teleports)),
        })
    }
}
```

### 6.3 Programmatic typing (Playwright `fill`)

```javascript
// client/fcaptcha.js — per-field input listener (extend existing form analyzer)
field.addEventListener('input', (e) => {
  const rec = this._fieldStats(e.target.id);
  rec.inputEvents++;
  // fill() inserts text with no keydown; value length jumps with zero key events
  if (e.inputType === 'insertText' && rec.keysSinceInput === 0) rec.noKeyInserts++;
  rec.keysSinceInput = 0;
});
field.addEventListener('keydown', (e) => { this._fieldStats(e.target.id).keysSinceInput++; });
```

```go
// detection.go — extend the existing textarea/form analysis
if rec := /* per-field stats */; getFloat(rec, "noKeyInserts") > 0 &&
    getFloat(rec, "keyCount") == 0 && len(fieldValue) > 3 {
    results = append(results, DetectionResult{
        Category: CategoryAutomation, Score: 0.8, Confidence: 0.8,
        Reason: fmt.Sprintf("Field %q filled programmatically (insertText, no keystrokes)", fieldID),
    })
}
```

---

## 7. Workstream 4 — Hosted-agent environment tells

**Why:** Operator/Gemini-class agents run headless Chromium in containers. Software
GPU + minimal font set + datacenter IP + canonical viewport is a high-confidence
*composite* that resists single-signal spoofing.

### 7.1 Software GPU (WebGL unmasked renderer)

```javascript
// client/fcaptcha.js — extend _getWebGLInfo()
_getWebGLRenderer() {
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    const dbg = gl && gl.getExtension('WEBGL_debug_renderer_info');
    const renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : '';
    const vendor   = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : '';
    const software = /swiftshader|llvmpipe|mesa offscreen|software/i.test(renderer);
    return { renderer, vendor, software };
  } catch { return { renderer: '', vendor: '', software: false }; }
}
```

```go
// detection.go — detectHeadless
if wgl := getMap(env, "webglRenderer"); getBool(wgl, "software") {
    results = append(results, DetectionResult{
        Category: CategoryHeadless, Score: 0.7, Confidence: 0.75,
        Reason:  "Software WebGL renderer (VM/container/headless): " + getString(wgl, "renderer"),
    })
}
```

### 7.2 Composite hosted-agent signal

```go
// scoring.go — run after individual detections are collected
func (e *ScoringEngine) detectHostedAgentComposite(signals map[string]interface{}, ip string, headers map[string]string) []DetectionResult {
    env := getMap(signals, "environmental")
    score := 0
    if wgl := getMap(env, "webglRenderer"); getBool(wgl, "software") { score++ }
    if fonts := getMap(env, "fontsInfo"); getFloat(fonts, "count") < 12 { score++ } // DejaVu-only set
    if nav := getMap(env, "navigator"); strings.Contains(strings.ToLower(getString(nav, "platform")), "linux") { score++ }
    if scr := getMap(env, "screen"); getFloat(scr, "dpr") == 1 && isCanonicalHeadlessViewport(scr) { score++ }
    if e.isDatacenterIP(ip) { score++ } // via enrichment

    if score >= 3 {
        return []DetectionResult{{
            Category: CategoryHeadless, Score: 0.85, Confidence: 0.8,
            Reason:  fmt.Sprintf("Hosted-agent environment composite (%d/5 indicators)", score),
            Details: map[string]interface{}{"indicators": score},
        }}
    }
    return nil
}
```

### 7.3 Client-hint coherence (server-side)

```go
// detection.go — compare Sec-CH-UA family against UA and JS-reported platform
chPlatform := strings.Trim(headers["sec-ch-ua-platform"], `"`)
jsPlatform := getString(getMap(getMap(signals, "environmental"), "navigator"), "platform")
if chPlatform != "" && jsPlatform != "" && !platformsAgree(chPlatform, jsPlatform) {
    results = append(results, DetectionResult{
        Category: CategoryHeadless, Score: 0.6, Confidence: 0.7,
        Reason:  fmt.Sprintf("Client-hint/JS platform mismatch: CH=%q JS=%q", chPlatform, jsPlatform),
    })
}
```

---

## 8. Workstream 5 — Accessibility-tree honeypots (DOM readers)

**Why:** DOM-driven agents (LLM `read_page`/`read the page` tools) act on the
accessibility tree, not pixels. A field that is **visually hidden but present and
innocuously labeled in the a11y tree** is seen (and sometimes filled) by DOM
readers while invisible to humans *and* to pure-vision agents — letting us
distinguish the two.

```javascript
// client/fcaptcha.js — inject during widget mount
_injectHoneypots() {
  // (A) Visually hidden, a11y-VISIBLE: only a DOM/a11y reader will fill it.
  const a = document.createElement('input');
  a.type = 'text'; a.name = 'contact_pref'; a.autocomplete = 'off';
  a.setAttribute('aria-label', 'Preferred contact method');
  a.style.cssText = 'position:absolute;left:-9999px;width:1px;height:1px;opacity:0';
  a.tabIndex = -1;

  // (B) a11y-HIDDEN but visually rendered offscreen: a vision agent might click it,
  //     a DOM reader will skip it (aria-hidden). Distinguishes reader vs. clicker.
  const b = document.createElement('button');
  b.textContent = 'Continue';
  b.setAttribute('aria-hidden', 'true');
  b.style.cssText = 'position:absolute;left:-9999px';

  this._hpFilled = false; this._hpClicked = false;
  a.addEventListener('input', () => { this._hpFilled = true; });
  b.addEventListener('click', () => { this._hpClicked = true; });
  this._root.append(a, b);
}

_getHoneypotState() {
  return { domReaderFill: !!this._hpFilled, visionClick: !!this._hpClicked };
}
```

```go
// scoring.go — detectVisionAI
if hp := getMap(behavioral, "honeypot"); hp != nil {
    if getBool(hp, "domReaderFill") {
        results = append(results, DetectionResult{
            Category: CategoryVisionAI, Score: 0.85, Confidence: 0.8,
            Reason:  "Filled a11y-only honeypot field (DOM/accessibility-tree reader)",
        })
    }
    if getBool(hp, "visionClick") {
        results = append(results, DetectionResult{
            Category: CategoryVisionAI, Score: 0.8, Confidence: 0.7,
            Reason:  "Clicked aria-hidden offscreen control (vision agent)",
        })
    }
}
```

> **FP mitigation — protect real screen-reader users.** A blind human using a
> screen reader also reads the a11y tree but will **not** fill a field whose
> accessible name clearly marks it skippable. Use an accessible name like
> *"Leave this field blank"* on honeypot (A), weight it **low on its own**, and
> only escalate when combined with another agent signal (§5/§6). Never hard-block
> on a honeypot alone.

---

## 9. Workstream 6 — Cross-session correlation (CloakBrowser gap)

**Why:** source-patched browsers defeat every point-in-time env check. What they
*can't* easily hide is behavioral consistency over time. `FingerprintStore`
already exists but is underused.

- Per-**fingerprint** behavioral profile: does this fingerprint *always* solve in
  the same suspiciously-tight timing band, *always* zero exploration, *always*
  identical micro-tremor score? Low variance across sessions = automation.
- Per-**ASN** velocity: many distinct fingerprints, same ASN, same behavioral
  signature = agent fleet.
- Persist a rolling per-fingerprint vector (solve time, tremor, exploration ratio,
  cadence CV); flag when intra-fingerprint variance collapses below a human floor.

```go
// scoring.go — sketch; extend FingerprintData with a behavioral ring buffer
type FingerprintData struct {
    FirstSeen int64
    Count     int
    IPs       map[string]bool
    Solves    []BehaviorSample // ring buffer, last N
}
type BehaviorSample struct{ SolveMs, Tremor, Exploration, GapCV float64 }

func (e *ScoringEngine) detectCorrelatedAutomation(fp string) []DetectionResult {
    d := e.fingerprintStore.get(fp)
    if d == nil || len(d.Solves) < 5 { return nil }
    if coefVar(samplesOf(d.Solves, func(s BehaviorSample) float64 { return s.SolveMs })) < 0.03 &&
        coefVar(samplesOf(d.Solves, func(s BehaviorSample) float64 { return s.Tremor })) < 0.03 {
        return []DetectionResult{{
            Category: CategoryBehavioral, Score: 0.7, Confidence: 0.6,
            Reason:  "Behavioral metrics inhumanly consistent across sessions (correlated automation)",
        }}
    }
    return nil
}
```

---

## 10. Scoring & weights

- Keep the weights map **summing to 1.0**. Introducing `CategoryDeclaredAI`
  requires rebalancing — proposed: take 0.02 from the combined `bot`/`tor_vpn`
  slack. Re-verify the sum in a unit test (there should already be one; if not,
  add `TestWeightsSumToOne`).
- New CDP/vision signals reuse **existing** categories (`CategoryCDP`,
  `CategoryVisionAI`, `CategoryHeadless`) so they ride existing weights — no
  rebalancing needed for §5–§8 except the new declared-AI category.
- **Severity vs. confidence:** declared agents = low score / high confidence
  (identify, let policy decide). Undeclared input-forensics = high score / high
  confidence (block).

---

## 11. Rollout plan

| Phase | Scope | Effort | Risk |
|---|---|---|---|
| **P1** ✅ | §4 declared UAs (shipped v1.11.0); IP/ASN via enrichment + policy knob still pending | ~0.5 day | very low |
| **P2** ✅ | §5 coalesced events + movement coherence + CDP side-effect; §6 teleport + cadence + programmatic fill | ~2–3 days | medium (FP tuning) |
| **P3** | §7 software-GPU + hosted composite + client-hint coherence | ~1–2 days | low |
| **P4** | §4.3 Web Bot Auth **signature verification** (JWKS fetch/cache) | ~2 days | low |
| **P5** | §8 a11y honeypots (behind a flag; heavy FP testing first) | ~1 day | medium (a11y FP) |
| **P6** | §9 cross-session correlation | ~3 days | medium |

Each phase ships to **all three servers** in lockstep (sync rule) plus the client.

---

## 12. Testing & FP guards

- **Human regression panel** in `test/test-detection.js`: keyboard-only,
  screen-reader (NVDA/VoiceOver-style a11y traversal), touch, DevTools-open, and
  high-latency/throttled-network humans must all stay below the block threshold.
  This directly guards §5.3, §6 (slow humans), and §8 (screen readers).
- **Agent corpus**: capture real traces from Playwright, Puppeteer-stealth,
  `chrome.debugger` extension, and a hosted computer-use agent; assert each new
  signal fires on the intended class and *not* on humans.
- **Per-signal FP budget**: no single new signal may exceed 0.3% FPR on the human
  panel in isolation; composites may be stricter.
- **Weights invariant test**: assert `Σ weights == 1.0` after adding the category.
- Per CLAUDE.md, behavioral test fixtures need realistic `totalPoints`,
  `trajectoryLength`, `approachPoints`, etc. — extend fixtures with the new fields
  (`coalescedStats`, `cadence`, `pointerInternals`, `honeypot`, `webglRenderer`).

---

## 13. Open questions

1. **Web Bot Auth trust anchor** — do we maintain our own allowlist of agent
   directories/JWKS, or defer to a registry (e.g. Cloudflare's)? Affects §4.3 v2.
2. **Honeypot default** — ship §8 off-by-default given a11y FP risk, or on with a
   conservative low weight?
3. **Enrichment contract** — finalize the field names FCaptcha consumes from
   webdecoy (`ASNOrg`, `IsDatacenter`, …) so §4.5/§7.2 don't hardcode.
4. **Policy storage** — per-site `AIAgentPolicy` lives where? (site config vs.
   request param vs. env default.)
```
