'use strict';

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
const IDENTITY_POLICY = 'identity-coherence-v1';

// Canonical order keeps reasons and fixtures identical across the servers.
const OS_LABELS = { windows: 'Windows', macos: 'macOS', ios: 'iOS', android: 'Android', chromeos: 'ChromeOS', linux: 'Linux' };
const ENGINE_LABELS = { blink: 'Blink', gecko: 'Gecko', webkit: 'WebKit' };

// ANGLE names its backend in the renderer string. Direct3D exists only on
// Windows and Metal only on Apple platforms. Deliberately absent: GPU model
// names. An Apple GPU runs Linux under Asahi, and Adreno/Mali ship in Windows
// laptops and Chromebooks, so a model name says nothing certain about the OS.
const DIRECT3D = /direct3d|\bd3d(9|11|12)\b/i;
const METAL = /\bmetal\b/i;

// The OS families the User-Agent is consistent with, or null. iPadOS requests
// desktop sites with a macOS UA, which touch points betray.
function claimedOS(ua, maxTouchPoints) {
  if (typeof ua !== 'string' || ua === '') return null;
  if (/iPhone|iPad|iPod/.test(ua)) return ['ios'];
  if (ua.includes('Android')) return ['android'];
  if (ua.includes('CrOS')) return ['chromeos'];
  if (ua.includes('Windows')) return ['windows'];
  if (/Macintosh|Mac OS X/.test(ua)) return maxTouchPoints > 1 ? ['macos', 'ios'] : ['macos'];
  if (/Linux|X11/.test(ua)) return ['linux'];
  return null;
}

// Browser engine implied by the UA. Every browser on iOS uses WebKit, including
// CriOS/FxiOS/EdgiOS, so platform takes precedence over the product token.
function claimedEngine(ua, maxTouchPoints = 0) {
  if (typeof ua !== 'string' || ua === '') return null;
  if (/iPhone|iPad|iPod/.test(ua)) return ['webkit'];
  if (/Macintosh|Mac OS X/.test(ua) && maxTouchPoints > 1) return ['webkit'];
  if (/Firefox\//.test(ua)) return ['gecko'];
  if (/(?:Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|SamsungBrowser)\//.test(ua)) return ['blink'];
  if (/AppleWebKit\//.test(ua) && /Safari\//.test(ua)) return ['webkit'];
  return null;
}

function gpuBackendAxis(env) {
  const axis = { id: 'gpu-backend-os-mismatch', dimension: 'os', observed: null };
  const webgl = env?.webglInfo;
  const renderer = webgl?.supported !== false && typeof webgl?.renderer === 'string' ? webgl.renderer : '';
  const d3d = DIRECT3D.test(renderer);
  const metal = METAL.test(renderer);
  if (d3d && !metal) return { ...axis, observed: ['windows'], subject: 'WebGL Direct3D backend' };
  if (metal && !d3d) return { ...axis, observed: ['macos', 'ios'], subject: 'WebGL Metal backend' };
  return axis;
}

// Mirrors checkFontPlatformCoherence: a short list is a blocked enumeration,
// and a mixed list (Office on a Mac) proves nothing.
function fontSetAxis(env) {
  const axis = { id: 'font-set-os-mismatch', dimension: 'os', observed: null };
  const fonts = env?.fontsInfo;
  if (!fonts || typeof fonts !== 'object' || fonts.supported === false ||
      !(typeof fonts.count === 'number' && fonts.count >= 3)) return axis;
  const mac = fonts.hasSFPro === true || fonts.hasMenlo === true;
  const win = fonts.hasSegoeUI === true || fonts.hasCalibri === true;
  if (win && !mac) return { ...axis, observed: ['windows'], subject: 'Font set (Windows faces)' };
  if (mac && !win) return { ...axis, observed: ['macos', 'ios'], subject: 'Font set (macOS faces)' };
  return axis;
}

function errorEngine(errorFingerprint) {
  if (!errorFingerprint || errorFingerprint.supported === false) return null;
  const message = typeof errorFingerprint.typeError === 'string' ? errorFingerprint.typeError : '';
  if (/Cannot read propert(?:y|ies) of null/i.test(message)) return 'blink';
  if (/null has no properties|can't access property ["']foo["'] of null/i.test(message)) return 'gecko';
  if (/null is not an object/i.test(message)) return 'webkit';
  return null;
}

function mathEngine(mathFingerprint) {
  if (!mathFingerprint || mathFingerprint.supported === false) return null;
  // Hashes come from captured stock Chrome, Firefox and Safari samples. They
  // are corroboration only: an unknown hash never becomes a contradiction.
  const known = { '6256c877': 'blink', '97ad9': 'gecko', '-1128d0aa': 'webkit' };
  return known[mathFingerprint.hash] || null;
}

function probeEngine(probes) {
  if (!probes || probes.supported === false) return null;
  const candidates = [];
  if (probes.errorCaptureStackTrace === true) candidates.push('blink');
  if (probes.mozAppearance === true) candidates.push('gecko');
  if (probes.webkitTouchCallout === true) candidates.push('webkit');
  return candidates.length === 1 ? candidates[0] : null;
}

function jsEngineAxis(env) {
  const axis = { id: 'js-engine-mismatch', dimension: 'engine', observed: null };
  const measured = [
    errorEngine(env?.errorFingerprint),
    mathEngine(env?.mathFingerprint),
    probeEngine(env?.engineProbes),
  ].filter(Boolean);
  if (measured.length < 2 || measured.some((engine) => engine !== measured[0])) return axis;
  return { ...axis, observed: [measured[0]], subject: `JavaScript engine (${ENGINE_LABELS[measured[0]]})` };
}

const overlap = (a, b) => a.some((x) => b.includes(x));
const label = (dimension, set) => {
  const labels = dimension === 'engine' ? ENGINE_LABELS : OS_LABELS;
  return Object.keys(labels).filter((value) => set.includes(value)).map((value) => labels[value]).join('/');
};

function identityObservation(signals) {
  const result = { mode: 'observe', status: 'unknown', detections: [] };
  const env = signals?.environmental;
  const nav = env?.navigator;
  const touch = typeof nav?.maxTouchPoints === 'number' ? nav.maxTouchPoints : 0;
  const claims = { os: claimedOS(nav?.userAgent, touch), engine: claimedEngine(nav?.userAgent, touch) };

  const known = [gpuBackendAxis(env), fontSetAxis(env), jsEngineAxis(env)]
    .filter((axis) => axis.observed && claims[axis.dimension]);
  if (known.length === 0) return result;

  const contradicting = known.filter((axis) => !overlap(axis.observed, claims[axis.dimension]));
  for (const axis of contradicting) {
    const claimedSubject = axis.dimension === 'engine' ? 'browser engine' : 'OS';
    result.detections.push({
      id: axis.id,
      reason: `${axis.subject} contradicts claimed ${claimedSubject} (${label(axis.dimension, claims[axis.dimension])})`,
    });
  }
  const disagree = known.some((a, i) => known.slice(i + 1).some(
    (b) => a.dimension === b.dimension && !overlap(a.observed, b.observed)));
  if (disagree) {
    result.detections.push({ id: 'identity-axes-disagree', reason: 'Measured properties disagree with each other' });
  } else if (contradicting.some((axis, i) => contradicting.slice(i + 1).some(
    (other) => axis.dimension === other.dimension && overlap(axis.observed, other.observed)))) {
    result.detections.push({
      id: 'identity-claim-contradicted',
      reason: 'Several measured properties agree with each other and contradict the claimed OS',
    });
  }
  result.status = result.detections.length > 0 ? 'detected' : 'clear';
  return result;
}

module.exports = { identityObservation, claimedOS, claimedEngine, IDENTITY_POLICY };
