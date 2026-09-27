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

const overlap = (a, b) => a.some((x) => b.includes(x));
const label = (set) => Object.keys(OS_LABELS).filter((os) => set.includes(os)).map((os) => OS_LABELS[os]).join('/');

function identityObservation(signals) {
  const result = { mode: 'observe', status: 'unknown', detections: [] };
  const env = signals?.environmental;
  const nav = env?.navigator;
  const touch = typeof nav?.maxTouchPoints === 'number' ? nav.maxTouchPoints : 0;
  const claim = claimedOS(nav?.userAgent, touch);
  if (!claim) return result;

  const known = [gpuBackendAxis(env), fontSetAxis(env)].filter((axis) => axis.observed);
  if (known.length === 0) return result;

  const contradicting = known.filter((axis) => !overlap(axis.observed, claim));
  for (const axis of contradicting) {
    result.detections.push({ id: axis.id, reason: `${axis.subject} contradicts claimed OS (${label(claim)})` });
  }
  const disagree = known.some((a, i) => known.slice(i + 1).some(
    (b) => a.dimension === b.dimension && !overlap(a.observed, b.observed)));
  if (disagree) {
    result.detections.push({ id: 'identity-axes-disagree', reason: 'Measured properties disagree with each other' });
  } else if (contradicting.length >= 2) {
    result.detections.push({
      id: 'identity-claim-contradicted',
      reason: 'Several measured properties agree with each other and contradict the claimed OS',
    });
  }
  result.status = result.detections.length > 0 ? 'detected' : 'clear';
  return result;
}

module.exports = { identityObservation, claimedOS, IDENTITY_POLICY };
