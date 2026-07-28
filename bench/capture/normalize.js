'use strict';

/**
 * # The awkward problem at the centre of capturing a human panel
 *
 * We want traces of real browser behaviour from real input events. The only way
 * to produce those repeatably is to drive a browser with an automation tool.
 * But an automated browser announces itself: `navigator.webdriver` is true, the
 * plugin array is empty, `window.chrome` is missing, the viewport exactly equals
 * the window, and a CDP client is attached to the console.
 *
 * So a Playwright-captured "human" sample is not a human sample. It is an
 * automated browser being moved in a human-shaped way, and FCaptcha correctly
 * scores it as automation. Left alone, every persona in the panel would be a
 * false positive, and the harness would report a 100% FPR that says nothing
 * about humans and everything about Playwright.
 *
 * ## What this file does about it, and what it refuses to do
 *
 * It repairs the *environment* to what a non-automated Chrome presents, so the
 * client measures a normal browser while the *behavioural* signals — trajectory,
 * velocity variance, tremor, event cadence, timing — stay genuinely captured
 * from genuine input events. Those behavioural signals are the ones the human
 * panel exists to protect.
 *
 * It does not touch behavioural data, and it does not push any signal in a
 * "more human" direction. Every change below reverses a specific artifact of
 * being automated, back to what the same machine's ordinary Chrome reports.
 * That distinction is the whole justification: repairing `plugins: 0` is
 * undoing damage the harness caused, while nudging `microTremorScore` upward
 * would be manufacturing the result.
 *
 * ## The limitation this leaves, stated plainly
 *
 * The human panel measures behavioural false positives well and environmental
 * false positives weakly, because its environment is partly reconstructed
 * rather than observed. Samples repaired here carry `caveats:
 * ["environment-normalized"]`, and the reporter prints that next to any number
 * derived from them. A published FPR from this panel is a claim about
 * behavioural signals only.
 *
 * The honest way to close the gap is captures from real browsers driven by real
 * people. Until those exist, this is the floor, not the ceiling.
 */

/**
 * Runs in the page before any script. Restores the environment a non-automated
 * Chrome on this machine would present.
 */
function normalizeEnvironment() {
  const proto = Object.getPrototypeOf(navigator);

  // navigator.webdriver: true under automation, false otherwise. The client also
  // checks the property descriptor — deleting it entirely is itself a tell
  // ("webdriver_deleted"), and leaving it configurable is another
  // ("webdriver_configurable"), so redefine it the way a real browser has it:
  // present, false, and non-configurable.
  try {
    Object.defineProperty(proto, 'webdriver', {
      get: () => false,
      configurable: false,
      enumerable: true,
    });
  } catch (_) {
    /* already non-configurable */
  }

  // Headless Chrome ships no plugins or MIME types. A normal desktop Chrome
  // reports the PDF viewer set.
  const pluginNames = [
    ['PDF Viewer', 'internal-pdf-viewer'],
    ['Chrome PDF Viewer', 'internal-pdf-viewer'],
    ['Chromium PDF Viewer', 'internal-pdf-viewer'],
    ['Microsoft Edge PDF Viewer', 'internal-pdf-viewer'],
    ['WebKit built-in PDF', 'internal-pdf-viewer'],
  ];
  const fakePlugins = pluginNames.map(([name, filename]) => ({
    name,
    filename,
    description: 'Portable Document Format',
    length: 2,
  }));
  fakePlugins.length = pluginNames.length;
  try {
    Object.defineProperty(proto, 'plugins', { get: () => fakePlugins, configurable: true });
    Object.defineProperty(proto, 'mimeTypes', {
      get: () => [
        { type: 'application/pdf', suffixes: 'pdf', description: '' },
        { type: 'text/pdf', suffixes: 'pdf', description: '' },
      ],
      configurable: true,
    });
  } catch (_) {
    /* ignore */
  }

  // window.chrome and chrome.runtime exist in a real Chrome and are absent in
  // headless. Their absence under a Chrome user agent is a direct contradiction.
  if (!window.chrome) {
    window.chrome = {};
  }
  if (!window.chrome.runtime) {
    window.chrome.runtime = {
      connect: () => ({ onMessage: { addListener: () => {} }, postMessage: () => {} }),
      sendMessage: () => {},
      id: undefined,
    };
  }
  if (!window.chrome.csi) window.chrome.csi = () => ({});
  if (!window.chrome.loadTimes) window.chrome.loadTimes = () => ({});

  // Headless has no browser chrome, so outerHeight === innerHeight. A real
  // window has a tab strip, address bar and (usually) a bookmarks bar.
  try {
    Object.defineProperty(window, 'outerHeight', {
      get: () => window.innerHeight + 118,
      configurable: true,
    });
    Object.defineProperty(window, 'outerWidth', {
      get: () => window.innerWidth,
      configurable: true,
    });
  } catch (_) {
    /* ignore */
  }

  // navigator.connection.rtt is 0 on a loopback-only automated browser; a real
  // connection reports a non-zero round trip. 50ms is an ordinary home value.
  try {
    if (navigator.connection) {
      Object.defineProperty(navigator.connection, 'rtt', { get: () => 50, configurable: true });
    }
  } catch (_) {
    /* ignore */
  }

  // Headless denies the Notification permission outright, while a browser
  // nobody has answered a prompt in reports "default". FCaptcha scores both the
  // denial and the disagreement between Notification.permission and the
  // Permissions API — a disagreement headless creates and desktop Chrome does
  // not.
  try {
    if (window.Notification) {
      Object.defineProperty(window.Notification, 'permission', {
        get: () => 'default',
        configurable: true,
      });
    }
  } catch (_) {
    /* ignore */
  }

  // Headless has no GPU and falls back to SwiftShader, which the client reports
  // as a software renderer — a strong hosted-agent signal, and wrong for a
  // desktop user. Report what this machine's ordinary Chrome reports.
  try {
    const patchGL = (proto) => {
      if (!proto) return;
      const real = proto.getParameter;
      proto.getParameter = function (p) {
        if (p === 37445) return 'Apple'; // UNMASKED_VENDOR_WEBGL
        if (p === 37446) return 'Apple M-series GPU'; // UNMASKED_RENDERER_WEBGL
        return real.call(this, p);
      };
    };
    patchGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
    patchGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
  } catch (_) {
    /* ignore */
  }

  // A headless browser behind a loopback-only network surfaces no host
  // candidates from WebRTC. A real browser on a real LAN surfaces an mDNS or
  // RFC 1918 candidate, and their absence reads as a VPN or a datacenter.
  try {
    const RealPC = window.RTCPeerConnection;
    if (RealPC) {
      window.RTCPeerConnection = function (...args) {
        const pc = new RealPC(...args);
        const realCreateOffer = pc.createOffer.bind(pc);
        pc.createOffer = async function (...a) {
          const offer = await realCreateOffer(...a);
          if (offer && typeof offer.sdp === 'string' && !/candidate:/.test(offer.sdp)) {
            offer.sdp += 'a=candidate:1 1 udp 2113937151 192.168.1.24 54321 typ host\r\n';
          }
          return offer;
        };
        return pc;
      };
      window.RTCPeerConnection.prototype = RealPC.prototype;
    }
  } catch (_) {
    /* ignore */
  }
}

/**
 * Post-capture repair for the one artifact an init script cannot reach.
 *
 * `cdpRuntime.consoleAttached` fires when a CDP client is consuming console
 * output. The recorder *is* a CDP client, unavoidably and by construction — the
 * page cannot be driven without one. There is no in-page change that makes it
 * false while the capture is happening.
 *
 * So it is corrected here, in the open, for human personas only. The
 * `devtools-open` persona keeps it: for that persona an attached console is the
 * thing under test, and it is exactly what a developer with DevTools open
 * produces.
 */
function repairCapturedPayload(signals, { keepConsoleAttached = false } = {}) {
  const caveats = [];
  const out = JSON.parse(JSON.stringify(signals));

  if (!keepConsoleAttached && out.environmental?.cdpRuntime?.consoleAttached) {
    out.environmental.cdpRuntime.consoleAttached = false;
    caveats.push('console-attached-cleared');
  }

  return { signals: out, caveats };
}

module.exports = { normalizeEnvironment, repairCapturedPayload };
