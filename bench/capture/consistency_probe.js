/* Research-only browser observations. Not loaded by the production client.
 * No detector scores or policy decisions are computed here. Missing APIs and
 * timeouts are explicit unknowns. Keep findings in the ignored research notes.
 */
(() => {
  'use strict';
  const REVISION = 'browser-consistency-v1';
  const outcome = (fn) => {
    try { return { status: 'ok', value: fn() }; }
    catch (error) { return { status: 'error', error: error.name }; }
  };
  const vector = (value) => ArrayBuffer.isView(value) ? Array.from(value) : value;

  function graphics(canvas, type) {
    if (!canvas) return { status: 'unsupported' };
    const gl = canvas.getContext(type);
    if (!gl) return { status: 'unavailable' };
    try {
      const names = ['VERSION', 'SHADING_LANGUAGE_VERSION', 'VENDOR', 'RENDERER',
        'MAX_TEXTURE_SIZE', 'MAX_CUBE_MAP_TEXTURE_SIZE', 'MAX_RENDERBUFFER_SIZE',
        'MAX_VIEWPORT_DIMS', 'MAX_VERTEX_ATTRIBS', 'MAX_TEXTURE_IMAGE_UNITS',
        'MAX_VERTEX_TEXTURE_IMAGE_UNITS', 'MAX_COMBINED_TEXTURE_IMAGE_UNITS'];
      const parameters = Object.fromEntries(names.map((name) => [name, vector(gl.getParameter(gl[name]))]));
      const debug = gl.getExtension('WEBGL_debug_renderer_info');
      if (debug) {
        parameters.unmaskedVendor = gl.getParameter(debug.UNMASKED_VENDOR_WEBGL);
        parameters.unmaskedRenderer = gl.getParameter(debug.UNMASKED_RENDERER_WEBGL);
      }
      const extensions = gl.getSupportedExtensions();
      const unavailableAdvertisedExtensions = extensions === null ? null
        : extensions.filter((name) => !gl.getExtension(name));
      const precision = {};
      for (const stage of ['VERTEX_SHADER', 'FRAGMENT_SHADER']) {
        const p = gl.getShaderPrecisionFormat(gl[stage], gl.HIGH_FLOAT);
        precision[stage] = p && { min: p.rangeMin, max: p.rangeMax, precision: p.precision };
      }
      gl.clearColor(0.25, 0.5, 0.75, 1);
      gl.clear(gl.COLOR_BUFFER_BIT);
      const pixel = new Uint8Array(4);
      gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixel);
      return { status: 'ok', parameters, extensions: extensions?.sort(),
        unavailableAdvertisedExtensions, precision, pixel: Array.from(pixel), error: gl.getError() };
    } finally {
      gl.getExtension('WEBGL_lose_context')?.loseContext();
    }
  }

  function textMetrics(canvas) {
    if (!canvas) return { status: 'unsupported' };
    const ctx = canvas.getContext('2d');
    if (!ctx) return { status: 'unavailable' };
    const result = {};
    for (const family of ['monospace', 'sans-serif', 'serif']) {
      ctx.font = `16px ${family}`;
      ctx.fontKerning = 'none';
      const text = 'Browser measurement 0123456789';
      const measurements = Array.from({ length: 3 }, () => {
        const m = ctx.measureText(text);
        return { width: m.width, left: m.actualBoundingBoxLeft, right: m.actualBoundingBoxRight,
          ascent: m.actualBoundingBoxAscent, descent: m.actualBoundingBoxDescent };
      });
      result[family] = measurements;
    }
    return { status: 'ok', metrics: result };
  }

  function common() {
    const n = navigator;
    const navigatorData = {};
    for (const name of ['userAgent', 'platform', 'hardwareConcurrency', 'language',
      'languages', 'deviceMemory', 'maxTouchPoints', 'oscpu', 'vendor']) {
      navigatorData[name] = outcome(() => n[name] === undefined ? null : n[name]);
    }
    const offscreen = () => typeof OffscreenCanvas === 'function' ? new OffscreenCanvas(32, 32) : null;
    return {
      navigator: navigatorData,
      timezone: outcome(() => Intl.DateTimeFormat().resolvedOptions().timeZone),
      offscreenWebgl: outcome(() => graphics(offscreen(), 'webgl')),
      offscreenWebgl2: outcome(() => graphics(offscreen(), 'webgl2')),
      offscreenText: outcome(() => textMetrics(offscreen())),
    };
  }

  function animationObservations() {
    if (typeof Element.prototype.animate !== 'function') return { status: 'unsupported' };
    const element = document.createElement('div');
    element.style.cssText = 'position:fixed;left:-1000px;top:0;width:10px;height:10px;visibility:hidden';
    document.body.append(element);
    try {
      const tests = {};
      for (const [name, iterations] of [['finite', 1], ['repeated', 3], ['infinite', Infinity]]) {
        const animation = element.animate([{ opacity: 0.2 }, { opacity: 0.8 }], {
          duration: 1000, iterations, fill: 'both', easing: 'linear',
        });
        try {
          animation.pause();
          const samples = [];
          for (const t of [0, 250, 500, 750]) {
            animation.currentTime = t;
            const computed = animation.effect.getComputedTiming();
            samples.push({ currentTime: t, duration: computed.duration,
              activeDuration: Number.isFinite(computed.activeDuration) ? computed.activeDuration : 'Infinity',
              progress: computed.progress, currentIteration: computed.currentIteration });
          }
          tests[name] = { specifiedDuration: animation.effect.getTiming().duration, samples };
        } finally {
          animation.cancel();
        }
      }
      return { status: 'ok', tests, reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches };
    } finally { element.remove(); }
  }

  function pageObservations() {
    const canvas = () => { const c = document.createElement('canvas'); c.width = c.height = 32; return c; };
    return { ...common(),
      htmlWebgl: outcome(() => graphics(canvas(), 'webgl')),
      htmlWebgl2: outcome(() => graphics(canvas(), 'webgl2')),
      htmlText: outcome(() => textMetrics(canvas())),
      animation: outcome(animationObservations),
      screen: outcome(() => ({ width: screen.width, height: screen.height,
        availWidth: screen.availWidth, availHeight: screen.availHeight,
        devicePixelRatio, innerWidth, innerHeight,
        cssDeviceWidthMatches: matchMedia(`(device-width: ${screen.width}px)`).matches,
        cssResolutionMatches: matchMedia(`(resolution: ${devicePixelRatio}dppx)`).matches })),
    };
  }

  function workerSnapshot(nested = false) {
    return new Promise((resolve) => {
      if (typeof Worker !== 'function') return resolve({ status: 'unsupported' });
      let worker;
      let timer;
      const finish = (value) => { clearTimeout(timer); worker?.terminate(); resolve(value); };
      try {
        worker = new Worker('/__research/probe.js?worker');
        timer = setTimeout(() => finish({ status: 'timeout' }), 6000);
        worker.onmessage = (event) => finish({ status: 'ok', value: event.data });
        worker.onerror = () => finish({ status: 'error' });
        worker.postMessage({ nested });
      } catch (error) { finish({ status: 'error', error: error.name }); }
    });
  }

  if (typeof document === 'undefined') {
    self.onmessage = async ({ data }) => {
      const value = common();
      if (data.nested) value.nestedWorker = await workerSnapshot(false);
      self.postMessage(value);
    };
    return;
  }

  if (location.pathname === '/__research/frame') {
    window.addEventListener('message', ({ source, data }) => {
      if (source !== parent || data !== 'collect-browser-observations') return;
      parent.postMessage({ kind: 'browser-observations', value: pageObservations() }, location.origin);
    }, { once: true });
    return;
  }

  async function frameSnapshot() {
    return new Promise((resolve) => {
      const frame = document.createElement('iframe');
      frame.style.cssText = 'position:fixed;left:-2000px;top:0;width:600px;height:400px';
      let timer;
      const finish = (value) => {
        clearTimeout(timer); window.removeEventListener('message', onMessage); frame.remove(); resolve(value);
      };
      const onMessage = (event) => {
        if (event.source === frame.contentWindow && event.origin === location.origin && event.data?.kind === 'browser-observations') {
          finish({ status: 'ok', value: event.data.value });
        }
      };
      window.addEventListener('message', onMessage);
      timer = setTimeout(() => finish({ status: 'timeout' }), 6000);
      frame.onload = () => frame.contentWindow.postMessage('collect-browser-observations', location.origin);
      frame.src = '/__research/frame';
      document.body.append(frame);
    });
  }

  // Called by the local page after scoring has completed, never by an
  // automation-world evaluate call. This keeps Camoufox's isolated world out
  // of the observation and prevents probes changing the scored interaction.
  window.collectBrowserObservations = async () => {
    const main = pageObservations();
    const iframe = await frameSnapshot();
    const worker = await workerSnapshot(true);
    return { revision: REVISION, main, iframe, worker };
  };

  window.startBrowserObservationCapture = () => {
    const observer = new PerformanceObserver(async (list) => {
      if (!list.getEntries().some((entry) => ['/api/score', '/api/verify'].includes(new URL(entry.name).pathname))) return;
      observer.disconnect();
      const status = document.createElement('p');
      status.textContent = 'Collecting research observations…';
      document.querySelector('#result').after(status);
      let data;
      try { data = await window.collectBrowserObservations(); }
      catch (error) { data = { revision: REVISION, status: 'error', error: error.name }; }
      try {
        const response = await fetch('/__research/observations', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
        });
        status.textContent = response.ok ? 'Research observations saved.' : 'Research capture failed.';
      } catch { status.textContent = 'Research capture failed.'; }
    });
    observer.observe({ type: 'resource', buffered: true });
  };
})();
