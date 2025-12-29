/**
 * FCaptcha - Open Source CAPTCHA
 *
 * Detects bots, vision AI agents, headless browsers, and automation frameworks
 * through behavioral analysis, environmental fingerprinting, and temporal signals.
 *
 * MIT License
 */

(function(window) {
  'use strict';

  const FCaptcha = {
    version: '1.0.0',
    widgets: new Map(),
    serverUrl: null,
  };

  // ============================================================
  // Behavioral Signal Collector
  // ============================================================

  class BehavioralCollector {
    constructor() {
      this.mousePositions = [];
      this.mouseVelocities = [];
      this.mouseAccelerations = [];
      this.scrollEvents = [];
      this.keyEvents = [];
      this.touchEvents = [];
      this.focusEvents = [];
      this.clickData = null;
      this.startTime = Date.now();
      this.lastMousePos = null;
      this.lastMouseTime = null;
      this.lastVelocity = null;
      this.eventDeltas = [];
    }

    recordMouseMove(e) {
      const now = performance.now();
      const pos = { x: e.clientX, y: e.clientY, t: now };

      this.mousePositions.push(pos);

      // Calculate velocity and acceleration
      if (this.lastMousePos && this.lastMouseTime) {
        const dt = now - this.lastMouseTime;
        if (dt > 0) {
          const dx = e.clientX - this.lastMousePos.x;
          const dy = e.clientY - this.lastMousePos.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          const velocity = distance / dt;

          this.mouseVelocities.push({ v: velocity, t: now });
          this.eventDeltas.push(dt);

          if (this.lastVelocity !== null) {
            const acceleration = (velocity - this.lastVelocity) / dt;
            this.mouseAccelerations.push({ a: acceleration, t: now });
          }
          this.lastVelocity = velocity;
        }
      }

      this.lastMousePos = { x: e.clientX, y: e.clientY };
      this.lastMouseTime = now;

      // Limit memory usage
      if (this.mousePositions.length > 500) {
        this.mousePositions.shift();
        if (this.mouseVelocities.length > 500) this.mouseVelocities.shift();
        if (this.mouseAccelerations.length > 500) this.mouseAccelerations.shift();
      }
    }

    recordMouseDown(e) {
      this.clickData = {
        x: e.clientX,
        y: e.clientY,
        button: e.button,
        downTime: performance.now()
      };
    }

    recordMouseUp(e) {
      if (this.clickData) {
        this.clickData.upTime = performance.now();
        this.clickData.holdDuration = this.clickData.upTime - this.clickData.downTime;
      }
    }

    recordScroll(e) {
      this.scrollEvents.push({
        x: window.scrollX,
        y: window.scrollY,
        t: performance.now()
      });
      if (this.scrollEvents.length > 100) this.scrollEvents.shift();
    }

    recordKeyEvent(e) {
      this.keyEvents.push({
        type: e.type,
        keyLength: e.key ? e.key.length : 0, // Don't store actual keys
        t: performance.now()
      });
    }

    recordTouch(e) {
      const touch = e.touches[0] || e.changedTouches[0];
      if (touch) {
        this.touchEvents.push({
          x: touch.clientX,
          y: touch.clientY,
          t: performance.now()
        });
      }
    }

    recordFocus(e) {
      this.focusEvents.push({
        type: e.type,
        target: e.target?.tagName,
        t: performance.now()
      });
    }

    analyze() {
      const positions = this.mousePositions;
      const velocities = this.mouseVelocities;
      const accelerations = this.mouseAccelerations;

      if (positions.length < 10) {
        return this._getEmptyAnalysis();
      }

      // Velocity statistics
      let avgVelocity = 0;
      let velocityVariance = 0;
      if (velocities.length > 0) {
        const sum = velocities.reduce((acc, v) => acc + v.v, 0);
        avgVelocity = sum / velocities.length;
        velocityVariance = velocities.reduce((acc, v) => {
          return acc + Math.pow(v.v - avgVelocity, 2);
        }, 0) / velocities.length;
      }

      // Acceleration statistics
      let avgAcceleration = 0;
      let accelerationChanges = 0;
      if (accelerations.length > 0) {
        avgAcceleration = accelerations.reduce((acc, a) => acc + a.a, 0) / accelerations.length;
        for (let i = 1; i < accelerations.length; i++) {
          if (Math.sign(accelerations[i].a) !== Math.sign(accelerations[i-1].a)) {
            accelerationChanges++;
          }
        }
      }

      // Micro-tremor detection (high-frequency noise - humans shake at 3-25Hz)
      const microTremorScore = this._detectMicroTremor(positions);

      // Straight line ratio (bots often move in straight lines)
      const straightLineRatio = this._calculateStraightLineRatio(positions);

      // Micro-movements (small jitters that humans make)
      let microMovements = 0;
      for (let i = 1; i < positions.length; i++) {
        const dx = Math.abs(positions[i].x - positions[i-1].x);
        const dy = Math.abs(positions[i].y - positions[i-1].y);
        if (dx < 3 && dy < 3 && (dx > 0 || dy > 0)) {
          microMovements++;
        }
      }

      // Direction changes
      const directionChanges = this._countDirectionChanges(positions);

      // Event timing variance
      const eventDeltaVariance = this._variance(this.eventDeltas);
      const mouseEventRate = positions.length > 1 ?
        positions.length / ((positions[positions.length-1].t - positions[0].t) / 1000) : 0;

      // Calculate trajectory length
      let trajectoryLength = 0;
      for (let i = 1; i < positions.length; i++) {
        const dx = positions[i].x - positions[i-1].x;
        const dy = positions[i].y - positions[i-1].y;
        trajectoryLength += Math.sqrt(dx*dx + dy*dy);
      }

      return {
        totalPoints: positions.length,
        trajectoryLength,
        avgVelocity,
        velocityVariance,
        avgAcceleration,
        accelerationChanges,
        microTremorScore,
        straightLineRatio,
        microMovements,
        directionChanges,
        eventDeltas: this.eventDeltas.slice(-50),
        eventDeltaVariance,
        mouseEventRate,
        scrollEvents: this.scrollEvents.length,
        keyEvents: this.keyEvents.length,
        touchEvents: this.touchEvents.length,
        focusEvents: this.focusEvents.length,
        clickData: this.clickData,
        interactionDuration: Date.now() - this.startTime
      };
    }

    analyzeClick(clickX, clickY, targetRect) {
      const positions = this.mousePositions;
      if (positions.length < 5) {
        return this._getEmptyClickAnalysis();
      }

      // Approach trajectory (last 20 points)
      const approachPoints = positions.slice(-20);

      // Click precision (distance from target center)
      const targetCenterX = targetRect.left + targetRect.width / 2;
      const targetCenterY = targetRect.top + targetRect.height / 2;
      const clickPrecision = Math.sqrt(
        Math.pow(clickX - targetCenterX, 2) +
        Math.pow(clickY - targetCenterY, 2)
      );

      // Exploration ratio (movement outside target area)
      let outsideMovement = 0;
      let totalMovement = 0;

      for (let i = 1; i < positions.length; i++) {
        const dist = Math.sqrt(
          Math.pow(positions[i].x - positions[i-1].x, 2) +
          Math.pow(positions[i].y - positions[i-1].y, 2)
        );
        totalMovement += dist;

        const inTarget = (
          positions[i].x >= targetRect.left &&
          positions[i].x <= targetRect.right &&
          positions[i].y >= targetRect.top &&
          positions[i].y <= targetRect.bottom
        );
        if (!inTarget) outsideMovement += dist;
      }

      const explorationRatio = totalMovement > 0 ? outsideMovement / totalMovement : 0;

      // Overshoot detection
      let overshoots = 0;
      let wasInTarget = false;
      let passedTarget = false;

      for (const point of approachPoints) {
        const inTarget = (
          point.x >= targetRect.left &&
          point.x <= targetRect.right &&
          point.y >= targetRect.top &&
          point.y <= targetRect.bottom
        );

        if (wasInTarget && !inTarget) passedTarget = true;
        if (passedTarget && inTarget) {
          overshoots++;
          passedTarget = false;
        }
        wasInTarget = inTarget;
      }

      // Hover time before click
      let hoverTime = 0;
      for (let i = approachPoints.length - 1; i >= 0; i--) {
        const point = approachPoints[i];
        const inTarget = (
          point.x >= targetRect.left &&
          point.x <= targetRect.right &&
          point.y >= targetRect.top &&
          point.y <= targetRect.bottom
        );
        if (inTarget && i < approachPoints.length - 1) {
          hoverTime = approachPoints[approachPoints.length - 1].t - point.t;
        } else if (!inTarget) {
          break;
        }
      }

      // Approach directness
      const directDistance = Math.sqrt(
        Math.pow(approachPoints[approachPoints.length-1].x - approachPoints[0].x, 2) +
        Math.pow(approachPoints[approachPoints.length-1].y - approachPoints[0].y, 2)
      );
      let approachPathLength = 0;
      for (let i = 1; i < approachPoints.length; i++) {
        approachPathLength += Math.sqrt(
          Math.pow(approachPoints[i].x - approachPoints[i-1].x, 2) +
          Math.pow(approachPoints[i].y - approachPoints[i-1].y, 2)
        );
      }
      const approachDirectness = approachPathLength > 0 ? directDistance / approachPathLength : 1;

      return {
        clickPrecision,
        explorationRatio,
        overshootCorrections: overshoots,
        hoverTime,
        approachDirectness,
        approachPoints: approachPoints.length
      };
    }

    _detectMicroTremor(positions) {
      if (positions.length < 20) return 0.5;

      const windowSize = 5;
      let totalNoise = 0;

      for (let i = windowSize; i < positions.length - windowSize; i++) {
        let smoothX = 0, smoothY = 0;
        for (let j = i - windowSize; j <= i + windowSize; j++) {
          smoothX += positions[j].x;
          smoothY += positions[j].y;
        }
        smoothX /= (windowSize * 2 + 1);
        smoothY /= (windowSize * 2 + 1);

        const deviation = Math.sqrt(
          Math.pow(positions[i].x - smoothX, 2) +
          Math.pow(positions[i].y - smoothY, 2)
        );
        totalNoise += deviation;
      }

      const avgNoise = totalNoise / (positions.length - windowSize * 2);
      return Math.min(1, avgNoise / 2);
    }

    _calculateStraightLineRatio(positions) {
      if (positions.length < 3) return 0;

      let straightSegments = 0;
      let totalSegments = 0;

      for (let i = 2; i < positions.length; i++) {
        const p1 = positions[i-2];
        const p2 = positions[i-1];
        const p3 = positions[i];

        const angle1 = Math.atan2(p2.y - p1.y, p2.x - p1.x);
        const angle2 = Math.atan2(p3.y - p2.y, p3.x - p2.x);
        const angleDiff = Math.abs(angle2 - angle1);

        totalSegments++;
        if (angleDiff < 0.1) straightSegments++;
      }

      return totalSegments > 0 ? straightSegments / totalSegments : 0;
    }

    _countDirectionChanges(positions) {
      let changes = 0;
      for (let i = 2; i < positions.length; i++) {
        const angle1 = Math.atan2(
          positions[i-1].y - positions[i-2].y,
          positions[i-1].x - positions[i-2].x
        );
        const angle2 = Math.atan2(
          positions[i].y - positions[i-1].y,
          positions[i].x - positions[i-1].x
        );
        if (Math.abs(angle2 - angle1) > Math.PI / 6) changes++;
      }
      return changes;
    }

    _variance(arr) {
      if (arr.length === 0) return 0;
      const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
      return arr.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / arr.length;
    }

    _getEmptyAnalysis() {
      return {
        totalPoints: 0, trajectoryLength: 0, avgVelocity: 0, velocityVariance: 0,
        avgAcceleration: 0, accelerationChanges: 0, microTremorScore: 0.5,
        straightLineRatio: 0, microMovements: 0, directionChanges: 0,
        eventDeltas: [], eventDeltaVariance: 0, mouseEventRate: 0,
        scrollEvents: 0, keyEvents: 0, touchEvents: 0, focusEvents: 0,
        clickData: null, interactionDuration: 0
      };
    }

    _getEmptyClickAnalysis() {
      return {
        clickPrecision: 0, explorationRatio: 0, overshootCorrections: 0,
        hoverTime: 0, approachDirectness: 1, approachPoints: 0
      };
    }
  }

  // ============================================================
  // Form Interaction Analyzer (Credential Stuffing & Spam Detection)
  // ============================================================

  class FormAnalyzer {
    constructor() {
      this.pageLoadTime = performance.now();
      this.firstInteractionTime = null;
      this.lastInteractionTime = null;
      this.totalEvents = 0;
      this.eventLog = []; // Recent events before submit
      this.textareaStats = new Map(); // Per-textarea keyboard analysis
      this.submitData = null;

      this._setupListeners();
    }

    _setupListeners() {
      // Track first and ongoing interactions
      const interactionEvents = ['mousedown', 'keydown', 'touchstart', 'scroll'];
      interactionEvents.forEach(eventType => {
        document.addEventListener(eventType, (e) => this._recordInteraction(e), { passive: true });
      });

      // Track textarea keyboard patterns (spam detection)
      document.addEventListener('keydown', (e) => this._recordTextareaKey(e), { passive: true });
      document.addEventListener('keyup', (e) => this._recordTextareaKey(e), { passive: true });

      // Track form submissions
      document.addEventListener('submit', (e) => this._recordSubmit(e), { capture: true });

      // Track programmatic submit detection
      this._interceptFormSubmit();
    }

    _recordInteraction(e) {
      const now = performance.now();

      if (this.firstInteractionTime === null) {
        this.firstInteractionTime = now;
      }
      this.lastInteractionTime = now;
      this.totalEvents++;

      // Keep last 50 events for analysis
      this.eventLog.push({
        type: e.type,
        time: now,
        target: e.target?.tagName || 'unknown'
      });
      if (this.eventLog.length > 50) {
        this.eventLog.shift();
      }
    }

    _recordTextareaKey(e) {
      // Only analyze textareas (safe from password manager conflicts)
      if (e.target?.tagName !== 'TEXTAREA') return;

      const textareaId = e.target.id || e.target.name || 'unnamed';
      if (!this.textareaStats.has(textareaId)) {
        this.textareaStats.set(textareaId, {
          keydowns: [],
          keyups: [],
          intervals: [],
          lastKeyTime: null,
          inputWithoutKey: 0,
          pasteCount: 0
        });
      }

      const stats = this.textareaStats.get(textareaId);
      const now = performance.now();

      if (e.type === 'keydown') {
        stats.keydowns.push(now);
        if (stats.lastKeyTime !== null) {
          stats.intervals.push(now - stats.lastKeyTime);
        }
        stats.lastKeyTime = now;

        // Limit memory
        if (stats.keydowns.length > 200) stats.keydowns.shift();
        if (stats.intervals.length > 200) stats.intervals.shift();
      } else if (e.type === 'keyup') {
        stats.keyups.push(now);
        if (stats.keyups.length > 200) stats.keyups.shift();
      }
    }

    _interceptFormSubmit() {
      // Detect programmatic form.submit() calls
      const self = this;
      const originalSubmit = HTMLFormElement.prototype.submit;

      HTMLFormElement.prototype.submit = function() {
        self._recordProgrammaticSubmit(this);
        return originalSubmit.apply(this, arguments);
      };
    }

    _recordProgrammaticSubmit(form) {
      const now = performance.now();
      this.submitData = {
        method: 'programmatic', // form.submit() called directly
        time: now,
        timeSincePageLoad: now - this.pageLoadTime,
        timeSinceFirstInteraction: this.firstInteractionTime ? now - this.firstInteractionTime : null,
        timeSinceLastInteraction: this.lastInteractionTime ? now - this.lastInteractionTime : null,
        eventsBeforeSubmit: this.totalEvents,
        hadTriggerEvent: false
      };
    }

    _recordSubmit(e) {
      const now = performance.now();

      // Check what triggered the submit
      const lastEvents = this.eventLog.slice(-5);
      const recentKeydown = lastEvents.find(ev => ev.type === 'keydown' && now - ev.time < 100);
      const recentMousedown = lastEvents.find(ev => ev.type === 'mousedown' && now - ev.time < 100);

      let method = 'unknown';
      if (recentKeydown) {
        method = 'keyboard'; // Enter key or similar
      } else if (recentMousedown) {
        method = 'mouse'; // Mouse click
      } else if (!this.submitData) {
        // No recent user event and not programmatic - likely programmatic click()
        method = 'programmatic_click';
      }

      // Don't overwrite if already recorded by intercepted submit()
      if (!this.submitData || this.submitData.method === 'programmatic') {
        this.submitData = {
          method,
          time: now,
          timeSincePageLoad: now - this.pageLoadTime,
          timeSinceFirstInteraction: this.firstInteractionTime ? now - this.firstInteractionTime : null,
          timeSinceLastInteraction: this.lastInteractionTime ? now - this.lastInteractionTime : null,
          eventsBeforeSubmit: this.totalEvents,
          hadTriggerEvent: method === 'keyboard' || method === 'mouse'
        };
      }
    }

    analyze() {
      const now = performance.now();

      // Textarea analysis (spam detection)
      const textareaAnalysis = {};
      this.textareaStats.forEach((stats, id) => {
        const intervals = stats.intervals;
        let avgInterval = 0;
        let intervalVariance = 0;

        if (intervals.length > 0) {
          avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
          intervalVariance = intervals.reduce((acc, i) => acc + Math.pow(i - avgInterval, 2), 0) / intervals.length;
        }

        textareaAnalysis[id] = {
          keyCount: stats.keydowns.length,
          avgKeyInterval: avgInterval,
          keyIntervalVariance: intervalVariance,
          keydownUpRatio: stats.keyups.length > 0 ? stats.keydowns.length / stats.keyups.length : 0,
          pasteCount: stats.pasteCount
        };
      });

      // Check for textareas with content but no keyboard events (DOM manipulation)
      const textareas = document.querySelectorAll('textarea');
      textareas.forEach(ta => {
        const id = ta.id || ta.name || 'unnamed';
        const contentLength = (ta.value || '').length;

        if (contentLength > 0) {
          if (!textareaAnalysis[id]) {
            // Textarea has content but we never saw any keyboard events - DOM manipulation!
            textareaAnalysis[id] = {
              keyCount: 0,
              avgKeyInterval: 0,
              keyIntervalVariance: 0,
              keydownUpRatio: 0,
              pasteCount: 0,
              contentLength: contentLength,
              noKeyboardEvents: true // Flag for server-side detection
            };
          } else {
            // Add content length for comparison
            textareaAnalysis[id].contentLength = contentLength;
            textareaAnalysis[id].noKeyboardEvents = textareaAnalysis[id].keyCount === 0;
          }
        }
      });

      return {
        // Timing signals
        pageLoadToFirstInteraction: this.firstInteractionTime ? this.firstInteractionTime - this.pageLoadTime : null,
        pageLoadToNow: now - this.pageLoadTime,
        totalInteractionEvents: this.totalEvents,

        // Submit analysis (credential stuffing detection)
        submit: this.submitData || {
          method: 'none',
          eventsBeforeSubmit: this.totalEvents,
          hadTriggerEvent: false
        },

        // Textarea analysis (spam detection)
        textareaKeyboard: Object.keys(textareaAnalysis).length > 0 ? textareaAnalysis : null
      };
    }

    // Track paste events on textareas
    recordPaste(e) {
      if (e.target?.tagName !== 'TEXTAREA') return;

      const textareaId = e.target.id || e.target.name || 'unnamed';
      if (this.textareaStats.has(textareaId)) {
        this.textareaStats.get(textareaId).pasteCount++;
      }
    }
  }

  // Global form analyzer instance - initialize immediately to capture all events
  let globalFormAnalyzer = null;
  function getFormAnalyzer() {
    if (!globalFormAnalyzer) {
      globalFormAnalyzer = new FormAnalyzer();
      // Also track paste events
      document.addEventListener('paste', (e) => globalFormAnalyzer.recordPaste(e), { passive: true });
    }
    return globalFormAnalyzer;
  }

  // Initialize immediately when script loads
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => getFormAnalyzer());
    } else {
      getFormAnalyzer();
    }
  }

  // ============================================================
  // Environmental Signal Collector
  // ============================================================

  class EnvironmentalCollector {
    collect() {
      return {
        // Comprehensive automation detection
        webdriver: this._detectWebdriver(),
        automationFlags: this._getAutomationFlags(),

        // Browser fingerprints
        canvasHash: this._getCanvasHash(),
        webglInfo: this._getWebGLInfo(),
        audioInfo: this._getAudioInfo(),

        // Headless detection
        headlessIndicators: this._getHeadlessIndicators(),

        // System info
        screen: this._getScreenInfo(),
        navigator: this._getNavigatorInfo(),

        // Timing fingerprints
        jsExecutionTime: this._measureJSExecution(),
      };
    }

    _detectWebdriver() {
      return !!(
        navigator.webdriver ||
        window.document.__webdriver_evaluate ||
        window.document.__selenium_evaluate ||
        window.document.__webdriver_script_fn ||
        window.document.__webdriver_script_func ||
        window.document.__webdriver_script_function ||
        window.document['$cdc_asdjflasutopfhvcZLmcfl_'] ||
        window.document['$wdc_'] ||
        window['_Selenium_IDE_Recorder'] ||
        window['_phantom'] ||
        window['__nightmare'] ||
        window.callPhantom ||
        window._phantom
      );
    }

    _getAutomationFlags() {
      return {
        // Core automation
        webdriver: !!navigator.webdriver,
        domAutomation: !!window.domAutomation,
        domAutomationController: !!window.domAutomationController,

        // Selenium
        _selenium: !!window._selenium,
        __webdriver_script_fn: !!window.__webdriver_script_fn,
        __driver_evaluate: !!window.__driver_evaluate,
        __webdriver_evaluate: !!window.__webdriver_evaluate,
        __fxdriver_evaluate: !!window.__fxdriver_evaluate,
        __driver_unwrapped: !!window.__driver_unwrapped,
        __webdriver_unwrapped: !!window.__webdriver_unwrapped,
        __fxdriver_unwrapped: !!window.__fxdriver_unwrapped,
        _Selenium_IDE_Recorder: !!window._Selenium_IDE_Recorder,
        calledSelenium: !!window.calledSelenium,
        $chrome_asyncScriptInfo: !!window.$chrome_asyncScriptInfo,
        $cdc_asdjflasutopfhvcZLmcfl_: !!window.$cdc_asdjflasutopfhvcZLmcfl_,

        // PhantomJS
        _phantom: !!window._phantom,
        callPhantom: !!window.callPhantom,

        // Nightmare
        __nightmare: !!window.__nightmare,

        // Watir
        __lastWatirAlert: !!window.__lastWatirAlert,
        __lastWatirConfirm: !!window.__lastWatirConfirm,
        __lastWatirPrompt: !!window.__lastWatirPrompt,

        // Browser properties
        plugins: navigator.plugins ? navigator.plugins.length : 0,
        languages: navigator.languages && navigator.languages.length > 0,
        mimeTypes: navigator.mimeTypes ? navigator.mimeTypes.length : 0,
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack,

        // Chrome specific
        chrome: !!window.chrome,
        chromeRuntime: !!(window.chrome && window.chrome.runtime && window.chrome.runtime.id),

        // Permissions API
        permissionsAPI: !!navigator.permissions
      };
    }

    _getCanvasHash() {
      try {
        const canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 50;
        const ctx = canvas.getContext('2d');

        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('FCaptcha', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('FCaptcha', 4, 17);

        const dataUrl = canvas.toDataURL();
        let hash = 0;
        for (let i = 0; i < dataUrl.length; i++) {
          hash = ((hash << 5) - hash) + dataUrl.charCodeAt(i);
          hash = hash & hash;
        }
        return { hash: hash.toString(16), dataLength: dataUrl.length, supported: true };
      } catch (e) {
        return { error: true, supported: false };
      }
    }

    _getWebGLInfo() {
      try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

        if (!gl) return { supported: false };

        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown';
        const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown';

        const rendererLower = renderer.toLowerCase();
        const suspiciousRenderer =
          rendererLower.includes('swiftshader') ||
          rendererLower.includes('llvmpipe') ||
          rendererLower.includes('softpipe') ||
          rendererLower.includes('virtualbox') ||
          rendererLower.includes('vmware');

        return {
          supported: true,
          vendor,
          renderer,
          version: gl.getParameter(gl.VERSION),
          shadingVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
          suspiciousRenderer
        };
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    _getAudioInfo() {
      try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return { supported: false };

        const audioCtx = new AudioContext();
        const info = {
          supported: true,
          sampleRate: audioCtx.sampleRate,
          state: audioCtx.state,
          baseLatency: audioCtx.baseLatency
        };
        audioCtx.close();
        return info;
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    _getHeadlessIndicators() {
      return {
        hasOuterDimensions: window.outerWidth > 0 && window.outerHeight > 0,
        innerEqualsOuter: window.innerWidth === window.outerWidth && window.innerHeight === window.outerHeight,
        screenColorDepth: window.screen.colorDepth,
        screenPixelDepth: window.screen.pixelDepth,
        connectionType: navigator.connection ? navigator.connection.type : 'unknown',
        connectionRtt: navigator.connection ? navigator.connection.rtt : -1,
        notificationPermission: typeof Notification !== 'undefined' ? Notification.permission : 'unsupported',
        hasBattery: 'getBattery' in navigator,
        hasCredentials: 'credentials' in navigator,
        hasMediaDevices: 'mediaDevices' in navigator
      };
    }

    _getScreenInfo() {
      return {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
        pixelRatio: window.devicePixelRatio,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight
      };
    }

    _getNavigatorInfo() {
      return {
        language: navigator.language,
        languageCount: navigator.languages?.length || 0,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory,
        maxTouchPoints: navigator.maxTouchPoints || 0,
        vendor: navigator.vendor,
        userAgent: navigator.userAgent,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset()
      };
    }

    _measureJSExecution() {
      const results = {};

      let start = performance.now();
      for (let i = 0; i < 1000; i++) {
        Math.sqrt(i) * Math.sin(i);
      }
      results.mathOps = performance.now() - start;

      start = performance.now();
      const arr = [];
      for (let i = 0; i < 1000; i++) arr.push(i);
      results.arrayOps = performance.now() - start;

      start = performance.now();
      let str = '';
      for (let i = 0; i < 100; i++) str += 'a';
      results.stringOps = performance.now() - start;

      return results;
    }

    async measureRAFConsistency() {
      return new Promise((resolve) => {
        const times = [];
        let frameCount = 0;
        const maxFrames = 10;

        function measure(timestamp) {
          times.push(timestamp);
          frameCount++;

          if (frameCount < maxFrames) {
            requestAnimationFrame(measure);
          } else {
            const deltas = [];
            for (let i = 1; i < times.length; i++) {
              deltas.push(times[i] - times[i-1]);
            }

            const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
            const variance = deltas.reduce((sum, d) => sum + Math.pow(d - mean, 2), 0) / deltas.length;

            resolve({ avgFrameTime: mean, frameTimeVariance: variance, frames: maxFrames });
          }
        }

        requestAnimationFrame(measure);
      });
    }
  }

  // ============================================================
  // Proof of Work Manager (Web Worker based)
  // ============================================================

  class PoWManager {
    constructor() {
      this.worker = null;
      this.challenge = null;
      this.solution = null;
      this.solving = false;
      this.solvePromise = null;
      this.startTime = null;
    }

    // Create inline Web Worker for PoW computation
    _createWorker() {
      const workerCode = `
        async function sha256(message) {
          const msgBuffer = new TextEncoder().encode(message);
          const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }

        self.onmessage = async function(e) {
          const { prefix, difficulty, batchSize = 10000 } = e.data;
          const target = '0'.repeat(difficulty);
          let nonce = 0;
          let iterations = 0;
          const startTime = performance.now();

          while (true) {
            // Process in batches for better responsiveness
            for (let i = 0; i < batchSize; i++) {
              const hash = await sha256(prefix + ':' + nonce);
              iterations++;

              if (hash.startsWith(target)) {
                self.postMessage({
                  found: true,
                  nonce,
                  hash,
                  iterations,
                  duration: performance.now() - startTime
                });
                return;
              }
              nonce++;
            }

            // Report progress every batch
            self.postMessage({
              found: false,
              progress: iterations,
              elapsed: performance.now() - startTime
            });
          }
        };
      `;

      const blob = new Blob([workerCode], { type: 'application/javascript' });
      return new Worker(URL.createObjectURL(blob));
    }

    // Fetch challenge from server
    async fetchChallenge(siteKey) {
      const serverUrl = FCaptcha.serverUrl;
      if (!serverUrl) {
        // Fallback to local challenge generation
        return this._generateLocalChallenge();
      }

      try {
        const response = await fetch(`${serverUrl}/api/pow/challenge?siteKey=${encodeURIComponent(siteKey || 'default')}`);
        if (!response.ok) throw new Error('Challenge fetch failed');
        this.challenge = await response.json();
        return this.challenge;
      } catch (e) {
        console.warn('PoW challenge fetch failed, using local challenge:', e);
        return this._generateLocalChallenge();
      }
    }

    _generateLocalChallenge() {
      const id = Math.random().toString(36).substr(2) + Date.now().toString(36);
      this.challenge = {
        challengeId: id,
        prefix: `${id}:${Date.now()}:4`,
        difficulty: 4,
        expiresAt: Date.now() + 300000,
        local: true // Flag that this is a local challenge
      };
      return this.challenge;
    }

    // Start solving in background
    async startSolving(siteKey) {
      if (this.solving) return this.solvePromise;

      // Fetch challenge if not already fetched
      if (!this.challenge) {
        await this.fetchChallenge(siteKey);
      }

      this.solving = true;
      this.startTime = performance.now();

      this.solvePromise = new Promise((resolve, reject) => {
        this.worker = this._createWorker();

        this.worker.onmessage = (e) => {
          if (e.data.found) {
            this.solution = {
              challengeId: this.challenge.challengeId,
              nonce: e.data.nonce,
              hash: e.data.hash,
              iterations: e.data.iterations,
              duration: e.data.duration,
              difficulty: this.challenge.difficulty,
              local: this.challenge.local || false
            };
            this.solving = false;
            this.worker.terminate();
            resolve(this.solution);
          }
          // Progress updates can be used for UI if needed
        };

        this.worker.onerror = (e) => {
          this.solving = false;
          reject(e);
        };

        // Start solving
        this.worker.postMessage({
          prefix: this.challenge.prefix,
          difficulty: this.challenge.difficulty,
          batchSize: 5000
        });
      });

      return this.solvePromise;
    }

    // Wait for solution (or solve if not started)
    async getSolution(siteKey) {
      if (this.solution) return this.solution;
      if (this.solving) return this.solvePromise;
      return this.startSolving(siteKey);
    }

    // Reset for new challenge
    reset() {
      if (this.worker) {
        this.worker.terminate();
        this.worker = null;
      }
      this.challenge = null;
      this.solution = null;
      this.solving = false;
      this.solvePromise = null;
    }
  }

  // Global PoW manager - starts solving on page load
  let globalPoWManager = null;
  function getPoWManager() {
    if (!globalPoWManager) {
      globalPoWManager = new PoWManager();
    }
    return globalPoWManager;
  }

  // ============================================================
  // Temporal Signal Collector
  // ============================================================

  class TemporalCollector {
    constructor() {
      this.pageLoadTime = performance.now();
      this.firstInteractionTime = null;
      this.powResult = null;
    }

    recordFirstInteraction() {
      if (!this.firstInteractionTime) {
        this.firstInteractionTime = performance.now();
      }
    }

    // Legacy PoW method (still works but prefer PoWManager)
    async performProofOfWork(difficulty = 4) {
      const prefix = `${Date.now()}:${Math.random().toString(36).substr(2)}`;
      const target = '0'.repeat(difficulty);
      const startTime = performance.now();
      let nonce = 0;
      let iterations = 0;

      while (true) {
        const hash = await this._sha256(`${prefix}:${nonce}`);
        iterations++;

        if (hash.startsWith(target)) {
          this.powResult = {
            prefix,
            nonce,
            hash,
            iterations,
            duration: performance.now() - startTime,
            difficulty
          };
          return this.powResult;
        }

        nonce++;

        // Yield to main thread every 1000 iterations
        if (iterations % 1000 === 0) {
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      }
    }

    collect(clickTime) {
      const performanceTiming = {};
      if (performance.timing) {
        const timing = performance.timing;
        performanceTiming.dnsLookup = timing.domainLookupEnd - timing.domainLookupStart;
        performanceTiming.tcpConnection = timing.connectEnd - timing.connectStart;
        performanceTiming.serverResponse = timing.responseEnd - timing.requestStart;
        performanceTiming.domLoad = timing.domContentLoadedEventEnd - timing.navigationStart;
        performanceTiming.fullLoad = timing.loadEventEnd - timing.navigationStart;
      }

      return {
        pageLoadToFirstInteraction: this.firstInteractionTime ?
          this.firstInteractionTime - this.pageLoadTime : null,
        firstInteractionToClick: this.firstInteractionTime && clickTime ?
          clickTime - this.firstInteractionTime : null,
        totalSessionTime: performance.now() - this.pageLoadTime,
        performanceTiming,
        pow: this.powResult
      };
    }

    async _sha256(message) {
      const msgBuffer = new TextEncoder().encode(message);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
  }

  // ============================================================
  // Checkbox Widget
  // ============================================================

  class CaptchaWidget {
    constructor(container, options) {
      this.container = typeof container === 'string' ?
        document.getElementById(container) : container;

      this.options = Object.assign({
        siteKey: null,
        theme: 'light',
        size: 'normal',
        callback: null,
        errorCallback: null,
        expiredCallback: null,
        powDifficulty: 4
      }, options);

      this.id = 'fcaptcha_' + Math.random().toString(36).substr(2, 9);
      this.behavioral = new BehavioralCollector();
      this.environmental = new EnvironmentalCollector();
      this.temporal = new TemporalCollector();
      this.powManager = getPoWManager();
      this.token = null;
      this.verified = false;

      this._init();
    }

    _init() {
      this._createWidget();
      this._attachListeners();
      // Start PoW in background immediately
      this._startPoW();
    }

    async _startPoW() {
      try {
        await this.powManager.startSolving(this.options.siteKey);
      } catch (e) {
        console.warn('PoW background solving failed:', e);
      }
    }

    _createWidget() {
      const isDark = this.options.theme === 'dark';

      this.container.innerHTML = `
        <div class="fcaptcha-widget ${isDark ? 'fcaptcha-dark' : ''}" id="${this.id}">
          <style>
            .fcaptcha-widget {
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
              background: ${isDark ? '#1a1a2e' : '#fafafa'};
              border: 1px solid ${isDark ? '#333' : '#d3d3d3'};
              border-radius: 4px;
              padding: 12px 16px;
              display: inline-flex;
              align-items: center;
              gap: 12px;
              min-width: 280px;
              box-sizing: border-box;
              user-select: none;
            }
            .fcaptcha-checkbox {
              width: 24px;
              height: 24px;
              border: 2px solid ${isDark ? '#555' : '#c1c1c1'};
              border-radius: 3px;
              cursor: pointer;
              display: flex;
              align-items: center;
              justify-content: center;
              background: ${isDark ? '#2a2a3e' : '#fff'};
              transition: all 0.15s ease;
              flex-shrink: 0;
            }
            .fcaptcha-checkbox:hover { border-color: ${isDark ? '#7c7cff' : '#4285f4'}; }
            .fcaptcha-checkbox.loading { border-color: ${isDark ? '#7c7cff' : '#4285f4'}; }
            .fcaptcha-checkbox.verified { background: #00c853; border-color: #00c853; }
            .fcaptcha-checkbox.failed { background: #ea4335; border-color: #ea4335; }
            .fcaptcha-spinner {
              width: 16px;
              height: 16px;
              border: 2px solid ${isDark ? '#555' : '#e0e0e0'};
              border-top-color: ${isDark ? '#7c7cff' : '#4285f4'};
              border-radius: 50%;
              animation: fcaptcha-spin 0.8s linear infinite;
            }
            @keyframes fcaptcha-spin { to { transform: rotate(360deg); } }
            .fcaptcha-checkmark { display: none; color: white; font-size: 14px; font-weight: bold; }
            .fcaptcha-checkbox.verified .fcaptcha-checkmark { display: block; }
            .fcaptcha-x { display: none; color: white; font-size: 14px; font-weight: bold; }
            .fcaptcha-checkbox.failed .fcaptcha-x { display: block; }
            .fcaptcha-label { color: ${isDark ? '#e0e0e0' : '#555'}; font-size: 14px; flex-grow: 1; }
            .fcaptcha-branding {
              display: flex; flex-direction: column; align-items: flex-end; gap: 2px; flex-shrink: 0;
            }
            .fcaptcha-logo { font-size: 11px; font-weight: 600; color: ${isDark ? '#888' : '#666'}; letter-spacing: 0.5px; }
            .fcaptcha-privacy { font-size: 9px; color: ${isDark ? '#666' : '#999'}; }
            .fcaptcha-privacy a { color: inherit; text-decoration: none; }
            .fcaptcha-privacy a:hover { text-decoration: underline; }
          </style>
          <div class="fcaptcha-checkbox" role="checkbox" aria-checked="false" tabindex="0">
            <div class="fcaptcha-spinner" style="display: none;"></div>
            <span class="fcaptcha-checkmark">✓</span>
            <span class="fcaptcha-x">✕</span>
          </div>
          <span class="fcaptcha-label">I'm not a robot</span>
          <div class="fcaptcha-branding">
            <span class="fcaptcha-logo">FCaptcha</span>
            <span class="fcaptcha-privacy">
              <a href="#" onclick="return false;">Privacy</a> ·
              <a href="#" onclick="return false;">Terms</a>
            </span>
          </div>
        </div>
      `;

      this.checkbox = this.container.querySelector('.fcaptcha-checkbox');
      this.spinner = this.container.querySelector('.fcaptcha-spinner');
      this.label = this.container.querySelector('.fcaptcha-label');
    }

    _attachListeners() {
      // Global tracking
      document.addEventListener('mousemove', (e) => this.behavioral.recordMouseMove(e), { passive: true });
      document.addEventListener('mousedown', (e) => this.behavioral.recordMouseDown(e), { passive: true });
      document.addEventListener('mouseup', (e) => this.behavioral.recordMouseUp(e), { passive: true });
      document.addEventListener('scroll', (e) => this.behavioral.recordScroll(e), { passive: true });
      document.addEventListener('keydown', (e) => this.behavioral.recordKeyEvent(e), { passive: true });
      document.addEventListener('keyup', (e) => this.behavioral.recordKeyEvent(e), { passive: true });
      document.addEventListener('touchmove', (e) => this.behavioral.recordTouch(e), { passive: true });
      document.addEventListener('focus', (e) => this.behavioral.recordFocus(e), { passive: true, capture: true });
      document.addEventListener('blur', (e) => this.behavioral.recordFocus(e), { passive: true, capture: true });

      // First interaction
      const recordFirst = () => this.temporal.recordFirstInteraction();
      document.addEventListener('mousemove', recordFirst, { once: true });
      document.addEventListener('touchstart', recordFirst, { once: true });
      document.addEventListener('keydown', recordFirst, { once: true });

      // Checkbox click
      this.checkbox.addEventListener('click', (e) => this._handleClick(e));
      this.checkbox.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          this._handleClick(e);
        }
      });
    }

    async _handleClick(e) {
      if (this.verified || this.checkbox.classList.contains('loading')) return;

      const clickTime = performance.now();
      const rect = this.checkbox.getBoundingClientRect();

      this.checkbox.classList.add('loading');
      this.spinner.style.display = 'block';
      this.label.textContent = 'Verifying...';

      try {
        // Collect signals
        const behavioralData = this.behavioral.analyze();
        const clickData = this.behavioral.analyzeClick(e.clientX, e.clientY, rect);
        const envData = this.environmental.collect();
        const rafData = await this.environmental.measureRAFConsistency();

        // Wait for PoW solution (should already be solved in background)
        const powSolution = await this.powManager.getSolution(this.options.siteKey);

        // Also collect legacy PoW timing for temporal signals
        this.temporal.powResult = {
          duration: powSolution.duration,
          iterations: powSolution.iterations,
          difficulty: powSolution.difficulty
        };
        const temporalData = this.temporal.collect(clickTime);

        // Get form interaction analysis
        const formAnalysis = getFormAnalyzer().analyze();

        const signals = {
          behavioral: { ...behavioralData, ...clickData },
          environmental: { ...envData, rafConsistency: rafData },
          temporal: temporalData,
          formAnalysis: formAnalysis,
          meta: {
            widgetId: this.id,
            siteKey: this.options.siteKey,
            timestamp: Date.now(),
            userAgent: navigator.userAgent,
            screenSize: `${screen.width}x${screen.height}`,
            viewportSize: `${window.innerWidth}x${window.innerHeight}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
          }
        };

        const result = await this._verify(signals, powSolution);

        if (result.success) {
          this._showSuccess(result.token);
        } else {
          this._showFailure(result.message);
        }
      } catch (error) {
        console.error('FCaptcha error:', error);
        this._showFailure('Verification failed. Please try again.');
      }
    }

    async _verify(signals, powSolution = null) {
      if (!FCaptcha.serverUrl) {
        return this._clientSideVerify(signals);
      }

      try {
        const response = await fetch(FCaptcha.serverUrl + '/api/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            siteKey: this.options.siteKey,
            signals,
            powSolution: powSolution ? {
              challengeId: powSolution.challengeId,
              nonce: powSolution.nonce,
              hash: powSolution.hash
            } : null
          })
        });
        return await response.json();
      } catch (error) {
        console.warn('Server unavailable, using client-side verification');
        return this._clientSideVerify(signals);
      }
    }

    _clientSideVerify(signals) {
      let score = 0;
      const b = signals.behavioral;
      const e = signals.environmental;
      const t = signals.temporal;

      // Behavioral (40%)
      if (b.microTremorScore < 0.2) score += 0.12;
      if (b.velocityVariance < 0.03) score += 0.10;
      if (b.explorationRatio < 0.05) score += 0.08;
      if (b.overshootCorrections === 0 && b.trajectoryLength > 100) score += 0.05;
      if (b.clickPrecision < 2) score += 0.05;
      if (b.straightLineRatio > 0.8) score += 0.08;
      if (b.microMovements < 5 && b.totalPoints > 50) score += 0.06;

      // Environmental (35%)
      if (e.webdriver) score += 0.25;
      if (e.automationFlags && e.automationFlags.plugins === 0) score += 0.05;
      if (e.webglInfo && e.webglInfo.suspiciousRenderer) score += 0.10;
      if (e.headlessIndicators && !e.headlessIndicators.hasOuterDimensions) score += 0.12;
      if (e.headlessIndicators && e.headlessIndicators.innerEqualsOuter) score += 0.05;

      // Temporal (25%)
      if (t.pow && t.pow.duration < 50) score += 0.10;
      if (b.eventDeltaVariance < 3) score += 0.08;
      if (b.interactionDuration < 300) score += 0.07;

      const passed = score < 0.5;

      return {
        success: passed,
        score,
        token: passed ? btoa(JSON.stringify({ timestamp: Date.now(), score, id: this.id })) : null,
        message: passed ? null : 'Verification failed'
      };
    }

    _showSuccess(token) {
      this.verified = true;
      this.token = token;
      this.checkbox.classList.remove('loading');
      this.checkbox.classList.add('verified');
      this.checkbox.setAttribute('aria-checked', 'true');
      this.spinner.style.display = 'none';
      this.label.textContent = 'Verified';

      if (this.options.callback) this.options.callback(token);
      this.container.dispatchEvent(new CustomEvent('fcaptcha:verified', { detail: { token } }));
    }

    _showFailure(message) {
      this.checkbox.classList.remove('loading');
      this.checkbox.classList.add('failed');
      this.spinner.style.display = 'none';
      this.label.textContent = message || 'Verification failed';

      if (this.options.errorCallback) this.options.errorCallback(message);

      setTimeout(() => {
        this.checkbox.classList.remove('failed');
        this.label.textContent = "I'm not a robot";
      }, 3000);
    }

    getToken() { return this.token; }

    reset() {
      this.verified = false;
      this.token = null;
      this.behavioral = new BehavioralCollector();
      this.temporal = new TemporalCollector();
      this.powManager.reset();
      this.checkbox.classList.remove('verified', 'failed', 'loading');
      this.checkbox.setAttribute('aria-checked', 'false');
      this.spinner.style.display = 'none';
      this.label.textContent = "I'm not a robot";
      // Start new PoW in background
      this._startPoW();
    }
  }

  // ============================================================
  // Invisible Mode (Zero-Click)
  // ============================================================

  class InvisibleSession {
    constructor(options) {
      this.options = Object.assign({
        siteKey: null,
        serverUrl: null,
        minCollectionTime: 2000,
        autoScore: true,
        scoreThreshold: 0.5,
        powDifficulty: 3
      }, options);

      this.id = 'fcaptcha_inv_' + Math.random().toString(36).substr(2, 9);
      this.behavioral = new BehavioralCollector();
      this.environmental = new EnvironmentalCollector();
      this.temporal = new TemporalCollector();
      this.powManager = new PoWManager();
      this.startTime = Date.now();
      this.lastScore = null;
      this.listeners = [];

      this._init();
    }

    _init() {
      this._attachListeners();

      const recordFirst = () => this.temporal.recordFirstInteraction();
      document.addEventListener('mousemove', recordFirst, { once: true });
      document.addEventListener('touchstart', recordFirst, { once: true });
      document.addEventListener('keydown', recordFirst, { once: true });
      document.addEventListener('scroll', recordFirst, { once: true });

      if (this.options.autoScore) this._attachToForms();

      // Start PoW in background
      this._startPoW();
    }

    async _startPoW() {
      try {
        await this.powManager.startSolving(this.options.siteKey);
      } catch (e) {
        console.warn('PoW background solving failed:', e);
      }
    }

    _attachListeners() {
      const handlers = {
        mousemove: (e) => this.behavioral.recordMouseMove(e),
        mousedown: (e) => this.behavioral.recordMouseDown(e),
        mouseup: (e) => this.behavioral.recordMouseUp(e),
        scroll: (e) => this.behavioral.recordScroll(e),
        keydown: (e) => this.behavioral.recordKeyEvent(e),
        keyup: (e) => this.behavioral.recordKeyEvent(e),
        touchmove: (e) => this.behavioral.recordTouch(e),
        touchstart: (e) => this.behavioral.recordTouch(e),
        focus: (e) => this.behavioral.recordFocus(e),
        blur: (e) => this.behavioral.recordFocus(e)
      };

      for (const [event, handler] of Object.entries(handlers)) {
        const opts = event === 'focus' || event === 'blur' ?
          { passive: true, capture: true } : { passive: true };
        document.addEventListener(event, handler, opts);
        this.listeners.push({ event, handler, opts });
      }
    }

    _attachToForms() {
      document.addEventListener('submit', async (e) => {
        const form = e.target;
        if (form.dataset.fcaptchaIgnore) return;

        let tokenField = form.querySelector('input[name="fcaptcha_token"]');
        if (!tokenField) {
          tokenField = document.createElement('input');
          tokenField.type = 'hidden';
          tokenField.name = 'fcaptcha_token';
          form.appendChild(tokenField);
        }

        if (!this.lastScore || Date.now() - this.lastScore.timestamp > 60000) {
          e.preventDefault();

          try {
            const result = await this.execute(form.dataset.fcaptchaAction || 'form_submit');
            tokenField.value = result.token || '';

            if (result.success) {
              form.submit();
            } else {
              document.dispatchEvent(new CustomEvent('fcaptcha:blocked', {
                detail: { score: result.score, form }
              }));
            }
          } catch (error) {
            console.error('FCaptcha error:', error);
            form.submit(); // Fail open
          }
        } else {
          tokenField.value = this.lastScore.token || '';
        }
      });
    }

    async execute(action = '') {
      const elapsed = Date.now() - this.startTime;
      if (elapsed < this.options.minCollectionTime) {
        await new Promise(r => setTimeout(r, this.options.minCollectionTime - elapsed));
      }

      const behavioralData = this.behavioral.analyze();
      const envData = this.environmental.collect();

      // Wait for PoW solution (should already be solved in background)
      const powSolution = await this.powManager.getSolution(this.options.siteKey);

      // Also collect legacy PoW timing for temporal signals
      this.temporal.powResult = {
        duration: powSolution.duration,
        iterations: powSolution.iterations,
        difficulty: powSolution.difficulty
      };
      const temporalData = this.temporal.collect(Date.now());
      const rafData = await this.environmental.measureRAFConsistency();

      // Get form interaction analysis
      const formAnalysis = getFormAnalyzer().analyze();

      const signals = {
        behavioral: behavioralData,
        environmental: { ...envData, rafConsistency: rafData },
        temporal: temporalData,
        formAnalysis: formAnalysis,
        meta: {
          sessionId: this.id,
          siteKey: this.options.siteKey,
          action,
          timestamp: Date.now(),
          userAgent: navigator.userAgent,
          screenSize: `${screen.width}x${screen.height}`,
          viewportSize: `${window.innerWidth}x${window.innerHeight}`,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          sessionDuration: Date.now() - this.startTime,
          invisible: true
        }
      };

      const result = await this._score(signals, action, powSolution);
      this.lastScore = { ...result, timestamp: Date.now() };
      return result;
    }

    async _score(signals, action, powSolution = null) {
      const url = this.options.serverUrl || FCaptcha.serverUrl;

      if (!url) return this._clientSideScore(signals);

      try {
        const response = await fetch(url + '/api/score', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            siteKey: this.options.siteKey,
            signals,
            action,
            powSolution: powSolution ? {
              challengeId: powSolution.challengeId,
              nonce: powSolution.nonce,
              hash: powSolution.hash
            } : null
          })
        });
        return await response.json();
      } catch (error) {
        console.warn('FCaptcha server unavailable, using client-side scoring');
        return this._clientSideScore(signals);
      }
    }

    _clientSideScore(signals) {
      let score = 0;
      const b = signals.behavioral;
      const e = signals.environmental;
      const t = signals.temporal;
      const m = signals.meta;

      // Behavioral
      if (b.microTremorScore < 0.2) score += 0.12;
      if (b.velocityVariance < 0.03) score += 0.10;
      if (b.totalPoints < 10 && m.sessionDuration > 5000) score += 0.08;
      if (b.scrollEvents === 0 && b.keyEvents === 0 && m.sessionDuration > 10000) score += 0.06;
      if (b.eventDeltaVariance < 3) score += 0.08;
      if (b.straightLineRatio > 0.8) score += 0.08;

      // Environmental
      if (e.webdriver) score += 0.25;
      if (e.automationFlags && e.automationFlags.plugins === 0) score += 0.06;
      if (e.headlessIndicators && !e.headlessIndicators.hasOuterDimensions) score += 0.12;
      if (e.webglInfo && e.webglInfo.suspiciousRenderer) score += 0.10;

      // Temporal
      if (t.pow && t.pow.duration < 30) score += 0.10;
      if (m.sessionDuration < 500) score += 0.12;
      if (m.sessionDuration < 1000 && b.totalPoints < 5) score += 0.15;

      const success = score < this.options.scoreThreshold;

      return {
        success,
        score: Math.min(1, score),
        action: m.action,
        token: success ? btoa(JSON.stringify({
          timestamp: Date.now(), score, action: m.action, id: this.id
        })) : null
      };
    }

    getScore() { return this.lastScore; }

    destroy() {
      for (const { event, handler, opts } of this.listeners) {
        document.removeEventListener(event, handler, opts);
      }
      this.listeners = [];
      if (this.powManager) {
        this.powManager.reset();
      }
    }
  }

  // ============================================================
  // Public API
  // ============================================================

  FCaptcha.invisible = function(options) {
    const session = new InvisibleSession(options);
    this.widgets.set(session.id, session);
    return session;
  };

  FCaptcha.execute = async function(siteKey, options = {}) {
    const session = new InvisibleSession({
      siteKey,
      serverUrl: this.serverUrl,
      minCollectionTime: options.minTime || 1000,
      autoScore: false,
      powDifficulty: options.powDifficulty || 3
    });

    const result = await session.execute(options.action || '');
    session.destroy();
    return result;
  };

  FCaptcha.render = function(container, options) {
    const widget = new CaptchaWidget(container, options);
    this.widgets.set(widget.id, widget);
    return widget.id;
  };

  FCaptcha.getResponse = function(widgetId) {
    const widget = this.widgets.get(widgetId);
    return widget ? widget.getToken() : null;
  };

  FCaptcha.reset = function(widgetId) {
    const widget = this.widgets.get(widgetId);
    if (widget && widget.reset) widget.reset();
  };

  FCaptcha.configure = function(options) {
    if (options.serverUrl) this.serverUrl = options.serverUrl;
  };

  FCaptcha.getSignals = function() {
    // For debugging - returns current signal collectors
    const collector = {
      behavioral: new BehavioralCollector(),
      environmental: new EnvironmentalCollector(),
      temporal: new TemporalCollector()
    };
    return {
      environmental: collector.environmental.collect()
    };
  };

  // Auto-init
  FCaptcha.autoInit = function() {
    document.querySelectorAll('[data-fcaptcha]').forEach(container => {
      const siteKey = container.dataset.sitekey || container.dataset.fcaptcha;
      const theme = container.dataset.theme || 'light';
      const endpoint = container.dataset.endpoint;
      const callback = container.dataset.callback ? window[container.dataset.callback] : null;

      if (endpoint) FCaptcha.serverUrl = endpoint;

      FCaptcha.render(container, { siteKey, theme, callback });
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => FCaptcha.autoInit());
  } else {
    FCaptcha.autoInit();
  }

  // Export
  window.FCaptcha = FCaptcha;
  window.Fcaptcha = FCaptcha; // Alias for compatibility

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = FCaptcha;
  }

})(window);
