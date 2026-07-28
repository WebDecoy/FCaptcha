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
    // Keep in sync with server-node/package.json and server-python/server.py
    // when cutting a release; this string ships to integrators.
    version: '1.19.2',
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
      this.touchMultiTouchSeen = false;
      this.touchIdentifiers = new Set();
      this.pointerPoints = [];
      this.focusEvents = [];
      this.clickData = null;
      this.startTime = Date.now();
      this.lastMousePos = null;
      this.lastMouseTime = null;
      this.lastVelocity = null;
      this.eventDeltas = [];

      // --- Input-event forensics (AI-agent detection, PRD phase 2) ---
      // Cross-input activity timeline for think-time cadence.
      this._lastActivityT = null;
      this._cadenceGaps = [];
      this._teleportClicks = 0;
      // Coalesced pointermove batches: real mice coalesce multiple hardware
      // samples per frame; CDP-injected moves produce single-entry batches.
      this._coalescedSamples = 0;
      this._coalescedEmpty = 0;
      this._coalescedSum = 0;
      this._coalescedMax = 0;
      // movementX/Y vs position-delta coherence (synthetic input is incoherent).
      this._ptrLastX = null;
      this._ptrLastY = null;
      this._ptrMoveSamples = 0;
      this._ptrMoveZero = 0;
    }

    // Record any user-input event on a single timeline so the server can spot
    // the agent act -> screenshot -> think (dead air) -> act loop.
    _markActivity(now) {
      if (this._lastActivityT !== null) {
        this._cadenceGaps.push(now - this._lastActivityT);
        if (this._cadenceGaps.length > 1000) this._cadenceGaps.shift();
      }
      this._lastActivityT = now;
    }

    recordMouseMove(e) {
      const now = performance.now();
      this._markActivity(now);
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
      const now = performance.now();
      this._markActivity(now);
      // Teleport click: mousedown landing far from the last observed mouse
      // position with no intervening movement = injected click (computer-use
      // agents dispatch a click at coordinates without an approach path).
      if (this.lastMousePos) {
        const d = Math.hypot(e.clientX - this.lastMousePos.x, e.clientY - this.lastMousePos.y);
        if (d > 150) this._teleportClicks++;
      }
      this.clickData = {
        x: e.clientX,
        y: e.clientY,
        button: e.button,
        downTime: now
      };
    }

    recordMouseUp(_e) {
      if (this.clickData) {
        this.clickData.upTime = performance.now();
        this.clickData.holdDuration = this.clickData.upTime - this.clickData.downTime;
      }
    }

    recordScroll(_e) {
      const now = performance.now();
      this._markActivity(now);
      this.scrollEvents.push({
        x: window.scrollX,
        y: window.scrollY,
        t: now
      });
      if (this.scrollEvents.length > 100) this.scrollEvents.shift();
    }

    recordKeyEvent(e) {
      const now = performance.now();
      this._markActivity(now);
      this.keyEvents.push({
        type: e.type,
        keyLength: e.key ? e.key.length : 0, // Don't store actual keys
        t: now
      });
    }

    recordTouch(e) {
      this._markActivity(performance.now());
      const touches = (e.touches && e.touches.length) ? e.touches : e.changedTouches;
      if (!touches || touches.length === 0) return;
      if (touches.length > 1) this.touchMultiTouchSeen = true;

      const touch = touches[0];
      if (typeof touch.identifier === 'number') this.touchIdentifiers.add(touch.identifier);

      this.touchEvents.push({
        x: touch.clientX,
        y: touch.clientY,
        t: performance.now(),
        force: typeof touch.force === 'number' ? touch.force : 0,
        radiusX: typeof touch.radiusX === 'number' ? touch.radiusX : 0,
        radiusY: typeof touch.radiusY === 'number' ? touch.radiusY : 0,
        rotationAngle: typeof touch.rotationAngle === 'number' ? touch.rotationAngle : 0,
        identifier: typeof touch.identifier === 'number' ? touch.identifier : -1,
        touchCount: touches.length
      });
      if (this.touchEvents.length > 500) this.touchEvents.shift();
    }

    recordPointer(e) {
      const now = performance.now();
      this._markActivity(now);

      if (e.type === 'pointermove') {
        // Coalesced-events batch size. Only mouse pointers; touch/pen coalesce
        // differently and are scored via their own kinematics.
        if (e.pointerType !== 'touch' && typeof e.getCoalescedEvents === 'function') {
          let len = 1;
          try {
            const coalesced = e.getCoalescedEvents();
            len = (coalesced && coalesced.length) ? coalesced.length : 1;
          } catch (_err) { len = 1; }
          this._coalescedSamples++;
          if (len <= 1) this._coalescedEmpty++;
          this._coalescedSum += len;
          if (len > this._coalescedMax) this._coalescedMax = len;
        }
        // movementX/Y should be nonzero whenever the position actually changed.
        if (e.pointerType !== 'touch' && this._ptrLastX !== null) {
          const dx = e.clientX - this._ptrLastX;
          const dy = e.clientY - this._ptrLastY;
          if (dx !== 0 || dy !== 0) {
            this._ptrMoveSamples++;
            const mx = typeof e.movementX === 'number' ? e.movementX : 0;
            const my = typeof e.movementY === 'number' ? e.movementY : 0;
            if (mx === 0 && my === 0) this._ptrMoveZero++;
          }
        }
        this._ptrLastX = e.clientX;
        this._ptrLastY = e.clientY;
      }

      this.pointerPoints.push({
        x: e.clientX,
        y: e.clientY,
        t: now,
        type: e.type,
        pressure: typeof e.pressure === 'number' ? e.pressure : 0,
        tiltX: typeof e.tiltX === 'number' ? e.tiltX : 0,
        tiltY: typeof e.tiltY === 'number' ? e.tiltY : 0,
        tangentialPressure: typeof e.tangentialPressure === 'number' ? e.tangentialPressure : 0,
        pointerType: e.pointerType || 'unknown'
      });
      if (this.pointerPoints.length > 500) this.pointerPoints.shift();
    }

    // Aggregate the input-event forensics into a compact object consumed by the
    // server's detectCDP / detectVisionAI. All thresholds live server-side.
    /**
     * Scroll morphology: the *shape* of scrolling, not the amount.
     *
     * A wheel, a trackpad and a finger all produce a burst of scroll events
     * spread over hundreds of milliseconds, because a scroll is a physical
     * gesture with acceleration and a tail. `element.scrollIntoView()` produces
     * a single event, or a few in one frame, and lands on the same offsets
     * every time because it is aiming at the same elements.
     *
     * So this segments the raw event buffer into gestures — consecutive events
     * separated by less than a pause — and reports how long each took and how
     * far it went. A population of zero-duration gestures means the page was
     * scrolled by an API call rather than by a hand. That is an architecture
     * tell as much as a bot tell: DOM-driven agents jump, vision-driven ones
     * emit short bursts, people produce long variable ones.
     *
     * Reports distributions, never raw offsets: where on a page someone
     * scrolled is more revealing about them than how they got there.
     */
    _analyzeScrollMorphology() {
      const events = this.scrollEvents;
      if (events.length < 2) {
        return {
          gestures: 0, instantGestures: 0, instantRatio: 0,
          maxStep: 0, distancePerEvent: 0, samples: events.length
        };
      }

      // A gap this long means the hand stopped and started again. Short enough
      // that two flicks do not merge, long enough that one flick does not split.
      const GESTURE_GAP_MS = 200;

      const gestures = [];
      let start = 0;
      for (let i = 1; i <= events.length; i++) {
        const ended = i === events.length || events[i].t - events[i - 1].t > GESTURE_GAP_MS;
        if (!ended) continue;

        const first = events[start];
        const last = events[i - 1];
        gestures.push({
          duration: last.t - first.t,
          distance: Math.abs(last.y - first.y) + Math.abs(last.x - first.x),
          events: i - start
        });
        start = i;
      }

      const durations = gestures.map(g => g.duration);
      const distances = gestures.map(g => g.distance);
      const mean = (a) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);
      const variance = (a) => {
        if (a.length < 2) return 0;
        const m = mean(a);
        return a.reduce((acc, v) => acc + Math.pow(v - m, 2), 0) / a.length;
      };

      // A gesture that began and ended in the same instant did not involve a
      // hand. One frame of slack so a fast real flick is not miscounted.
      const instant = gestures.filter(g => g.duration <= 16).length;

      // The sharper tell is how far the page moved per event.
      //
      // A wheel notch or a trackpad flick advances tens of pixels and emits an
      // event for each, so a person covering 2000px produces dozens of them.
      // `scrollIntoView` covers the same 2000px in a single event, because it is
      // aiming at an element rather than turning a wheel. Measured here: a human
      // scroll averaged 58px per event, an agent jump around 700px.
      //
      // Duration alone misses this — three jumps 30ms apart segment into one
      // gesture with a plausible-looking 60ms duration.
      let maxStep = 0;
      for (let i = 1; i < events.length; i++) {
        const step = Math.abs(events[i].y - events[i - 1].y) + Math.abs(events[i].x - events[i - 1].x);
        if (step > maxStep) maxStep = step;
      }
      const totalDistance = distances.reduce((a, b) => a + b, 0);
      const distancePerEvent = events.length > 1 ? totalDistance / (events.length - 1) : 0;

      // Repeated landing offsets: scrollIntoView aims at elements, so it stops
      // at the same y over and over. Rounded to absorb sub-pixel differences.
      const endOffsets = gestures.map(g => Math.round(events[0].y + g.distance));
      const uniqueEnds = new Set(endOffsets).size;

      return {
        gestures: gestures.length,
        instantGestures: instant,
        instantRatio: gestures.length ? instant / gestures.length : 0,
        avgDuration: mean(durations),
        durationVariance: variance(durations),
        avgDistance: mean(distances),
        distanceVariance: variance(distances),
        repeatedEndRatio: gestures.length ? 1 - uniqueEnds / gestures.length : 0,
        maxStep,
        distancePerEvent,
        samples: events.length
      };
    }

    _analyzeInputForensics() {
      const gaps = this._cadenceGaps;
      let silentGaps = 0;
      let silentTime = 0;
      let totalTime = 0;
      for (const g of gaps) {
        totalTime += g;
        if (g > 1500) { silentGaps++; silentTime += g; }
      }
      const mean = gaps.length ? totalTime / gaps.length : 0;
      let variance = 0;
      if (gaps.length) {
        variance = gaps.reduce((acc, g) => acc + (g - mean) * (g - mean), 0) / gaps.length;
      }
      const gapCV = mean > 0 ? Math.sqrt(variance) / mean : 0;
      return {
        coalescedSamples: this._coalescedSamples,
        coalescedEmptyRatio: this._coalescedSamples ? this._coalescedEmpty / this._coalescedSamples : 0,
        coalescedAvg: this._coalescedSamples ? this._coalescedSum / this._coalescedSamples : 0,
        coalescedMax: this._coalescedMax,
        pointerMoveSamples: this._ptrMoveSamples,
        pointerMoveZeroRatio: this._ptrMoveSamples ? this._ptrMoveZero / this._ptrMoveSamples : 0,
        cadenceEvents: gaps.length,
        cadenceSilentGaps: silentGaps,
        cadenceGapCV: gapCV,
        cadenceSilentRatio: totalTime > 0 ? silentTime / totalTime : 0,
        teleportClicks: this._teleportClicks
      };
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

      // Touch kinematics (mobile-native behavioral signal)
      const touchAnalysis = this._analyzeTouchPoints(this.touchEvents);

      // Pointer event aggregates (stylus/pen high-entropy signal)
      const pointerAnalysis = this._analyzePointerPoints(this.pointerPoints);

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
        scrollMorphology: this._analyzeScrollMorphology(),
        keyEvents: this.keyEvents.length,
        touchEvents: this.touchEvents.length,
        focusEvents: this.focusEvents.length,
        clickData: this.clickData,
        interactionDuration: Date.now() - this.startTime,
        inputForensics: this._analyzeInputForensics(),
        ...touchAnalysis,
        ...pointerAnalysis
      };
    }

    _analyzeTouchPoints(touches) {
      if (!touches || touches.length === 0) {
        return {
          touchTotalPoints: 0,
          touchTrajectoryLength: 0,
          touchAvgVelocity: 0,
          touchVelocityVariance: 0,
          touchMicroTremorScore: 0,
          touchStraightLineRatio: 0,
          touchDirectionChanges: 0,
          touchForceMin: 0,
          touchForceMax: 0,
          touchForceVariance: 0,
          touchRadiusMin: 0,
          touchRadiusMax: 0,
          touchRadiusVariance: 0,
          touchMultiTouchSeen: this.touchMultiTouchSeen,
          touchUniqueIdentifiers: this.touchIdentifiers.size,
          touchForceAllZero: false,
          touchForceAllOne: false
        };
      }

      let trajLen = 0;
      const vels = [];
      for (let i = 1; i < touches.length; i++) {
        const dx = touches[i].x - touches[i-1].x;
        const dy = touches[i].y - touches[i-1].y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        trajLen += dist;
        const dt = touches[i].t - touches[i-1].t;
        if (dt > 0) vels.push(dist / dt);
      }
      const avgVel = vels.length > 0 ? vels.reduce((a, b) => a + b, 0) / vels.length : 0;

      const forces = touches.map(p => p.force);
      const radii = touches.map(p => Math.max(p.radiusX || 0, p.radiusY || 0));
      const forceAllZero = forces.length > 0 && forces.every(f => f === 0);
      const forceAllOne = forces.length > 0 && forces.every(f => f === 1);

      return {
        touchTotalPoints: touches.length,
        touchTrajectoryLength: trajLen,
        touchAvgVelocity: avgVel,
        touchVelocityVariance: this._variance(vels),
        touchMicroTremorScore: this._detectMicroTremor(touches),
        touchStraightLineRatio: this._calculateStraightLineRatio(touches),
        touchDirectionChanges: this._countDirectionChanges(touches),
        touchForceMin: forces.length > 0 ? Math.min(...forces) : 0,
        touchForceMax: forces.length > 0 ? Math.max(...forces) : 0,
        touchForceVariance: this._variance(forces),
        touchRadiusMin: radii.length > 0 ? Math.min(...radii) : 0,
        touchRadiusMax: radii.length > 0 ? Math.max(...radii) : 0,
        touchRadiusVariance: this._variance(radii),
        touchMultiTouchSeen: this.touchMultiTouchSeen,
        touchUniqueIdentifiers: this.touchIdentifiers.size,
        touchForceAllZero: forceAllZero,
        touchForceAllOne: forceAllOne
      };
    }

    _analyzePointerPoints(points) {
      if (!points || points.length === 0) {
        return {
          pointerEvents: 0,
          pointerAvgPressure: 0,
          pointerPressureVariance: 0,
          pointerMaxTilt: 0,
          pointerHasNonMouseType: false,
          pointerTypes: []
        };
      }
      const pressures = points.map(p => p.pressure);
      const avgP = pressures.length > 0 ? pressures.reduce((a, b) => a + b, 0) / pressures.length : 0;
      let maxTilt = 0;
      const types = new Set();
      for (const p of points) {
        const tilt = Math.abs(p.tiltX || 0) + Math.abs(p.tiltY || 0);
        if (tilt > maxTilt) maxTilt = tilt;
        if (p.pointerType) types.add(p.pointerType);
      }
      return {
        pointerEvents: points.length,
        pointerAvgPressure: avgP,
        pointerPressureVariance: this._variance(pressures),
        pointerMaxTilt: maxTilt,
        pointerHasNonMouseType: Array.from(types).some(t => t !== 'mouse' && t !== 'unknown'),
        pointerTypes: Array.from(types)
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
        scrollEvents: this.scrollEvents.length,
        scrollMorphology: this._analyzeScrollMorphology(),
        keyEvents: this.keyEvents.length,
        touchEvents: this.touchEvents.length, focusEvents: this.focusEvents.length,
        clickData: this.clickData, interactionDuration: Date.now() - this.startTime,
        inputForensics: this._analyzeInputForensics(),
        ...this._analyzeTouchPoints(this.touchEvents),
        ...this._analyzePointerPoints(this.pointerPoints)
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
  // Sensor Collector (passive DeviceMotion/Orientation)
  // ============================================================
  //
  // Listens opportunistically for devicemotion/deviceorientation events.
  // Does NOT call requestPermission(): on iOS 13+ events simply won't fire
  // without permission, which we treat as neutral server-side. On Android
  // and older iOS the events fire freely, and flat accelerometer readings
  // distinguish emulators from real phones.

  class SensorCollector {
    constructor() {
      this.motionEvents = [];
      this.orientationEvents = [];
      this._motionHandler = (e) => this._recordMotion(e);
      this._orientationHandler = (e) => this._recordOrientation(e);
      this._attached = false;
    }

    attach() {
      if (this._attached) return;
      this._attached = true;
      try {
        window.addEventListener('devicemotion', this._motionHandler, { passive: true });
        window.addEventListener('deviceorientation', this._orientationHandler, { passive: true });
      } catch (_e) { /* ignore */ }
    }

    detach() {
      if (!this._attached) return;
      this._attached = false;
      try {
        window.removeEventListener('devicemotion', this._motionHandler);
        window.removeEventListener('deviceorientation', this._orientationHandler);
      } catch (_e) { /* ignore */ }
    }

    _recordMotion(e) {
      const a = e.accelerationIncludingGravity || e.acceleration || {};
      this.motionEvents.push({
        x: typeof a.x === 'number' ? a.x : 0,
        y: typeof a.y === 'number' ? a.y : 0,
        z: typeof a.z === 'number' ? a.z : 0,
        t: performance.now()
      });
      if (this.motionEvents.length > 300) this.motionEvents.shift();
    }

    _recordOrientation(e) {
      this.orientationEvents.push({
        alpha: typeof e.alpha === 'number' ? e.alpha : 0,
        beta: typeof e.beta === 'number' ? e.beta : 0,
        gamma: typeof e.gamma === 'number' ? e.gamma : 0,
        t: performance.now()
      });
      if (this.orientationEvents.length > 300) this.orientationEvents.shift();
    }

    analyze() {
      const motion = this.motionEvents;
      const orientation = this.orientationEvents;

      let motionAccelVariance = 0;
      let motionAccelAvg = 0;
      if (motion.length > 1) {
        const mags = motion.map(m => Math.sqrt(m.x*m.x + m.y*m.y + m.z*m.z));
        motionAccelAvg = mags.reduce((a, b) => a + b, 0) / mags.length;
        motionAccelVariance = mags.reduce((s, v) => s + (v - motionAccelAvg) * (v - motionAccelAvg), 0) / mags.length;
      }

      let orientationVariance = 0;
      if (orientation.length > 1) {
        const tilts = orientation.map(o => Math.abs(o.beta) + Math.abs(o.gamma));
        const mean = tilts.reduce((a, b) => a + b, 0) / tilts.length;
        orientationVariance = tilts.reduce((s, v) => s + (v - mean) * (v - mean), 0) / tilts.length;
      }

      return {
        motionEventCount: motion.length,
        motionAccelAvg,
        motionAccelVariance,
        orientationEventCount: orientation.length,
        orientationVariance,
        hasSensorSupport: typeof window.DeviceMotionEvent !== 'undefined'
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

      // Typing modality — see _recordModalityKey. Shape only, no content.
      this.typing = {
        pasteShortcutMeta: 0,      // Meta+V  (macOS muscle memory)
        pasteShortcutControl: 0,   // Ctrl+V  (Windows/Linux)
        selectAllShortcuts: 0,
        pasteEvents: 0,            // real `paste` events, anywhere on the page
        pasteInputs: 0,            // input events the browser attributes to a paste
        inputEvents: 0,
        inputsWithoutKeys: 0,      // text appeared with no keystroke behind it
        inputsWithoutInputType: 0, // synthetic events carry no inputType
        keydownsBeforeInput: 0     // running counter, reset on each input
      };

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

      // Typing modality (see _recordModality). Document-level and field-agnostic:
      // unlike the textarea keystroke stats, this records only *how* text arrived,
      // never what or where, so it is safe to run across every field including
      // password inputs a password manager fills.
      document.addEventListener('keydown', (e) => this._recordModalityKey(e), { passive: true });
      document.addEventListener('input', (e) => this._recordModalityInput(e), { passive: true });

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
          pasteCount: 0,
          dwellTimes: [],
          rollovers: 0,
          activeKeyCount: 0,
          pendingKeydowns: []
        });
      }

      const stats = this.textareaStats.get(textareaId);
      const now = performance.now();

      // Modifier keys excluded from dwell/rollover tracking
      const isModifier = ['Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'NumLock', 'ScrollLock'].includes(e.key);

      if (e.type === 'keydown') {
        stats.keydowns.push(now);
        if (stats.lastKeyTime !== null) {
          stats.intervals.push(now - stats.lastKeyTime);
        }
        stats.lastKeyTime = now;

        // Dwell/rollover tracking (non-modifier, non-repeat only)
        if (!isModifier && !e.repeat) {
          if (stats.activeKeyCount > 0) {
            stats.rollovers++;
          }
          stats.activeKeyCount++;
          stats.pendingKeydowns.push(now);
        }

        // Limit memory
        if (stats.keydowns.length > 200) stats.keydowns.shift();
        if (stats.intervals.length > 200) stats.intervals.shift();
      } else if (e.type === 'keyup') {
        stats.keyups.push(now);
        if (stats.keyups.length > 200) stats.keyups.shift();

        // Dwell time tracking (non-modifier only)
        if (!isModifier && stats.activeKeyCount > 0) {
          stats.activeKeyCount--;
          if (stats.pendingKeydowns.length > 0) {
            const keydownTime = stats.pendingKeydowns.shift();
            const dwell = now - keydownTime;
            if (dwell > 0 && dwell < 2000) {
              stats.dwellTimes.push(dwell);
              // Ring buffer: cap at 100
              if (stats.dwellTimes.length > 100) stats.dwellTimes.shift();
            }
          }
        }
      }
    }

    /**
     * Typing modality: how did text get into a field?
     *
     * Real keystrokes, a paste, a paste keyboard shortcut, or a value assigned
     * straight into the DOM all leave different traces, and agents differ from
     * each other as much as they differ from people — some drive keystrokes,
     * some fire Ctrl+V, some dispatch a bare `input`/`change` event.
     *
     * The most useful thing here is not a timing threshold but a
     * *contradiction*: an agent that fires Ctrl+V while its own navigator
     * reports MacIntel has told us two incompatible things about itself. Mac
     * users paste with Meta+V. That check needs no calibration, no distribution
     * and no per-machine tuning, which is what makes it worth having.
     *
     * Records shape only — which modifier accompanied a paste shortcut, and how
     * many inputs arrived with no keystroke behind them. Never key identities
     * (beyond the single 'v'), never field names, never content. That is why it
     * can safely run document-wide while the keystroke-cadence stats stay
     * confined to textareas.
     */
    _recordModalityKey(e) {
      const t = this.typing;
      if (e.key === 'v' || e.key === 'V') {
        // Which modifier the visitor's muscle memory reached for. On macOS that
        // is Meta; on Windows and Linux it is Control. Recording both lets the
        // server compare against the platform the client claims.
        if (e.metaKey && !e.ctrlKey) t.pasteShortcutMeta++;
        else if (e.ctrlKey && !e.metaKey) t.pasteShortcutControl++;
      }
      if (e.key === 'a' || e.key === 'A') {
        // Select-all before paste — the Comet-on-Windows shape noted in the PRD.
        if (e.metaKey || e.ctrlKey) t.selectAllShortcuts++;
      }
      if (!['Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'Tab'].includes(e.key)) {
        t.keydownsBeforeInput++;
      }
    }

    _recordModalityInput(e) {
      const t = this.typing;
      t.inputEvents++;

      // An input event with no keystroke and no paste behind it is a value that
      // was assigned, not typed. `inputType` distinguishes the browser's own
      // account of what happened; it is absent on synthetic events, which is
      // itself the tell.
      const inputType = e.inputType || null;
      if (inputType === null) t.inputsWithoutInputType++;
      else if (inputType.startsWith('insertFromPaste')) t.pasteInputs++;

      if (t.keydownsBeforeInput === 0 && t.pasteEvents === 0) t.inputsWithoutKeys++;
      t.keydownsBeforeInput = 0;
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

    _recordProgrammaticSubmit(_form) {
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

    _recordSubmit(_e) {
      const now = performance.now();

      // What gesture triggered this submit?
      //
      // Two things were wrong here and both punished real people.
      //
      // `touchstart` is recorded in the event log but was never consulted — only
      // keydown and mousedown were. A tap produces a compatibility mousedown, but
      // it can lag or be suppressed, so a genuine mobile submit was liable to be
      // classified programmatic. Same shape as the touch exemption bug fixed in
      // v1.18.0, and observed on real demo traffic.
      //
      // The window was also 100ms, measured from the gesture to the submit event.
      // A click has to travel mousedown -> mouseup -> click -> submit, through any
      // validation the page does, and on a loaded or low-end device that is easily
      // more than 100ms. Widening it costs little: an agent that dispatches a
      // synthetic gesture before submitting evades either way, so the check really
      // only separates "a gesture happened" from "nothing happened at all".
      //
      // Selecting by time rather than by the last five entries, because scroll
      // events share this log and could push the real trigger out of the window.
      const RECENT_GESTURE_MS = 500;
      const recent = this.eventLog.filter(ev => now - ev.time < RECENT_GESTURE_MS);
      const recentKeydown = recent.find(ev => ev.type === 'keydown');
      const recentMousedown = recent.find(ev => ev.type === 'mousedown');
      const recentTouch = recent.find(ev => ev.type === 'touchstart');

      let method = 'unknown';
      if (recentKeydown) {
        method = 'keyboard'; // Enter key or similar
      } else if (recentTouch) {
        method = 'touch'; // tap on a phone or tablet
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
          hadTriggerEvent: method === 'keyboard' || method === 'mouse' || method === 'touch'
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
          pasteCount: stats.pasteCount,
          intervals: stats.intervals.slice(-100),
          dwellTimes: stats.dwellTimes.slice(-100),
          rollovers: stats.rollovers
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
        textareaKeyboard: Object.keys(textareaAnalysis).length > 0 ? textareaAnalysis : null,

        // Typing modality (see _recordModalityKey)
        typing: { ...this.typing }
      };
    }

    // Track paste events on textareas
    recordPaste(e) {
      // Page-wide modality counter first: a human pasting into a login field is
      // still a human pasting, and the modality checks need to know that even
      // though the per-textarea stats deliberately do not look at that field.
      this.typing.pasteEvents++;

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
        cdp: this._detectCDP(),
        cdpRuntime: this._detectCDPRuntime(),
        playwright: this._detectPlaywright(),
        stealthArtifacts: this._detectStealthArtifacts(),

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

        // Advanced fingerprint detections
        mathFingerprint: this._getMathFingerprint(),
        errorFingerprint: this._getErrorFingerprint(),
        domRectFingerprint: this._getDOMRectFingerprint(),
        cssMediaQueries: this._getCSSMediaQueries(),
        permissionsInfo: this._getPermissionsInfo(),
        fontsInfo: this._getFontsInfo(),
      };
    }

    // Async detections collected separately
    async collectAsync() {
      const [speechInfo, webrtcInfo, workerConsistency, permissionProbe] = await Promise.all([
        this._getSpeechInfo(),
        this._getWebRTCInfo(),
        this._checkWorkerConsistency(),
        this._checkPermissionContradiction()
      ]);
      return { speechInfo, webrtcInfo, workerConsistency, permissionProbe };
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

    _detectPlaywright() {
      try {
        const signals = [];

        // Check for Playwright window properties
        const pwKeys = Object.getOwnPropertyNames(window).filter(k =>
          k.startsWith('__pw') || k.startsWith('__playwright')
        );
        if (pwKeys.length > 0) signals.push('playwright_globals');

        // Check if navigator.webdriver was deleted.
        //
        // Deletion is deliberate tampering: the property is defined on
        // Navigator.prototype in every current browser, so its absence cannot
        // happen by accident.
        //
        // What is NOT checked here any more is whether the descriptor is
        // *configurable*. That was reported as `webdriver_configurable` and
        // treated as an automation artifact, and it is not one — WebIDL defines
        // the attribute as configurable, so an ordinary browser reports exactly
        // what a patched one does. Measured in Chrome 150 with
        // navigator.webdriver === false: descriptor present, configurable true.
        const proto = Object.getPrototypeOf(navigator);
        const desc = Object.getOwnPropertyDescriptor(proto, 'webdriver');
        if (!desc) {
          signals.push('webdriver_deleted');
        }

        // chrome.runtime is NOT checked either, for the same reason. It is only
        // exposed to a page when an extension declares externally_connectable
        // matching it, so on an ordinary site an ordinary Chrome has no
        // chrome.runtime at all. Measured in Chrome 150: window.chrome present,
        // chrome.runtime absent, on a page with no such extension.
        //
        // Both checks fired together on genuine browsers, which is the worst
        // shape a signal can have: common, correlated, and confidently wrong.

        return { detected: signals.length > 0, signals };
      } catch (e) {
        return { detected: false, signals: [] };
      }
    }

    // Detect stealth-automation patch artifacts. A genuine browser keeps its
    // built-in functions native and internally consistent. Anti-detection
    // tooling (puppeteer-extra-stealth, patchright, etc.) overrides natives to
    // spoof fingerprints and then hides the overrides — leaving traces a real
    // user never produces. Returns a list of signal strings; the server scores
    // only the false-positive-safe ones (see server detectStealthArtifacts).
    _detectStealthArtifacts() {
      const signals = [];
      try {
        // Pristine reference to the native toString. Used to stringify other
        // functions so a patched Function.prototype.toString can't mask them.
        const fnToString = Function.prototype.toString;
        const isNative = (fn) => {
          if (typeof fn !== 'function') return true; // not a function: ignore
          try {
            return /\{\s*\[native code\]\s*\}/.test(fnToString.call(fn));
          } catch (e) {
            // A throwing toString is itself anomalous, but be conservative.
            return true;
          }
        };

        // 1. FP-SAFE: Function.prototype.toString itself must be native.
        //    Stealth tooling proxies it to make its other overrides look native
        //    — essentially the signature move of anti-detection frameworks.
        //    Real browsers (and privacy extensions) leave it untouched.
        if (!isNative(fnToString)) signals.push('tostring_proxied');

        // 2. Observability only (NOT scored server-side): native functions that
        //    stealth tooling commonly overrides. Legitimate privacy/anti-
        //    fingerprint extensions also patch some of these (canvas/webgl), so
        //    they are collected for analysis but never affect the verdict.
        const watched = {
          'permissions_query': navigator.permissions && navigator.permissions.query,
          'webgl_getparameter': typeof WebGLRenderingContext !== 'undefined' && WebGLRenderingContext.prototype.getParameter,
          'canvas_todataurl': typeof HTMLCanvasElement !== 'undefined' && HTMLCanvasElement.prototype.toDataURL,
        };
        for (const name in watched) {
          const fn = watched[name];
          if (fn && !isNative(fn)) signals.push('patched_' + name);
        }
      } catch (e) {
        // Never let collection throw.
      }
      return { signals };
    }

    // FP-SAFE permission-state contradiction. In a real browser, when
    // Notification.permission is "denied" the Permissions API must also report
    // "denied". Headless/stealth Chromium classically reports "denied" while the
    // Permissions API still says "prompt" (or stealth tooling patches query to
    // paper over it but misses an edge) — a state a genuine browser can't reach.
    async _checkPermissionContradiction() {
      try {
        if (typeof Notification === 'undefined' || !navigator.permissions || !navigator.permissions.query) {
          return { supported: false };
        }
        const notif = Notification.permission;
        let queryState = null;
        try {
          const status = await navigator.permissions.query({ name: 'notifications' });
          queryState = status && status.state;
        } catch (e) {
          return { supported: false };
        }
        const contradiction = notif === 'denied' && queryState === 'prompt';
        return { supported: true, notificationPermission: notif, queryState, contradiction };
      } catch (e) {
        return { supported: false };
      }
    }

    // Detect an attached CDP Runtime/DevTools console consumer. When a client
    // (DevTools, chrome.debugger, Playwright/Puppeteer over CDP) is attached and
    // consuming console output, the host eagerly serializes logged objects,
    // firing accessor traps that never fire for an ordinary visitor. Low
    // confidence server-side: a developer with DevTools open also trips this.
    _detectCDPRuntime() {
      let consoleAttached = false;
      try {
        const bait = new Error();
        Object.defineProperty(bait, 'message', {
          configurable: true,
          get() { consoleAttached = true; return ''; }
        });
        // debug level is hidden from the visible console by default, so this is
        // silent for real users while still serialized by an attached consumer.
        console.debug(bait);
      } catch (_e) {
        consoleAttached = false;
      }
      return { consoleAttached };
    }

    _detectCDP() {
      try {
        const signals = [];

        // ChromeDriver injects cdc_ prefixed properties (ChromeDriver Canary Detection)
        // These are randomly named but always start with cdc_
        const cdcKeys = Object.keys(window).filter(k => k.startsWith('cdc_'));
        if (cdcKeys.length > 0) {
          signals.push('chromedriver_cdc');
        }

        // Selenium WebDriver specific properties
        if ('__webdriver_evaluate' in window) signals.push('selenium_evaluate');
        if ('__driver_evaluate' in window) signals.push('selenium_driver_evaluate');
        if ('__webdriver_unwrapped' in window) signals.push('selenium_unwrapped');
        if ('__driver_unwrapped' in window) signals.push('selenium_driver_unwrapped');
        if ('__selenium_evaluate' in window) signals.push('selenium_direct');
        if ('__fxdriver_evaluate' in window) signals.push('firefox_driver');
        if ('__fxdriver_unwrapped' in window) signals.push('firefox_driver_unwrapped');

        // Puppeteer-specific CDP artifacts
        if ('__puppeteer_evaluation_script__' in window) signals.push('puppeteer_eval');

        // Check for CDP Runtime.evaluate artifacts
        // These appear when scripts are injected via CDP
        if (document.__webdriver_script_fn) signals.push('cdp_script_injection');

        // Check for modified navigator.webdriver getter
        // Some tools try to hide webdriver but leave traces
        try {
          const descriptor = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
          if (descriptor && typeof descriptor.get === 'function') {
            const getterStr = descriptor.get.toString();
            if (getterStr.indexOf('[native code]') === -1) {
              signals.push('webdriver_getter_modified');
            }
          }
        } catch (e) {
          // Skip if can't access descriptor
        }

        return {
          detected: signals.length > 0,
          signals: signals
        };
      } catch (e) {
        return { detected: false, signals: [] };
      }
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
      results.arrayLen = arr.length; // Ensure array is "used" to prevent optimization

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

    // ============================================================
    // Advanced Fingerprint Detection Methods
    // ============================================================

    /**
     * Math fingerprint - Different JS engines produce slightly different results
     * for certain math operations. Headless browsers/VMs may show inconsistencies.
     */
    _getMathFingerprint() {
      try {
        const results = {
          // These produce engine-specific results
          acos: Math.acos(0.123456789),
          acosh: Math.acosh(1e308),
          asin: Math.asin(0.123456789),
          asinh: Math.asinh(1),
          atanh: Math.atanh(0.5),
          cbrt: Math.cbrt(100),
          cosh: Math.cosh(1),
          expm1: Math.expm1(1),
          log1p: Math.log1p(10),
          sinh: Math.sinh(1),
          tan: Math.tan(-1e308),
          tanh: Math.tanh(1),
          // These can expose VM artifacts
          pow: Math.pow(Math.PI, -100),
          sin: Math.sin(Math.PI),
        };

        // Create a hash of the results
        const str = Object.values(results).map(v => String(v)).join(',');
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
          hash = ((hash << 5) - hash) + str.charCodeAt(i);
          hash = hash & hash;
        }

        return {
          hash: hash.toString(16),
          // Include a few key values for cross-checking
          sinPi: results.sin,
          tanLarge: results.tan,
          supported: true
        };
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    /**
     * Error fingerprint - Error message formatting varies by engine
     * Uses safe error triggers (no eval/Function) to get engine-specific messages
     */
    _getErrorFingerprint() {
      try {
        const errors = {};

        // TypeError - null property access
        try { null.foo; } catch (e) { errors.typeError = e.message; }

        // RangeError - invalid array length
        try { [].length = -1; } catch (e) { errors.rangeError = e.message; }

        // URIError - bad URI encoding
        try { decodeURIComponent('%'); } catch (e) { errors.uriError = e.message; }

        // ReferenceError - undefined variable (via indirect detection)
        try {
          const obj = {};
          obj.undefinedMethod();
        } catch (e) { errors.refTypeError = e.message; }

        // Generate hash from error messages
        const str = Object.values(errors).join('|');
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
          hash = ((hash << 5) - hash) + str.charCodeAt(i);
          hash = hash & hash;
        }

        return {
          hash: hash.toString(16),
          typeError: errors.typeError,
          supported: true
        };
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    /**
     * DOMRect fingerprint - Element rendering varies slightly between browsers/configs
     */
    _getDOMRectFingerprint() {
      try {
        const container = document.createElement('div');
        container.style.cssText = 'position:absolute;left:-9999px;font-size:16px;font-family:Arial,sans-serif;';

        // Test element A - simple text
        const textA = document.createElement('span');
        textA.textContent = 'FCaptcha Test String 123';
        container.appendChild(textA);

        // Test element B - styled text
        const textB = document.createElement('span');
        textB.style.cssText = 'letter-spacing:1px;word-spacing:2px;';
        textB.textContent = 'WWWW 0000';
        container.appendChild(textB);

        document.body.appendChild(container);

        const rectA = textA.getBoundingClientRect();
        const rectB = textB.getBoundingClientRect();

        // Create range for additional precision
        const range = document.createRange();
        range.selectNode(textA);
        const rangeRect = range.getBoundingClientRect();

        document.body.removeChild(container);

        // Hash the measurements
        const values = [
          rectA.width, rectA.height, rectA.x, rectA.y,
          rectB.width, rectB.height,
          rangeRect.width, rangeRect.height
        ];

        const str = values.map(v => v.toFixed(6)).join(',');
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
          hash = ((hash << 5) - hash) + str.charCodeAt(i);
          hash = hash & hash;
        }

        return {
          hash: hash.toString(16),
          rectAWidth: rectA.width,
          rectBWidth: rectB.width,
          rangeWidth: rangeRect.width,
          supported: true
        };
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    /**
     * CSS Media Queries - Detect screen/device characteristics
     */
    _getCSSMediaQueries() {
      try {
        const queries = {
          // Color scheme preference
          prefersColorScheme: window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
          prefersReducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
          prefersReducedTransparency: window.matchMedia('(prefers-reduced-transparency: reduce)').matches,
          prefersContrast: window.matchMedia('(prefers-contrast: more)').matches ? 'more' :
                          window.matchMedia('(prefers-contrast: less)').matches ? 'less' : 'no-preference',

          // Pointer capabilities (helps identify device type)
          anyHover: window.matchMedia('(any-hover: hover)').matches,
          anyPointer: window.matchMedia('(any-pointer: fine)').matches ? 'fine' :
                      window.matchMedia('(any-pointer: coarse)').matches ? 'coarse' : 'none',
          hover: window.matchMedia('(hover: hover)').matches,
          pointer: window.matchMedia('(pointer: fine)').matches ? 'fine' :
                   window.matchMedia('(pointer: coarse)').matches ? 'coarse' : 'none',

          // Display characteristics
          colorGamut: window.matchMedia('(color-gamut: p3)').matches ? 'p3' :
                      window.matchMedia('(color-gamut: srgb)').matches ? 'srgb' : 'none',
          displayMode: window.matchMedia('(display-mode: standalone)').matches ? 'standalone' :
                       window.matchMedia('(display-mode: fullscreen)').matches ? 'fullscreen' : 'browser',
          orientation: window.matchMedia('(orientation: portrait)').matches ? 'portrait' : 'landscape',

          // HDR
          dynamicRange: window.matchMedia('(dynamic-range: high)').matches ? 'high' : 'standard',

          // Forced colors (accessibility)
          forcedColors: window.matchMedia('(forced-colors: active)').matches
        };

        return { ...queries, supported: true };
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    /**
     * Permissions API - Check browser permission states
     */
    _getPermissionsInfo() {
      // Sync check - async detailed check happens separately
      try {
        return {
          hasPermissionsAPI: 'permissions' in navigator,
          hasClipboard: 'clipboard' in navigator,
          hasShare: 'share' in navigator,
          hasCredentials: 'credentials' in navigator,
          hasBluetooth: 'bluetooth' in navigator,
          hasUsb: 'usb' in navigator,
          hasSerial: 'serial' in navigator,
          hasHid: 'hid' in navigator,
          hasXR: 'xr' in navigator,
          hasGeolocation: 'geolocation' in navigator,
          hasMIDI: 'requestMIDIAccess' in navigator,
          supported: true
        };
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    /**
     * Font detection - Check for system fonts
     * Uses canvas-based detection (fast, doesn't require font loading)
     */
    _getFontsInfo() {
      try {
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testFonts = [
          // Common system fonts
          'Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Georgia',
          'Verdana', 'Trebuchet MS', 'Comic Sans MS', 'Impact', 'Lucida Console',
          // Mac fonts
          'Menlo', 'Monaco', 'SF Pro', 'Helvetica Neue',
          // Windows fonts
          'Segoe UI', 'Consolas', 'Calibri', 'Cambria',
          // Linux fonts
          'DejaVu Sans', 'Liberation Sans', 'Ubuntu', 'Cantarell',
          // CJK fonts
          'MS Gothic', 'Meiryo', 'SimHei', 'Microsoft YaHei'
        ];

        const canvas = document.createElement('canvas');
        canvas.width = 400;
        canvas.height = 40;
        const ctx = canvas.getContext('2d');

        const testString = 'mmMWWLLiiff00';
        const testSize = '72px';

        // Get baseline widths
        const baseWidths = {};
        for (const baseFont of baseFonts) {
          ctx.font = testSize + ' ' + baseFont;
          baseWidths[baseFont] = ctx.measureText(testString).width;
        }

        // Test each font against baselines
        const detectedFonts = [];
        for (const font of testFonts) {
          let detected = false;
          for (const baseFont of baseFonts) {
            ctx.font = testSize + ' "' + font + '", ' + baseFont;
            const width = ctx.measureText(testString).width;
            if (width !== baseWidths[baseFont]) {
              detected = true;
              break;
            }
          }
          if (detected) {
            detectedFonts.push(font);
          }
        }

        // Create hash of detected fonts
        const str = detectedFonts.join(',');
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
          hash = ((hash << 5) - hash) + str.charCodeAt(i);
          hash = hash & hash;
        }

        return {
          hash: hash.toString(16),
          count: detectedFonts.length,
          // Only include a few key fonts to keep payload small
          hasArial: detectedFonts.includes('Arial'),
          hasTimesNewRoman: detectedFonts.includes('Times New Roman'),
          hasSegoeUI: detectedFonts.includes('Segoe UI'),
          hasSFPro: detectedFonts.includes('SF Pro'),
          hasDejaVuSans: detectedFonts.includes('DejaVu Sans'),
          // OS-coherence markers (PRD §7.3). Calibri ships with Windows/Office;
          // Menlo is macOS-only. Reported so the server can score a font list
          // that *contradicts* the claimed platform — never raw enumeration,
          // which fires on privacy extensions and minimal Linux installs.
          hasCalibri: detectedFonts.includes('Calibri'),
          hasMenlo: detectedFonts.includes('Menlo'),
          supported: true
        };
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    /**
     * Speech Synthesis API - Get available voices
     * Voices are OS/browser specific and hard to spoof
     */
    async _getSpeechInfo() {
      try {
        if (!('speechSynthesis' in window)) {
          return { supported: false };
        }

        // Voices may load async
        const getVoices = () => {
          return new Promise((resolve) => {
            let voices = speechSynthesis.getVoices();
            if (voices.length > 0) {
              resolve(voices);
              return;
            }

            // Wait for voiceschanged event
            const timeout = setTimeout(() => resolve([]), 1000);
            speechSynthesis.onvoiceschanged = () => {
              clearTimeout(timeout);
              resolve(speechSynthesis.getVoices());
            };
          });
        };

        const voices = await getVoices();

        // Categorize voices
        const localVoices = voices.filter(v => v.localService);
        const defaultVoice = voices.find(v => v.default);

        // Get unique languages
        const languages = [...new Set(voices.map(v => v.lang))];

        // Create hash
        const voiceNames = voices.map(v => v.name).sort().join(',');
        let hash = 0;
        for (let i = 0; i < voiceNames.length; i++) {
          hash = ((hash << 5) - hash) + voiceNames.charCodeAt(i);
          hash = hash & hash;
        }

        return {
          hash: hash.toString(16),
          totalVoices: voices.length,
          localVoices: localVoices.length,
          languages: languages.length,
          defaultVoiceLang: defaultVoice?.lang || null,
          hasGoogleVoices: voices.some(v => v.name.includes('Google')),
          hasMicrosoftVoices: voices.some(v => v.name.includes('Microsoft')),
          hasAppleVoices: voices.some(v => v.name.includes('Samantha') || v.name.includes('Alex')),
          supported: true
        };
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    /**
     * WebRTC fingerprinting - Get local IPs and media devices
     * Very effective for detecting VMs, proxies, and headless browsers
     */
    async _getWebRTCInfo() {
      try {
        const info = {
          supported: 'RTCPeerConnection' in window,
          mediaDevices: { supported: false },
          localIPs: []
        };

        if (!info.supported) return info;

        // Get media devices (doesn't require permission for enumeration)
        if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
          try {
            const devices = await navigator.mediaDevices.enumerateDevices();
            info.mediaDevices = {
              supported: true,
              audioInputs: devices.filter(d => d.kind === 'audioinput').length,
              audioOutputs: devices.filter(d => d.kind === 'audiooutput').length,
              videoInputs: devices.filter(d => d.kind === 'videoinput').length,
              // Headless browsers typically have 0 devices
              totalDevices: devices.length
            };
          } catch (e) {
            info.mediaDevices = { supported: false, error: true };
          }
        }

        // Get local IPs via WebRTC (no permission needed)
        try {
          const pc = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
          });

          const localIPs = new Set();

          pc.onicecandidate = (event) => {
            if (event.candidate) {
              const candidate = event.candidate.candidate;
              // Extract IP addresses from ICE candidates
              const ipRegex = /([0-9]{1,3}\.){3}[0-9]{1,3}/g;
              const matches = candidate.match(ipRegex);
              if (matches) {
                matches.forEach(ip => {
                  // Filter out STUN server responses, keep only local IPs
                  if (ip.startsWith('192.168.') || ip.startsWith('10.') ||
                      ip.startsWith('172.') || ip.startsWith('169.254.')) {
                    localIPs.add(ip);
                  }
                });
              }
            }
          };

          // Create data channel to trigger ICE gathering
          pc.createDataChannel('');
          await pc.createOffer().then(offer => pc.setLocalDescription(offer));

          // Wait briefly for ICE candidates
          await new Promise(r => setTimeout(r, 500));

          info.localIPs = Array.from(localIPs);
          info.hasLocalIP = localIPs.size > 0;

          pc.close();
        } catch (e) {
          info.localIPError = true;
        }

        return info;
      } catch (e) {
        return { supported: false, error: true };
      }
    }

    /**
     * Worker consistency check - Compare main thread vs worker values
     * Spoofed values often don't match between contexts
     */
    async _checkWorkerConsistency() {
      try {
        if (typeof Worker === 'undefined') {
          return { supported: false };
        }

        // Create inline worker
        const workerCode = `
          self.onmessage = function() {
            const data = {
              userAgent: navigator.userAgent,
              language: navigator.language,
              languages: navigator.languages ? Array.from(navigator.languages) : [],
              platform: navigator.platform,
              hardwareConcurrency: navigator.hardwareConcurrency,
              deviceMemory: navigator.deviceMemory,
              timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
              timezoneOffset: new Date().getTimezoneOffset()
            };
            self.postMessage(data);
          };
        `;

        const blob = new Blob([workerCode], { type: 'application/javascript' });
        const worker = new Worker(URL.createObjectURL(blob));

        const workerData = await new Promise((resolve, reject) => {
          const timeout = setTimeout(() => reject(new Error('timeout')), 2000);
          worker.onmessage = (e) => {
            clearTimeout(timeout);
            resolve(e.data);
          };
          worker.onerror = () => {
            clearTimeout(timeout);
            reject(new Error('worker error'));
          };
          worker.postMessage('collect');
        });

        worker.terminate();

        // Compare with main thread values
        const mainData = {
          userAgent: navigator.userAgent,
          language: navigator.language,
          languages: navigator.languages ? Array.from(navigator.languages) : [],
          platform: navigator.platform,
          hardwareConcurrency: navigator.hardwareConcurrency,
          deviceMemory: navigator.deviceMemory,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          timezoneOffset: new Date().getTimezoneOffset()
        };

        // Check for mismatches (indicates spoofing)
        const mismatches = [];
        if (workerData.userAgent !== mainData.userAgent) mismatches.push('userAgent');
        if (workerData.language !== mainData.language) mismatches.push('language');
        if (workerData.platform !== mainData.platform) mismatches.push('platform');
        if (workerData.hardwareConcurrency !== mainData.hardwareConcurrency) mismatches.push('hardwareConcurrency');
        if (workerData.deviceMemory !== mainData.deviceMemory) mismatches.push('deviceMemory');
        if (workerData.timezone !== mainData.timezone) mismatches.push('timezone');
        if (workerData.timezoneOffset !== mainData.timezoneOffset) mismatches.push('timezoneOffset');
        if (JSON.stringify(workerData.languages) !== JSON.stringify(mainData.languages)) mismatches.push('languages');

        return {
          supported: true,
          consistent: mismatches.length === 0,
          mismatches: mismatches,
          mismatchCount: mismatches.length
        };
      } catch (e) {
        return { supported: false, error: true };
      }
    }
  }

  // ============================================================
  // SHA-256 Helper (main thread)
  // ============================================================

  async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ============================================================
  // Proof of Work Manager (Web Worker based)
  // ============================================================

  class PoWManager {
    constructor() {
      this.workers = [];
      this.challenge = null;
      this.solution = null;
      this.solving = false;
      this.solvePromise = null;
      this.startTime = null;
    }

    // Create inline Web Worker for PoW computation.
    // Each worker scans a disjoint nonce slice via (startNonce + k*stride),
    // so N workers explore the search space N-way in parallel.
    _createWorker() {
      const workerCode = `
        async function sha256(message) {
          const msgBuffer = new TextEncoder().encode(message);
          const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }

        self.onmessage = async function(e) {
          const { prefix, difficulty, signalsHash, startNonce = 0, stride = 1, batchSize = 10000 } = e.data;
          const target = '0'.repeat(difficulty);
          let nonce = startNonce;
          let iterations = 0;
          const startTime = performance.now();

          // Build PoW input: include signalsHash if provided
          const inputPrefix = signalsHash ? prefix + ':' + signalsHash : prefix;

          while (true) {
            // Process in batches for better responsiveness
            for (let i = 0; i < batchSize; i++) {
              const hash = await sha256(inputPrefix + ':' + nonce);
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
              nonce += stride;
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

    // Pick a worker count that uses available cores without monopolizing them.
    // Half of hardwareConcurrency leaves headroom for the page itself.
    _threadCount() {
      const hc = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 1;
      return Math.max(1, Math.floor(hc / 2));
    }

    _terminateWorkers() {
      for (const w of this.workers) {
        try { w.terminate(); } catch (_) { /* ignore */ }
      }
      this.workers = [];
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
        if (!response.ok) {
          console.warn('PoW challenge fetch failed (status ' + response.status + '), using local challenge');
          return this._generateLocalChallenge();
        }
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

    // Start solving in background (legacy - solve without signals binding)
    async startSolving(siteKey) {
      return this._solve(siteKey, null);
    }

    // Solve with signals hash bound into PoW input
    async solveWithSignalsHash(siteKey, signalsHash) {
      return this._solve(siteKey, signalsHash);
    }

    async _solve(siteKey, signalsHash) {
      if (this.solving) return this.solvePromise;

      // Fetch challenge if not already fetched
      if (!this.challenge) {
        await this.fetchChallenge(siteKey);
      }

      this.solving = true;
      this.startTime = performance.now();

      this.solvePromise = new Promise((resolve, reject) => {
        const threads = this._threadCount();
        let settled = false;

        const finish = (fn, value) => {
          if (settled) return;
          settled = true;
          this.solving = false;
          this._terminateWorkers();
          fn(value);
        };

        for (let i = 0; i < threads; i++) {
          const worker = this._createWorker();

          worker.onmessage = (e) => {
            if (e.data.found) {
              // Report the winning worker's iteration count, not the sum across
              // workers. With N-way striding the winner has explored ~total/N
              // iterations in wall-clock time ~total/(N*rate), so the ratio
              // iterations/duration stays at the per-thread browser hash rate
              // that server-side timing detection (server.js) expects.
              this.solution = {
                challengeId: this.challenge.challengeId,
                nonce: e.data.nonce,
                hash: e.data.hash,
                iterations: e.data.iterations,
                duration: e.data.duration,
                difficulty: this.challenge.difficulty,
                signalsHash: signalsHash || null,
                local: this.challenge.local || false
              };
              finish(resolve, this.solution);
            }
            // Progress updates can be used for UI if needed
          };

          worker.onerror = (e) => {
            finish(reject, e);
          };

          worker.postMessage({
            prefix: this.challenge.prefix,
            difficulty: this.challenge.difficulty,
            signalsHash: signalsHash || null,
            startNonce: i,
            stride: threads,
            batchSize: 5000
          });

          this.workers.push(worker);
        }
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
      this._terminateWorkers();
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
      this.sensor = new SensorCollector();
      this.powManager = getPoWManager();
      this.token = null;
      this.verified = false;

      this._init();
    }

    _init() {
      this._createWidget();
      this._attachListeners();
      // Fetch challenge eagerly but defer solving until signals are collected
      this._fetchChallenge();
    }

    async _fetchChallenge() {
      try {
        await this.powManager.fetchChallenge(this.options.siteKey);
      } catch (e) {
        console.warn('PoW challenge fetch failed:', e);
      }
    }

    _createWidget() {
      const isDark = this.options.theme === 'dark';

      this.container.innerHTML = `
        <div class="fcaptcha-widget ${isDark ? 'fcaptcha-dark' : ''}" id="${this.id}">
          <style>
            .fcaptcha-widget {
              font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif;
              background: ${isDark ? '#1e1e1e' : '#fafafa'};
              border: 1px solid ${isDark ? '#424242' : '#d3d3d3'};
              border-radius: 6px;
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
              border-radius: 4px;
              cursor: pointer;
              display: flex;
              align-items: center;
              justify-content: center;
              background: ${isDark ? '#252525' : '#fff'};
              transition: all 0.15s ease;
              flex-shrink: 0;
            }
            .fcaptcha-checkbox:hover { border-color: #00bcd4; }
            .fcaptcha-checkbox.loading { border-color: #00bcd4; }
            .fcaptcha-checkbox.verified { background: #4caf50; border-color: #4caf50; }
            .fcaptcha-checkbox.failed { background: #f44336; border-color: #f44336; }
            .fcaptcha-spinner {
              width: 16px;
              height: 16px;
              border: 2px solid ${isDark ? '#555' : '#e0e0e0'};
              border-top-color: #00bcd4;
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
            .fcaptcha-brand { font-size: 11px; font-weight: 600; color: #ff2a6d; letter-spacing: 0.5px; }
            .fcaptcha-logo { font-size: 9px; font-weight: 500; color: ${isDark ? '#808080' : '#999'}; }
          </style>
          <div class="fcaptcha-checkbox" role="checkbox" aria-checked="false" tabindex="0">
            <div class="fcaptcha-spinner" style="display: none;"></div>
            <span class="fcaptcha-checkmark">✓</span>
            <span class="fcaptcha-x">✕</span>
          </div>
          <span class="fcaptcha-label">I'm not a robot</span>
          <div class="fcaptcha-branding">
            <span class="fcaptcha-brand">WebDecoy</span>
            <span class="fcaptcha-logo">FCaptcha</span>
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
      document.addEventListener('touchstart', (e) => this.behavioral.recordTouch(e), { passive: true });
      document.addEventListener('touchmove', (e) => this.behavioral.recordTouch(e), { passive: true });
      document.addEventListener('pointermove', (e) => this.behavioral.recordPointer(e), { passive: true });
      document.addEventListener('pointerdown', (e) => this.behavioral.recordPointer(e), { passive: true });
      document.addEventListener('pointerup', (e) => this.behavioral.recordPointer(e), { passive: true });
      document.addEventListener('focus', (e) => this.behavioral.recordFocus(e), { passive: true, capture: true });
      document.addEventListener('blur', (e) => this.behavioral.recordFocus(e), { passive: true, capture: true });

      // Passive device sensors (no permission request; absence treated as neutral server-side)
      this.sensor.attach();

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
        // Step 1: Collect all signals (sync and async in parallel)
        const behavioralData = this.behavioral.analyze();
        const clickData = this.behavioral.analyzeClick(e.clientX, e.clientY, rect);
        const envData = this.environmental.collect();

        const [rafData, asyncEnvData] = await Promise.all([
          this.environmental.measureRAFConsistency(),
          this.environmental.collectAsync()
        ]);

        // Collect temporal data WITHOUT pow timing (not yet solved)
        const temporalData = this.temporal.collect(clickTime);

        const formAnalysis = getFormAnalyzer().analyze();

        // Step 2: Build signals object (without pow timing)
        const sensorData = this.sensor.analyze();
        const signals = {
          behavioral: { ...behavioralData, ...clickData },
          environmental: { ...envData, rafConsistency: rafData, ...asyncEnvData, sensor: sensorData },
          temporal: temporalData,
          formAnalysis: formAnalysis,
          meta: {
            widgetId: this.id,
            siteKey: this.options.siteKey,
            challengeNonce: this.powManager.challenge?.nonce || null,
            timestamp: Date.now(),
            userAgent: navigator.userAgent,
            screenSize: `${screen.width}x${screen.height}`,
            viewportSize: `${window.innerWidth}x${window.innerHeight}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
          }
        };

        // Step 3: Serialize and hash signals for PoW binding
        const signalsJson = JSON.stringify(signals);
        const signalsHash = await sha256(signalsJson);

        // Step 4: Solve PoW with signalsHash bound
        const powSolution = await this.powManager.solveWithSignalsHash(this.options.siteKey, signalsHash);

        // Step 5: Build powTiming separately (not part of committed signals)
        const powTiming = {
          duration: powSolution.duration,
          iterations: powSolution.iterations,
          difficulty: powSolution.difficulty
        };

        // Step 6: Submit with signals, signalsJson, signalsHash, and powTiming
        const result = await this._verify(signals, powSolution, signalsJson, signalsHash, powTiming);

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

    async _verify(signals, powSolution = null, signalsJson = null, signalsHash = null, powTiming = null) {
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
            signalsJson: signalsJson || null,
            powSolution: powSolution ? {
              challengeId: powSolution.challengeId,
              nonce: powSolution.nonce,
              hash: powSolution.hash,
              signalsHash: signalsHash || null
            } : null,
            powTiming: powTiming || null
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

      // Zero mouse movement detection (AI agent / programmatic click)
      // Exempt touch users (mobile) and keyboard-only users (accessibility)
      const isTouchUser = (b.touchEvents || 0) >= 3;
      const isKbdUser = (b.keyEvents || 0) > 0 && b.totalPoints === 0;
      if (b.totalPoints < 5 && b.trajectoryLength < 10 && !isTouchUser && !isKbdUser) score += 0.35;
      else if (b.totalPoints < 10 && !isTouchUser && !isKbdUser && b.trajectoryLength < 30) score += 0.15;

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
      if (this.sensor) this.sensor.detach();
      this.sensor = new SensorCollector();
      this.sensor.attach();
      this.powManager.reset();
      this.checkbox.classList.remove('verified', 'failed', 'loading');
      this.checkbox.setAttribute('aria-checked', 'false');
      this.spinner.style.display = 'none';
      this.label.textContent = "I'm not a robot";
      // Fetch new challenge in background
      this._fetchChallenge();
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
      this.sensor = new SensorCollector();
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

      // Fetch challenge eagerly but defer solving until signals are collected
      this._fetchChallenge();
    }

    async _fetchChallenge() {
      try {
        await this.powManager.fetchChallenge(this.options.siteKey);
      } catch (e) {
        console.warn('PoW challenge fetch failed:', e);
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
        pointermove: (e) => this.behavioral.recordPointer(e),
        pointerdown: (e) => this.behavioral.recordPointer(e),
        pointerup: (e) => this.behavioral.recordPointer(e),
        focus: (e) => this.behavioral.recordFocus(e),
        blur: (e) => this.behavioral.recordFocus(e)
      };

      for (const [event, handler] of Object.entries(handlers)) {
        const opts = event === 'focus' || event === 'blur' ?
          { passive: true, capture: true } : { passive: true };
        document.addEventListener(event, handler, opts);
        this.listeners.push({ event, handler, opts });
      }

      // Passive device sensors (no permission request)
      this.sensor.attach();
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

      // Step 1: Collect all signals
      const behavioralData = this.behavioral.analyze();
      const envData = this.environmental.collect();

      // Collect temporal data WITHOUT pow timing (not yet solved)
      const temporalData = this.temporal.collect(Date.now());

      const [rafData, asyncEnvData] = await Promise.all([
        this.environmental.measureRAFConsistency(),
        this.environmental.collectAsync()
      ]);

      const formAnalysis = getFormAnalyzer().analyze();

      // Step 2: Build signals object (without pow timing)
      const sensorData = this.sensor.analyze();
      const signals = {
        behavioral: behavioralData,
        environmental: { ...envData, rafConsistency: rafData, ...asyncEnvData, sensor: sensorData },
        temporal: temporalData,
        formAnalysis: formAnalysis,
        meta: {
          sessionId: this.id,
          siteKey: this.options.siteKey,
          action,
          challengeNonce: this.powManager.challenge?.nonce || null,
          timestamp: Date.now(),
          userAgent: navigator.userAgent,
          screenSize: `${screen.width}x${screen.height}`,
          viewportSize: `${window.innerWidth}x${window.innerHeight}`,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          sessionDuration: Date.now() - this.startTime,
          invisible: true
        }
      };

      // Step 3: Serialize and hash signals for PoW binding
      const signalsJson = JSON.stringify(signals);
      const signalsHash = await sha256(signalsJson);

      // Step 4: Solve PoW with signalsHash bound
      const powSolution = await this.powManager.solveWithSignalsHash(this.options.siteKey, signalsHash);

      // Step 5: Build powTiming separately
      const powTiming = {
        duration: powSolution.duration,
        iterations: powSolution.iterations,
        difficulty: powSolution.difficulty
      };

      // Step 6: Submit
      const result = await this._score(signals, action, powSolution, signalsJson, signalsHash, powTiming);
      this.lastScore = { ...result, timestamp: Date.now() };
      return result;
    }

    async _score(signals, action, powSolution = null, signalsJson = null, signalsHash = null, powTiming = null) {
      const url = this.options.serverUrl || FCaptcha.serverUrl;

      if (!url) return this._clientSideScore(signals);

      try {
        const response = await fetch(url + '/api/score', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            siteKey: this.options.siteKey,
            signals,
            signalsJson: signalsJson || null,
            action,
            powSolution: powSolution ? {
              challengeId: powSolution.challengeId,
              nonce: powSolution.nonce,
              hash: powSolution.hash,
              signalsHash: signalsHash || null
            } : null,
            powTiming: powTiming || null
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

      // Zero mouse movement detection (AI agent / programmatic click)
      // Exempt touch users (mobile) and keyboard-only users (accessibility)
      const isTouchUsr = (b.touchEvents || 0) >= 3;
      const isKbdUsr = (b.keyEvents || 0) > 0 && b.totalPoints === 0;
      if (b.totalPoints < 5 && b.trajectoryLength < 10 && !isTouchUsr && !isKbdUsr) score += 0.35;
      else if (b.totalPoints < 10 && !isTouchUsr && !isKbdUsr && b.trajectoryLength < 30) score += 0.15;

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
