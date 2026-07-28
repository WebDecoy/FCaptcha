'use strict';

/**
 * Input choreography for the capture recorder.
 *
 * These functions drive a real Chromium through Playwright. Everything they
 * dispatch goes through CDP's Input domain, so the page sees genuine trusted
 * events with real timestamps — which is the entire reason for capturing rather
 * than hand-writing signal vectors. A fixture author guesses what
 * `velocityVariance` looks like for a trackpad; a capture measures it.
 *
 * The movement models are stylised, not claimed to be biometrically accurate.
 * They exist to produce *structurally* correct traces — a tremor persona really
 * does emit high-frequency direction reversals, a keyboard persona really does
 * emit zero pointer events — so the detections under test are exercised the way
 * a real user would exercise them. Where a model is a guess, it says so.
 */

const { makeRng } = require('../lib/rng');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * A curved approach with speed that rises and falls.
 *
 * Straight-line constant-velocity movement is the classic automation signature,
 * so a human panel that moved in straight lines would be measuring the wrong
 * thing. The curve is a quadratic Bézier through a perpendicular offset, and
 * the speed profile is a sine ease — fast in the middle, slow at both ends,
 * which is roughly how a hand behaves.
 */
function bezierPath(from, to, rng, opts = {}) {
  const steps = opts.steps || 40;
  const curvature = opts.curvature ?? 0.2;

  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const dist = Math.hypot(dx, dy) || 1;

  // Control point offset perpendicular to the straight line.
  const side = rng.bool() ? 1 : -1;
  const mag = dist * curvature * rng.range(0.5, 1.5) * side;
  const cx = from.x + dx / 2 + (-dy / dist) * mag;
  const cy = from.y + dy / 2 + (dx / dist) * mag;

  const pts = [];
  for (let i = 1; i <= steps; i++) {
    // Ease so the pointer accelerates away and decelerates onto the target.
    const linear = i / steps;
    const t = linear - Math.sin(2 * Math.PI * linear) / (2 * Math.PI);
    const inv = 1 - t;
    pts.push({
      x: inv * inv * from.x + 2 * inv * t * cx + t * t * to.x,
      y: inv * inv * from.y + 2 * inv * t * cy + t * t * to.y,
    });
  }
  return pts;
}

/** Adds per-sample positional noise — the involuntary jitter of a real hand. */
function withTremor(points, rng, amplitudePx, everyN = 1) {
  return points.map((p, i) =>
    i % everyN === 0
      ? { x: p.x + rng.gaussian(0, amplitudePx), y: p.y + rng.gaussian(0, amplitudePx) }
      : p
  );
}

/**
 * Overshoots the target and corrects back, one or more times.
 *
 * Fitts's-law behaviour: fast movements to small targets routinely overshoot.
 * The server counts corrections as a humanity signal, and an approach that
 * never overshoots is one of the things it treats as suspicious.
 *
 * The geometry here is dictated by how the client counts them. It looks at the
 * last 20 pointer samples only, and an overshoot registers when a point is
 * inside the target rect, then outside, then inside again. A big early
 * overshoot on a long approach is therefore invisible: by the time the final 20
 * samples begin, the pointer has long since left the target and only comes back
 * once. So the corrections are placed at the very end of the path, and sized
 * relative to the target — tens of pixels past a 24px checkbox, not a fraction
 * of a 300px journey.
 */
function withOvershoot(from, to, rng, corrections = 1, targetSize = 24) {
  // Approach the target proper first.
  const path = bezierPath(from, to, rng, { steps: 28, curvature: 0.2 });

  // Direction of travel at arrival, used to overshoot along the same line.
  const prev = path[path.length - 2] || from;
  const dx = to.x - prev.x;
  const dy = to.y - prev.y;
  const norm = Math.hypot(dx, dy) || 1;

  let cursor = to;
  for (let c = 0; c < corrections; c++) {
    // Far enough past to clearly exit the target, close enough that the whole
    // out-and-back fits inside the 20-sample window the client examines.
    const dist = targetSize * rng.range(1.2, 2.2) * (1 / (c + 1));
    const past = {
      x: cursor.x + (dx / norm) * dist + rng.gaussian(0, 2),
      y: cursor.y + (dy / norm) * dist + rng.gaussian(0, 2),
    };
    path.push(...bezierPath(cursor, past, rng, { steps: 4, curvature: 0.05 }));
    path.push(...bezierPath(past, to, rng, { steps: 5, curvature: 0.08 }));
    cursor = to;
  }

  return path;
}

/**
 * Where inside the target the click actually lands.
 *
 * Playwright's `locator.click()` hits the exact geometric centre, which the
 * client measures as sub-pixel precision and the server flags as unnaturally
 * accurate — a real hand does not repeatedly hit dead centre. Offsetting by a
 * few pixels is not making the sample "more human", it is removing an artifact
 * of the driver that a human could not produce.
 */
function clickPointIn(box, rng) {
  const maxOffset = Math.max(2, Math.min(box.width, box.height) / 2 - 3);
  return {
    x: box.x + box.width / 2 + rng.gaussian(0, maxOffset / 2),
    y: box.y + box.height / 2 + rng.gaussian(0, maxOffset / 2),
  };
}

/** Replays a path at a given event rate, so inter-event timing is real. */
async function traverse(page, points, opts = {}) {
  const hz = opts.hz || 60;
  const interval = 1000 / hz;
  const rng = opts.rng;

  for (const p of points) {
    await page.mouse.move(p.x, p.y);
    // Real pointer streams are not perfectly periodic; a perfectly periodic one
    // is itself a tell (the server scores inter-event delta variance).
    const wait = rng ? Math.max(1, rng.gaussian(interval, interval * 0.25)) : interval;
    await sleep(wait);
  }
}

async function centerOf(locator) {
  const box = await locator.boundingBox();
  if (!box) throw new Error('element has no bounding box');
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
}

/**
 * The shared desktop-mouse choreography: idle, approach on a curve with tremor,
 * overshoot and correct, dwell, then click off-centre.
 *
 * Several personas differ from this baseline only in their environment (a
 * throttled link, an attached CDP session, a canvas-blocking extension) rather
 * than in how the pointer moves. They share the movement so that when a
 * detection fires for one and not another, the difference is the environment
 * and nothing else.
 */
async function desktopMouse({ page, target, rng }, tuning = {}) {
  const box = await target.boundingBox();
  const to = { x: box.x + box.width / 2, y: box.y + box.height / 2 };
  const from = { x: rng.range(80, 320), y: rng.range(80, 280) };

  await page.mouse.move(from.x, from.y);
  await sleep(rng.range(tuning.settleMin ?? 200, tuning.settleMax ?? 600));

  const path = withTremor(
    withOvershoot(from, to, rng, tuning.corrections ?? 1, Math.min(box.width, box.height)),
    rng,
    tuning.tremor ?? 0.7
  );

  // End on a point a hand could plausibly have chosen, not the exact centre.
  path[path.length - 1] = clickPointIn(box, rng);

  await traverse(page, path, { hz: tuning.hz ?? 60, rng });
  await sleep(rng.range(tuning.dwellMin ?? 120, tuning.dwellMax ?? 400));
  const last = path[path.length - 1];
  await page.mouse.click(last.x, last.y);
}

/**
 * Each persona receives `{ page, target, rng }` and is responsible for getting
 * the widget activated however that persona would. `target` is the checkbox.
 *
 * `evidence` records what each persona is standing in for and how confident we
 * are in the model — it is copied into the sample's `notes` so nobody reads a
 * number off this harness without seeing what produced it.
 */
const HUMAN_PERSONAS = {
  'mouse-desktop': {
    evidence: 'baseline: curved approach, mild tremor, single overshoot correction',
    run: (ctx) => desktopMouse(ctx),
  },

  trackpad: {
    evidence:
      'trackpad: shorter strokes at a higher sample rate, little overshoot. ' +
      'Model is stylised — no trackpad-vs-mouse dataset was consulted.',
    async run({ page, target, rng }) {
      const to = await centerOf(target);
      let cur = { x: rng.range(150, 400), y: rng.range(150, 350) };
      await page.mouse.move(cur.x, cur.y);
      await sleep(rng.range(150, 400));

      // Several short flicks with a pause between, rather than one long sweep.
      for (let i = 0; i < 3; i++) {
        const next = {
          x: cur.x + (to.x - cur.x) * rng.range(0.4, 0.7),
          y: cur.y + (to.y - cur.y) * rng.range(0.4, 0.7),
        };
        await traverse(page, withTremor(bezierPath(cur, next, rng, { steps: 18, curvature: 0.08 }), rng, 0.4), { hz: 120, rng });
        cur = next;
        await sleep(rng.range(60, 180));
      }
      // Final short hop, ending off-centre and overshooting once as the
      // pointer settles — trackpads overshoot small targets too.
      const box = await target.boundingBox();
      const tail = withOvershoot(cur, to, rng, 1, Math.min(box.width, box.height));
      tail[tail.length - 1] = clickPointIn(box, rng);
      await traverse(page, tail, { hz: 120, rng });
      await sleep(rng.range(100, 300));
      const end = tail[tail.length - 1];
      await page.mouse.click(end.x, end.y);
    },
  },

  'keyboard-only': {
    evidence:
      'keyboard-only: zero pointer events, Tab to focus, Space to activate. ' +
      'Directly exercises the accessibility exemption (keyEvents >= 2 && totalPoints === 0).',
    async run({ page, target, rng }) {
      await page.keyboard.press('Tab');
      await sleep(rng.range(300, 900));
      for (let i = 0; i < 3 && !(await target.evaluate((el) => el === document.activeElement)); i++) {
        await page.keyboard.press('Tab');
        await sleep(rng.range(200, 700));
      }
      await target.focus();
      await sleep(rng.range(400, 1200));
      await page.keyboard.press('Space');
    },
  },

  'screen-reader': {
    evidence:
      'screen-reader traversal: many Tab presses with long dwell times as content ' +
      'is announced, no pointer. Dwell times are a plausible range, not measured ' +
      'against a real AT user.',
    async run({ page, target, rng }) {
      for (let i = 0; i < 6; i++) {
        await page.keyboard.press('Tab');
        await sleep(rng.range(900, 2400)); // announcement time
      }
      await target.focus();
      await sleep(rng.range(1200, 2600));
      await page.keyboard.press('Space');
    },
  },

  touch: {
    evidence: 'touch: tap with no pointer trajectory. Exercises the touch exemption.',
    context: { hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } },
    async run({ page, target, rng }) {
      await sleep(rng.range(400, 1200));
      const to = await centerOf(target);
      // A tap that drifts a little, as a finger does.
      await page.touchscreen.tap(to.x + rng.gaussian(0, 3), to.y + rng.gaussian(0, 3));
    },
  },

  'motor-tremor': {
    evidence:
      'motor impairment (tremor): high-amplitude oscillation superimposed on the ' +
      'approach plus repeated corrections. Amplitude chosen to be clearly outside ' +
      'the normal range; not fitted to clinical data.',
    run: (ctx) =>
      desktopMouse(ctx, {
        corrections: 3,
        tremor: 4.5,
        hz: 45,
        settleMin: 400,
        settleMax: 1000,
        dwellMin: 500,
        dwellMax: 1500,
      }),
  },

  'motor-slow': {
    evidence:
      'motor impairment (slow/corrected): low-speed approach with long pauses ' +
      'mid-path and several corrections.',
    async run({ page, target, rng }) {
      const to = await centerOf(target);
      const from = { x: rng.range(100, 300), y: rng.range(100, 260) };
      await page.mouse.move(from.x, from.y);
      await sleep(rng.range(800, 1600));

      const box = await target.boundingBox();
      const path = withTremor(
        withOvershoot(from, to, rng, 2, Math.min(box.width, box.height)),
        rng,
        1.8
      );
      path[path.length - 1] = clickPointIn(box, rng);

      // Pause partway, the way someone resting a hand mid-movement would.
      const third = Math.floor(path.length / 3);
      await traverse(page, path.slice(0, third), { hz: 22, rng });
      await sleep(rng.range(700, 1800));
      await traverse(page, path.slice(third), { hz: 22, rng });
      await sleep(rng.range(600, 1400));
      const end = path[path.length - 1];
      await page.mouse.click(end.x, end.y);
    },
  },

  elderly: {
    evidence:
      'older user: deliberate pace, one clear overshoot, long dwell before ' +
      'committing to the click. Stylised.',
    run: (ctx) =>
      desktopMouse(ctx, {
        tremor: 1.4,
        hz: 35,
        settleMin: 900,
        settleMax: 2000,
        dwellMin: 900,
        dwellMax: 2200, // reads the label before committing
      }),
  },

  'high-latency': {
    evidence:
      'throttled connection: same input as the desktop baseline, but the page ' +
      'loads and the challenge round-trips over a slow link (CDP emulation). ' +
      'Targets timing-derived signals, not movement ones.',
    network: { downloadThroughput: (400 * 1024) / 8, uploadThroughput: (200 * 1024) / 8, latency: 600 },
    run: (ctx) => desktopMouse(ctx),
  },

  'devtools-open': {
    evidence:
      'developer with DevTools open. Emulated by attaching a CDP session and ' +
      'enabling the Runtime and Console domains — which is literally what ' +
      'DevTools does, so this is a faithful emulation rather than an approximation. ' +
      'Exercises the CDP-adjacent signals that must not fire on a developer.',
    cdp: ['Runtime.enable', 'Console.enable', 'Debugger.enable'],
    // Alone among the human personas, this one keeps `consoleAttached: true`.
    // For everyone else it is an artifact of the recorder being a CDP client;
    // here it is precisely the condition being tested.
    keepConsoleAttached: true,
    run: (ctx) => desktopMouse(ctx),
  },

  typing: {
    evidence:
      'human typing into a textarea: log-normal inter-key intervals with real ' +
      'hold times, produced by actual key events rather than a scripted delay. ' +
      'Exercises the inter-key/hold floors of PRD §7.1.',
    async run(ctx) {
      const { page, rng } = ctx;
      const box = page.locator('#message');
      await box.click();
      await sleep(rng.range(200, 600));

      // Log-normal around ~130ms median, which is where ordinary prose typing
      // sits. The spread matters more than the centre: a human's variance is
      // what separates them, not their speed.
      const text = 'the quick brown fox jumps over the lazy dog';
      for (const ch of text) {
        const interval = Math.min(600, Math.max(45, Math.exp(rng.gaussian(4.8, 0.45))));
        await page.keyboard.press(ch === ' ' ? 'Space' : ch, {
          delay: Math.max(25, rng.gaussian(75, 22)), // hold time
        });
        await sleep(interval);
      }
      await sleep(rng.range(300, 900));
      await desktopMouse(ctx);
    },
  },

  'paste-by-human': {
    evidence:
      'a real person pasting — from a password manager or their own clipboard. ' +
      'Humans paste constantly, so this is the persona the inter-key floors must ' +
      'never fire on. Uses the platform-correct shortcut for the claimed OS.',
    async run(ctx) {
      const { page, rng } = ctx;
      const box = page.locator('#message');
      await box.click();
      await sleep(rng.range(400, 1200));

      // Put something on the clipboard, then paste it the way a Mac user does.
      // normalize.js leaves navigator.platform as this machine reports it, so
      // Meta is the coherent choice here — the incoherence check must NOT fire.
      await page.evaluate(() => navigator.clipboard.writeText('pasted by a person').catch(() => {}));
      await page.keyboard.press('Meta+V');
      await sleep(rng.range(500, 1400));
      await desktopMouse(ctx);
    },
  },

  scrolling: {
    evidence:
      'human scrolling: several wheel gestures with real duration and a tail, ' +
      'landing at unrepeated offsets. Baseline for the scroll morphology of ' +
      'PRD §7.2.',
    async run(ctx) {
      const { page, rng } = ctx;
      await sleep(rng.range(300, 800));

      for (let g = 0; g < 4; g++) {
        // One gesture = a burst of wheel deltas over a few hundred ms, the way
        // a finger on a wheel or trackpad actually delivers them.
        const steps = rng.int(6, 12);
        for (let i = 0; i < steps; i++) {
          await page.mouse.wheel(0, rng.range(40, 110));
          await sleep(rng.range(12, 34));
        }
        await sleep(rng.range(350, 900)); // reading pause between gestures
      }

      // Scroll back up the same way, then click — the widget is above the
      // filler, so a persona that only scrolls down cannot reach it.
      for (let g = 0; g < 5; g++) {
        for (let i = 0; i < rng.int(6, 12); i++) {
          await page.mouse.wheel(0, -rng.range(40, 110));
          await sleep(rng.range(12, 34));
        }
        await sleep(rng.range(200, 500));
      }
      await desktopMouse(ctx);
    },
  },

  'privacy-extension': {
    evidence:
      'privacy extension (Brave / CanvasBlocker style): canvas readback and WebGL ' +
      'parameters are wrapped by non-native functions. The client records these as ' +
      'patched_* artifacts, which FCaptcha deliberately does NOT score — this ' +
      'persona is the regression test for that decision.',
    initScript: () => {
      // Wrap canvas readback the way a fingerprint-blocking extension does:
      // return perturbed data through a non-native function.
      const realToDataURL = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function (...args) {
        return realToDataURL.apply(this, args);
      };
      const realGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      CanvasRenderingContext2D.prototype.getImageData = function (...args) {
        const data = realGetImageData.apply(this, args);
        for (let i = 0; i < data.data.length; i += 997) data.data[i] ^= 1;
        return data;
      };
      const realGetParameter = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function (p) {
        if (p === 37445 || p === 37446) return 'Brave'; // UNMASKED_VENDOR/RENDERER
        return realGetParameter.call(this, p);
      };
    },
    run: (ctx) => desktopMouse(ctx),
  },
};

/**
 * Agent personas a local Chromium can genuinely produce. Classes that need
 * infrastructure we do not have — a hosted VM, a patched Chromium build, an
 * in-browser agent nobody has documented — are handled in personas/agents.js
 * and are labeled synthetic there.
 */
const AGENT_PERSONAS = {
  'scripted-typing': {
    normalize: false,
    class: 'local-cdp-agent',
    evidence:
      'agent typing at a programmed delay: keystrokes are real events but the ' +
      'cadence is a constant, so inter-key variance collapses. The FP-Agent ' +
      'shapes (Manus 1.39ms, Browser Use 5.31ms, Skyvern 9.52ms) are all this ' +
      'pattern at different speeds.',
    async run({ page }) {
      const box = page.locator('#message');
      await box.click();
      await page.keyboard.type('the quick brown fox jumps over the lazy dog', { delay: 6 });
      await page.waitForTimeout(40);
      const target = page.locator('#captcha .fcaptcha-checkbox, #captcha [role=checkbox]').first();
      await target.click();
    },
  },

  'programmatic-fill': {
    normalize: false,
    class: 'dom-a11y-reader',
    evidence:
      'text assigned straight into the DOM with a dispatched input event — the ' +
      'bare-change-event shape the PRD attributes to in-browser agents. No ' +
      'keystrokes at all, and the synthetic event carries no inputType.',
    async run({ page }) {
      await page.evaluate(() => {
        const el = document.querySelector('#message');
        el.value = 'the quick brown fox jumps over the lazy dog';
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      });
      await page.waitForTimeout(60);
      const target = page.locator('#captcha .fcaptcha-checkbox, #captcha [role=checkbox]').first();
      await target.evaluate((el) => el.click());
    },
  },

  'scroll-jump': {
    normalize: false,
    class: 'local-cdp-agent',
    evidence:
      'scrollIntoView navigation: the page jumps to each target in a single ' +
      'frame and lands on the same element offsets every time. Zero-duration ' +
      'gestures at repeated offsets, the DOM-driven architecture tell of §7.2.',
    async run({ page }) {
      await page.evaluate(() => {
        document.querySelector('#filler p').scrollIntoView();
      });
      await page.waitForTimeout(30);
      await page.evaluate(() => {
        document.querySelectorAll('#filler p')[1].scrollIntoView();
      });
      await page.waitForTimeout(30);
      await page.evaluate(() => document.querySelector('#captcha').scrollIntoView());
      await page.waitForTimeout(30);
      const target = page.locator('#captcha .fcaptcha-checkbox, #captcha [role=checkbox]').first();
      await target.click();
    },
  },

  'incoherent-paste': {
    normalize: false,
    class: 'hosted-computer-use',
    evidence:
      'the ChatGPT-Agent contradiction from PRD §7.1: pastes with a keyboard ' +
      'shortcut that does not belong to the platform it claims. The PRD describes ' +
      'Ctrl+V under a MacIntel claim; this persona is the mirror image — Meta+V ' +
      'under a Win32 claim — because the recording host is a Mac, where Ctrl+V ' +
      'genuinely does nothing and so cannot produce the completed paste the ' +
      'detection requires. Same contradiction, testable on this hardware. ' +
      'Needs no threshold and no calibration, which is why it is worth having.',
    initScript: () => {
      // Claim Windows while running on macOS. The contradiction is between the
      // claim and the modifier the "user" reached for.
      Object.defineProperty(navigator, 'platform', { get: () => 'Win32', configurable: true });
    },
    async run({ page }) {
      const box = page.locator('#message');
      await box.click();
      await page.evaluate(() => navigator.clipboard.writeText('filled by an agent').catch(() => {}));
      await page.keyboard.press('Meta+V');
      await page.waitForTimeout(80);
      const target = page.locator('#captcha .fcaptcha-checkbox, #captcha [role=checkbox]').first();
      await target.click();
    },
  },

  'teleport-click': {
    class: 'local-cdp-agent',
    normalize: false,
    evidence:
      'the default Playwright/Puppeteer click: pointer jumps straight to the ' +
      'target with no intervening movement. The canonical automation signature.',
    async run({ page, target, rng }) {
      await sleep(rng.range(50, 200));
      await target.click(); // no prior mouse.move at all
    },
  },

  'linear-approach': {
    normalize: false,
    class: 'local-cdp-agent',
    evidence:
      'automation that moves before clicking but in a straight line at constant ' +
      'speed — the naive attempt to look human.',
    async run({ page, target, rng }) {
      const to = await centerOf(target);
      await page.mouse.move(20, 20);
      await page.mouse.move(to.x, to.y, { steps: 25 }); // Playwright interpolates linearly
      await sleep(20);
      await target.click();
    },
  },

  'dom-a11y-reader': {
    normalize: false,
    class: 'dom-a11y-reader',
    evidence:
      'an LLM read_page tool: never touches the pointer, activates the control ' +
      'through the DOM. Produces an untrusted event with no input history at all.',
    async run({ page, target }) {
      await page.waitForTimeout(80);
      await target.evaluate((el) => el.click());
    },
  },

  'instant-keyboard': {
    normalize: false,
    class: 'local-cdp-agent',
    evidence:
      'keyboard-driven automation: correct modality, inhuman cadence. Separates ' +
      '"used the keyboard" from "is a human using the keyboard", which the ' +
      'accessibility exemption must not conflate.',
    async run({ page, target }) {
      await target.focus();
      await page.keyboard.press('Space', { delay: 0 });
    },
  },
};

module.exports = {
  AGENT_PERSONAS,
  HUMAN_PERSONAS,
  bezierPath,
  centerOf,
  clickPointIn,
  desktopMouse,
  makeRng,
  sleep,
  traverse,
  withOvershoot,
  withTremor,
};
