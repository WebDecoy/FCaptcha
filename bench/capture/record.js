'use strict';

/**
 * Records real signal payloads from a real browser.
 *
 * This is the part of the measurement harness that makes the rest of it worth
 * anything. Everything downstream — false-positive rates, per-signal budgets,
 * regression gates — is only as meaningful as the traces it runs on, and a
 * trace an engineer typed out by hand mostly encodes what that engineer already
 * believed the client collects.
 *
 * So: drive an actual Chromium through an actual interaction, intercept the
 * `/api/verify` body the widget produces, and store that. Whatever the client
 * really collects, in whatever shape it really collects it, is what lands in the
 * corpus — including fields nobody remembered were there.
 *
 * Usage:
 *   node bench/capture/record.js                       # all personas
 *   node bench/capture/record.js --personas touch,elderly
 *   node bench/capture/record.js --repeats 3 --headed
 *
 * Requires a server on --server (default http://localhost:3000).
 */

const path = require('path');
const { chromium, devices } = require('playwright');

const { saveSamples } = require('../lib/corpus');
const { makeRng } = require('../lib/rng');
const { AGENT_PERSONAS, HUMAN_PERSONAS, sleep } = require('./input');
const { normalizeEnvironment, repairCapturedPayload } = require('./normalize');

const OUT_DIR = path.join(__dirname, '..', 'corpus', 'captured');
const TEST_PATH = '/__fcaptcha_capture__';

function parseArgs(argv) {
  const args = {
    server: 'http://localhost:3000',
    out: OUT_DIR,
    repeats: 1,
    seed: 1,
    headed: false,
    personas: null,
    timeout: 45000,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--headed') args.headed = true;
    else if (a === '--server') args.server = argv[++i];
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--repeats') args.repeats = Number(argv[++i]);
    else if (a === '--seed') args.seed = Number(argv[++i]);
    else if (a === '--timeout') args.timeout = Number(argv[++i]);
    else if (a === '--personas') args.personas = argv[++i].split(',').map((s) => s.trim());
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

const PAGE_HTML = (server) => `<!doctype html>
<html><head><meta charset="utf-8"><title>fcaptcha capture</title>
<style>body{font-family:system-ui;margin:40px;max-width:640px}#captcha{margin-top:32px}</style>
</head><body>
  <h1>Capture harness</h1>
  <p>Some text above the widget so tab traversal and scrolling have somewhere to go.</p>
  <p><a href="#one">first link</a> &middot; <a href="#two">second link</a></p>
  <label>Name <input id="name" type="text" autocomplete="off"></label>
  <div id="captcha"></div>
  <script src="${server}/fcaptcha.js"></script>
  <script>
    window.__captured = null;
    FCaptcha.configure({ serverUrl: '${server}' });
    FCaptcha.render('captcha', { siteKey: 'bench-capture' });
  </script>
</body></html>`;

/**
 * Runs one persona once and returns the intercepted payload.
 *
 * The page is served through a route interception at a real localhost URL
 * rather than via setContent: on about:blank Chromium withholds crypto.subtle,
 * which the widget's SHA-256 helper needs. (Same reason as test/browser.)
 */
async function capture(browser, name, persona, opts) {
  const contextOpts = { ...(persona.context || {}) };
  if (persona.network || persona.throttle) contextOpts.offline = false;

  const context = await browser.newContext(contextOpts);
  const page = await context.newPage();

  // Human personas run with the automation artifacts repaired, so the client
  // measures a normal browser instead of measuring Playwright. Agent personas
  // do not: for them `webdriver: true` and an empty plugin array are the
  // signal, not noise. See normalize.js for what this does and does not touch.
  if (persona.normalize !== false) await page.addInitScript(normalizeEnvironment);
  if (persona.initScript) await page.addInitScript(persona.initScript);

  let payload = null;
  page.on('request', (req) => {
    if (req.method() === 'POST' && req.url().endsWith('/api/verify')) {
      const data = req.postData();
      if (data) payload = JSON.parse(data);
    }
  });

  await page.route(`${opts.server}${TEST_PATH}`, (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: PAGE_HTML(opts.server) })
  );

  // A CDP client attached to the page is what DevTools actually is, so the
  // devtools-open persona emulates it by being one.
  let cdp = null;
  if (persona.cdp || persona.network) {
    cdp = await context.newCDPSession(page);
    for (const method of persona.cdp || []) await cdp.send(method).catch(() => {});
    if (persona.network) {
      await cdp.send('Network.enable');
      await cdp.send('Network.emulateNetworkConditions', { offline: false, ...persona.network });
    }
  }

  await page.goto(`${opts.server}${TEST_PATH}`);
  await page.waitForFunction(() => !!window.FCaptcha, null, { timeout: opts.timeout });

  const target = page.locator('#captcha .fcaptcha-checkbox, #captcha input[type=checkbox], #captcha [role=checkbox]').first();
  await target.waitFor({ state: 'visible', timeout: opts.timeout });

  const rng = makeRng(opts.seed);

  // Nobody interacts with a page the instant it finishes loading — they read
  // it first. The client measures page-load-to-first-interaction and the server
  // flags anything under 100ms, so a recorder that starts moving immediately
  // manufactures that detection on every human persona. Agents get no such
  // pause: arriving and acting at once is what they actually do.
  if (persona.normalize !== false) await sleep(rng.range(600, 2200));

  await persona.run({ page, target, rng });

  // Wait for the widget to finish collecting, solving and posting.
  const deadline = Date.now() + opts.timeout;
  while (!payload && Date.now() < deadline) await sleep(100);

  await context.close();
  if (!payload) throw new Error(`${name}: no /api/verify request was made within ${opts.timeout}ms`);
  return payload;
}

/**
 * The captured challenge nonce is stripped: it is bound to a challenge that has
 * already been consumed, and the replayer stamps in a fresh one. Leaving a dead
 * nonce in the corpus would look like a signal and behave like litter.
 */
function toSample({ id, label, group, payload, notes, headers, clientIp, persona = {} }) {
  let signals = { ...payload.signals };
  if (signals.meta) {
    signals.meta = { ...signals.meta };
    delete signals.meta.challengeNonce;
  }

  const caveats = [];
  if (persona.normalize !== false) {
    caveats.push('environment-normalized');
    const repaired = repairCapturedPayload(signals, {
      keepConsoleAttached: persona.keepConsoleAttached === true,
    });
    signals = repaired.signals;
    caveats.push(...repaired.caveats);
  }

  const sample = { id, label, group, provenance: 'captured', notes, signals };
  if (caveats.length) sample.caveats = caveats;
  if (headers) sample.headers = headers;
  if (clientIp) sample.clientIp = clientIp;
  return sample;
}

async function main() {
  const opts = parseArgs(process.argv);

  const wanted = (names, table) =>
    Object.entries(table).filter(([n]) => !names || names.includes(n));

  const humans = wanted(opts.personas, HUMAN_PERSONAS);
  const agents = wanted(opts.personas, AGENT_PERSONAS);
  if (!humans.length && !agents.length) {
    throw new Error(`no personas matched ${opts.personas?.join(',')}`);
  }

  const res = await fetch(`${opts.server}/health`).catch(() => null);
  if (!res || !res.ok) throw new Error(`no server at ${opts.server} — start one first`);

  const browser = await chromium.launch({ headless: !opts.headed });
  const written = [];

  try {
    for (const [label, table] of [['human', humans], ['agent', agents]]) {
      for (const [name, persona] of table) {
        const samples = [];
        for (let r = 0; r < opts.repeats; r++) {
          const group = persona.class || name;
          const id = `${label}/${name}/${String(r).padStart(4, '0')}`;
          process.stdout.write(`  capturing ${id} ... `);
          try {
            const payload = await capture(browser, name, persona, { ...opts, seed: opts.seed + r });
            samples.push(
              toSample({
                id,
                label,
                group,
                payload,
                persona,
                notes: persona.evidence,
                clientIp: persona.clientIp,
              })
            );
            console.log('ok');
          } catch (err) {
            console.log(`FAILED: ${err.message}`);
          }
        }
        if (samples.length) {
          written.push(saveSamples(path.join(opts.out, `${label}-${name}.json`), samples));
        }
      }
    }
  } finally {
    await browser.close();
  }

  console.log(`\nwrote ${written.length} file(s) to ${opts.out}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}

module.exports = { capture, toSample };
