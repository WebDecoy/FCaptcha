'use strict';

// Replay recorded browser signals without the main corpus replayer's device
// normalization. Fresh PoW is necessary; original browser PoW timing is not
// claimed. This measures scorer behavior, not additional live browser visits.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { buildVerifyBody } = require('../lib/pow');

async function main() {
  const [input, output, ...servers] = process.argv.slice(2);
  if (!input || !output || !servers.length) {
    throw new Error('Usage: node replay_browser.js INPUT.json OUTPUT.json NAME=http://127.0.0.1:PORT [...]');
  }
  if (fs.existsSync(output)) throw new Error('Output already exists');
  const secret = process.env.FCAPTCHA_VERIFY_SECRET || process.env.FCAPTCHA_SECRET;
  if (!secret) throw new Error('Set FCAPTCHA_SECRET or FCAPTCHA_VERIFY_SECRET');
  const source = JSON.parse(fs.readFileSync(input, 'utf8'));
  const targets = servers.map((value) => {
    const separator = value.indexOf('=');
    if (separator < 1) throw new Error('Expected NAME=URL');
    const name = value.slice(0, separator);
    const url = new URL(value.slice(separator + 1));
    if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
      throw new Error('Use a loopback HTTP test server');
    }
    return { name, url: url.origin };
  });
  const report = { source: path.resolve(input), startedAt: new Date().toISOString(),
    kind: 'signal-replay', limitations: ['Fresh proof and timing; no new browser sessions.',
      'Per-sample state isolation; no transport or reputation measurement.'], results: [] };
  for (const [index, sample] of source.samples.entries()) {
    if (sample.error || !sample.capture) continue;
    for (const target of targets) {
      const record = { sampleIndex: index, server: target.name, browser: sample.browser,
        mode: sample.mode, headless: sample.headless, humanize: sample.humanize, privacy: sample.privacy };
      try {
        const id = crypto.randomBytes(12).toString('hex');
        const ip = `2001:db8:${id.match(/.{4}/g).join(':')}`;
        const siteKey = `browser-replay-${id}`;
        const headers = Object.fromEntries(Object.entries(sample.capture.headers)
          .filter(([key]) => !['host', 'content-length', 'connection', 'x-forwarded-for'].includes(key.toLowerCase())));
        headers['X-Forwarded-For'] = ip;
        const { body } = await buildVerifyBody(target.url, siteKey, sample.capture.request.signals, headers);
        body.action = sample.capture.request.action || '';
        const res = await fetch(target.url + sample.capture.endpoint, {
          method: 'POST', headers, body: JSON.stringify(body),
          signal: AbortSignal.timeout(90_000),
        });
        if (!res.ok) throw new Error(`Scoring HTTP ${res.status}`);
        const result = await res.json();
        const token = result.token;
        delete result.token;
        record.response = result;
        record.tokenIssued = Boolean(token);
        record.tokenValid = false;
        if (token) {
          const verify = await fetch(target.url + '/api/token/verify', {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ token, secret, remoteip: ip }), signal: AbortSignal.timeout(15_000),
          });
          record.tokenValid = verify.ok && (await verify.json()).valid === true;
        }
        if (result.experimental?.mode !== 'observe') throw new Error('Expected experimental monitoring mode');
        if (result.success && !record.tokenValid) throw new Error('Successful response without a valid token');
        if (!result.success && token) throw new Error('Unsuccessful response issued a token');
        if (['rate_limited', 'pow_not_satisfied', 'hostname_not_allowed'].includes(result.reason)) {
          throw new Error(`Infrastructure/proof failure: ${result.reason}`);
        }
        console.log(`${index} ${target.name} score=${result.score} token=${record.tokenValid}`);
      } catch (error) {
        record.error = error.message;
        console.log(`${index} ${target.name} ERROR ${error.message}`);
      }
      report.results.push(record);
      fs.mkdirSync(path.dirname(output), { recursive: true });
      fs.writeFileSync(output + '.tmp', JSON.stringify(report, null, 2) + '\n');
      fs.renameSync(output + '.tmp', output);
    }
  }
  if (!report.results.length) throw new Error('No completed captures to replay');
  if (report.results.some((record) => record.error)) process.exitCode = 1;
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
