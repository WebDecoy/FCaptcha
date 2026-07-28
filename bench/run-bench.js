#!/usr/bin/env node
'use strict';

/**
 * Replays the labeled corpus against a running FCaptcha server and reports
 * true-positive, false-positive and per-signal rates.
 *
 * Usage:
 *   node bench/run-bench.js                          # against localhost:3000
 *   node bench/run-bench.js --server http://host:3000
 *   node bench/run-bench.js --derive 20              # 20 jittered variants per capture
 *   node bench/run-bench.js --gate                   # exit non-zero on a budget breach
 *   node bench/run-bench.js --json out.json          # machine-readable output
 *
 * Start a server first — any of the three implementations:
 *   cd server-node && npm start
 *   cd server-go && go run .
 *   cd server-python && python server.py
 */

const fs = require('fs');
const path = require('path');

const { deriveVariant, loadCorpus } = require('./lib/corpus');
const { computeMetrics, evaluateGate } = require('./lib/metrics');
const { renderReport } = require('./lib/report');
const { replayCorpus } = require('./lib/replay');
const { makeRng } = require('./lib/rng');

function parseArgs(argv) {
  const args = {
    server: process.env.FCAPTCHA_BENCH_SERVER || 'http://localhost:3000',
    derive: 8,
    seed: 1,
    concurrency: 6,
    gate: false,
    json: null,
    quiet: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--gate') args.gate = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--server') args.server = argv[++i];
    else if (a === '--derive') args.derive = Number(argv[++i]);
    else if (a === '--seed') args.seed = Number(argv[++i]);
    else if (a === '--concurrency') args.concurrency = Number(argv[++i]);
    else if (a === '--json') args.json = argv[++i];
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return args;
}

/**
 * Expands each capture into jittered variants.
 *
 * One capture per persona can only ever produce a 0% or 100% rate, which is not
 * a measurement. The variants explore the neighbourhood around each real
 * capture, so "keyboard-only never trips anything" becomes a claim about a
 * region of the signal space rather than about one lucky point in it.
 *
 * They are labeled `derived`, never `captured` — see lib/corpus.js.
 */
function expand(corpus, count, seed) {
  if (count <= 0) return corpus;
  const rng = makeRng(seed);
  const out = [...corpus];
  let n = 0;
  for (const sample of corpus) {
    if (sample.provenance !== 'captured' || sample.unmeasured) continue;
    for (let i = 0; i < count; i++) {
      const variant = deriveVariant(sample, rng, n++);
      if (sample.caveats) variant.caveats = [...sample.caveats];
      if (sample.clientIp) variant.clientIp = sample.clientIp;
      out.push(variant);
    }
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    console.log(fs.readFileSync(path.join(__dirname, 'README.md'), 'utf8'));
    return 0;
  }

  const health = await fetch(`${args.server}/health`).catch(() => null);
  if (!health || !health.ok) {
    console.error(`no FCaptcha server at ${args.server} — start one and retry`);
    return 2;
  }

  const base = loadCorpus();
  if (!base.length) {
    console.error('corpus is empty — run `node bench/capture/record.js` first');
    return 2;
  }

  // Declared gaps are documentation, not data; they never reach the server.
  const scoreable = base.filter((s) => !s.unmeasured);
  const corpus = expand(scoreable, args.derive, args.seed);

  if (!args.quiet) {
    console.log(
      `replaying ${corpus.length} samples (${scoreable.length} base + ` +
        `${corpus.length - scoreable.length} derived) against ${args.server}`
    );
  }

  const started = Date.now();
  const results = await replayCorpus(args.server, corpus, {
    concurrency: args.concurrency,
    onProgress: args.quiet
      ? null
      : (done, total) => {
          if (done % 10 === 0 || done === total) {
            process.stdout.write(`\r  ${done}/${total} replayed`);
          }
        },
  });
  if (!args.quiet) console.log(`\r  ${corpus.length}/${corpus.length} replayed in ${((Date.now() - started) / 1000).toFixed(1)}s`);

  const metrics = computeMetrics(results);

  // Signals the recorder itself causes, exempt from failing the build but still
  // measured and printed. See bench/corpus/known-artifacts.json.
  const artifactsPath = path.join(__dirname, 'corpus', 'known-artifacts.json');
  const knownArtifacts = fs.existsSync(artifactsPath)
    ? JSON.parse(fs.readFileSync(artifactsPath, 'utf8')).artifacts || []
    : [];

  const gate = evaluateGate(metrics, knownArtifacts);

  console.log(renderReport(metrics, base, gate));

  if (args.json) {
    fs.writeFileSync(
      args.json,
      `${JSON.stringify(
        {
          server: args.server,
          seed: args.seed,
          derive: args.derive,
          corpusSize: corpus.length,
          metrics,
          gate,
          unmeasured: base.filter((s) => s.unmeasured).map((s) => ({ group: s.group, notes: s.notes })),
        },
        null,
        2
      )}\n`
    );
    if (!args.quiet) console.log(`wrote ${args.json}`);
  }

  return args.gate && !gate.passed ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err.stack || err.message);
    process.exit(2);
  });
