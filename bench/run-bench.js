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
 *   node bench/run-bench.js --research-export        # ephemeral hosted-demo export
 *   node bench/run-bench.js --research-input file    # ephemeral local NDJSON export
 *   command-producing-ndjson | node bench/run-bench.js --research-stdin
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
const crypto = require('crypto');
const { replayCorpus } = require('./lib/replay');
const { makeRng } = require('./lib/rng');
const {
  DEFAULT_EXPORT_URL,
  fetchExport,
  parseExport,
  readExportFile,
  readExportStream,
} = require('./lib/research-import');

function parseArgs(argv) {
  const args = {
    server: process.env.FCAPTCHA_BENCH_SERVER || 'http://localhost:3000',
    derive: 8,
    seed: 1,
    concurrency: 6,
    gate: false,
    json: null,
    quiet: false,
    researchInput: null,
    researchStdin: false,
    researchUrl: null,
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
    else if (a === '--research-export') args.researchUrl = DEFAULT_EXPORT_URL;
    else if (a === '--research-url') {
      args.researchUrl = argv[++i];
      if (!args.researchUrl) throw new Error('--research-url requires a value');
    }
    else if (a === '--research-input') {
      args.researchInput = argv[++i];
      if (!args.researchInput) throw new Error('--research-input requires a value');
    }
    else if (a === '--research-stdin') args.researchStdin = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  const researchSources = [args.researchInput, args.researchStdin, args.researchUrl].filter(Boolean);
  if (researchSources.length > 1) {
    throw new Error('--research-input, --research-stdin, and --research-export/--research-url are mutually exclusive');
  }
  return args;
}

async function loadResearchSamples(args) {
  if (!args.researchInput && !args.researchStdin && !args.researchUrl) return [];
  const bytes = args.researchInput
    ? readExportFile(path.resolve(args.researchInput))
    : args.researchStdin
      ? await readExportStream(process.stdin)
      : await fetchExport(args.researchUrl, process.env.FCAPTCHA_CAPTURE_EXPORT_TOKEN);
  return parseExport(bytes);
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

  const research = await loadResearchSamples(args);
  const committed = loadCorpus();
  const committedIds = new Set(committed.map((sample) => sample.id));
  const collision = research.find((sample) => committedIds.has(sample.id));
  if (collision) throw new Error(`research sample id collides with committed corpus: ${collision.id}`);
  const base = [...committed, ...research];
  if (!base.length) {
    console.error('corpus is empty — run `node bench/capture/record.js` first');
    return 2;
  }

  // Declared gaps are documentation, not data; they never reach the server.
  const scoreable = base.filter((s) => !s.unmeasured);
  const corpus = expand(scoreable, args.derive, args.seed);

  if (!args.quiet) {
    if (research.length) {
      console.log(
        `loaded ${research.length} ephemeral self-reported research sample(s); ` +
          'they will not be written to the corpus or JSON report'
      );
    }
    console.log(
      `replaying ${corpus.length} samples (${scoreable.length} base + ` +
        `${corpus.length - scoreable.length} derived) against ${args.server}`
    );
  }

  // Namespace this run's server-side per-source state.
  //
  // The server keys rate limits and accumulated suspicion by (siteKey, address).
  // Sample addresses are assigned by position, so two runs against the same
  // long-lived server reuse the same addresses and the second run measures the
  // residue of the first. Measured: one signal fired on 2/75 agents against a
  // fresh server and 74/75 against one that had already been benchmarked.
  //
  // A per-run site key makes runs independent without the harness having to own
  // the server's lifecycle.
  const siteKey = `bench-${crypto.randomBytes(6).toString('hex')}`;

  const started = Date.now();
  const results = await replayCorpus(args.server, corpus, {
    siteKey,
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

  // Absolute TPR targets remain advisory because this is not a population
  // sample. Floors for classes this fixed corpus already catches are regression
  // assertions, however, and are safe to gate on.
  const floorsPath = path.join(__dirname, 'agent-regression-floors.json');
  const agentRegressionFloors = fs.existsSync(floorsPath)
    ? JSON.parse(fs.readFileSync(floorsPath, 'utf8')).classes || {}
    : {};

  const gate = evaluateGate(metrics, knownArtifacts, agentRegressionFloors);

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

if (require.main === module) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(err.stack || err.message);
      process.exit(2);
    });
}

module.exports = { expand, loadResearchSamples, main, parseArgs };
