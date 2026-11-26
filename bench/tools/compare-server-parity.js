#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const { loadCorpus } = require('../lib/corpus');
const { replayCorpus } = require('../lib/replay');
const { compareServerResults } = require('../lib/server-parity');

function parseArgs(argv) {
  const servers = [];
  let concurrency = 6;
  let json = false;
  let strict = false;
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--server') {
      const value = argv[++i] || '';
      const split = value.indexOf('=');
      if (split < 1) throw new Error('--server requires name=https://host');
      const name = value.slice(0, split);
      const url = value.slice(split + 1).replace(/\/$/, '');
      if (!/^[a-z0-9-]+$/.test(name) || !/^https?:\/\//.test(url)) {
        throw new Error('--server requires a lowercase name and HTTP(S) URL');
      }
      servers.push({ name, url });
    } else if (argv[i] === '--concurrency') {
      concurrency = Number(argv[++i]);
    } else if (argv[i] === '--json') {
      json = true;
    } else if (argv[i] === '--strict') {
      strict = true;
    } else {
      throw new Error(`unknown argument: ${argv[i]}`);
    }
  }
  if (servers.length < 2) throw new Error('provide at least two --server name=url arguments');
  if (new Set(servers.map((server) => server.name)).size !== servers.length) {
    throw new Error('server names must be unique');
  }
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 32) {
    throw new Error('--concurrency must be an integer from 1 to 32');
  }
  return { servers, concurrency, json, strict };
}

async function main() {
  const args = parseArgs(process.argv);
  const corpus = loadCorpus().filter((sample) => sample.provenance !== 'derived' && !sample.unmeasured);
  const siteKey = `parity-${crypto.randomBytes(6).toString('hex')}`;
  const namedResults = [];

  for (const server of args.servers) {
    const health = await fetch(`${server.url}/health`).catch(() => null);
    if (!health?.ok) throw new Error(`${server.name} is not healthy at ${server.url}`);
    process.stderr.write(`replaying ${corpus.length} base samples against ${server.name}\n`);
    const results = await replayCorpus(server.url, corpus, {
      siteKey,
      isolateSiteKeys: true,
      concurrency: args.concurrency,
    });
    namedResults.push({ name: server.name, results });
  }

  const comparison = compareServerResults(namedResults);
  if (args.json) console.log(JSON.stringify(comparison, null, 2));
  if (comparison.detailMismatches.length) {
    if (!args.json) {
      for (const mismatch of comparison.detailMismatches.slice(0, 20)) {
        console.error(`${mismatch.sample}: ${mismatch.peer} differs from ${mismatch.reference}`);
        console.error(`  expected ${JSON.stringify(mismatch.expected)}`);
        console.error(`  actual   ${JSON.stringify(mismatch.actual)}`);
      }
    }
    console.error(
      `${comparison.decisionMismatches.length} decision mismatch(es); ` +
      `${comparison.detailMismatches.length} normalized detector-detail mismatch(es)`
    );
    if (comparison.decisionMismatches.length || args.strict) return 1;
  }
  console.error(`cross-server decision parity passed for ${corpus.length} base samples across ${comparison.servers.join(', ')}`);
  return 0;
}

if (require.main === module) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    console.error(error.message);
    process.exitCode = 2;
  });
}

module.exports = { parseArgs };
