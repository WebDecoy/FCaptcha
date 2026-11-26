#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { TextDecoder } = require('util');

const { loadCorpus, validate } = require('../lib/corpus');
const { prepareContribution } = require('../lib/community-contribution');

const MAX_INPUT_BYTES = 2 * 1024 * 1024;

function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--input') args.input = argv[++index];
    else if (arg === '--sample-out') args.sampleOut = argv[++index];
    else if (arg === '--manifest-out') args.manifestOut = argv[++index];
    else if (arg === '--help' || arg === '-h') args.help = true;
    else throw new Error(`unknown argument: ${arg}`);
  }
  return args;
}

function usage() {
  return `Usage:
  node bench/tools/prepare-community-contribution.js \\
    --input /path/to/community-capture.json \\
    --sample-out /path/to/review/sample.json \\
    --manifest-out /path/to/review/redaction-manifest.json

The source must use the permanent-publication schema documented in
bench/COMMUNITY-CONTRIBUTIONS.md. Both output paths must not exist. The command
sanitizes locally and writes a reviewable corpus sample plus an audit manifest;
it never uploads anything.
`;
}

function readBoundedJson(file) {
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new Error('input must be a regular file, not a symlink');
    if (stat.size > MAX_INPUT_BYTES) throw new Error(`input exceeds ${MAX_INPUT_BYTES} bytes`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size) {
      throw new Error('input changed while it was being read');
    }
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      throw new Error('input is not valid UTF-8');
    }
    return { bytes, value: JSON.parse(text) };
  } catch (error) {
    if (error?.code === 'ELOOP') throw new Error('input must be a regular file, not a symlink');
    throw error;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function writeExclusive(file, bytes) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const descriptor = fs.openSync(file, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
  } finally {
    fs.closeSync(descriptor);
  }
}

function run(args) {
  if (!args.input || !args.sampleOut || !args.manifestOut) {
    throw new Error(`--input, --sample-out and --manifest-out are required\n\n${usage()}`);
  }
  const input = path.resolve(args.input);
  const sampleOut = path.resolve(args.sampleOut);
  const manifestOut = path.resolve(args.manifestOut);
  if (sampleOut === manifestOut) throw new Error('sample and manifest output paths must differ');
  for (const output of [sampleOut, manifestOut]) {
    if (fs.existsSync(output)) throw new Error(`refusing to overwrite ${output}`);
  }

  const source = readBoundedJson(input);
  const prepared = prepareContribution(source.value, loadCorpus());
  validate(prepared.sample, input);

  const sampleBytes = Buffer.from(`${JSON.stringify([prepared.sample], null, 2)}\n`);
  const manifest = {
    ...prepared.manifest,
    inputSha256: crypto.createHash('sha256').update(source.bytes).digest('hex'),
    sampleSha256: crypto.createHash('sha256').update(sampleBytes).digest('hex'),
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);

  writeExclusive(sampleOut, sampleBytes);
  try {
    writeExclusive(manifestOut, manifestBytes);
  } catch (error) {
    fs.unlinkSync(sampleOut);
    throw error;
  }
  return { sample: prepared.sample, manifest, sampleOut, manifestOut };
}

function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    process.stdout.write(usage());
    return;
  }
  const result = run(args);
  process.stdout.write(
    `prepared ${result.sample.id}\n` +
    `sample: ${result.sampleOut}\n` +
    `manifest: ${result.manifestOut}\n` +
    `existing samples in this capture family: ${result.manifest.checks.existingCaptureFamilySamples}\n`
  );
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

module.exports = { MAX_INPUT_BYTES, parseArgs, readBoundedJson, run };
