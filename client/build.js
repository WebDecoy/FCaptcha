#!/usr/bin/env node
'use strict';

/**
 * Builds the distributable widget: a minified bundle plus its Subresource
 * Integrity digests.
 *
 * `client/fcaptcha.js` stays the canonical source and is what the servers serve
 * same-origin. This produces the artifact for the CDN path, where the file is
 * fetched from a host the integrator does not control and therefore wants to
 * pin.
 *
 * dist/ is generated, not committed, and built by `prepublishOnly` — a
 * committed build artifact is a second copy of the source that silently goes
 * stale the first time someone edits the real one.
 *
 * Minification is safe here, but not by luck:
 *
 *   - The proof-of-work workers are built from template-literal strings, and
 *     minifiers do not rewrite string contents, so the worker source survives.
 *   - The canvas fingerprinting strings are string literals for the same reason.
 *     They must survive byte-identical or every fingerprint changes; there is an
 *     assertion for that below rather than a hope.
 *   - The one `.toString()` call inspects a *native* getter, not our own code.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const SOURCE = path.join(ROOT, 'fcaptcha.js');
const DIST = path.join(ROOT, 'dist');
const OUTPUT = path.join(DIST, 'fcaptcha.min.js');

/** Strings whose bytes are load-bearing: they are hashed into fingerprints. */
const FINGERPRINT_LITERALS = ['FCaptcha Test String 123', 'WWWW 0000'];

function sriDigest(buffer) {
  return 'sha384-' + crypto.createHash('sha384').update(buffer).digest('base64');
}

function readVersion(source) {
  const match = source.match(/version:\s*'([^']+)'/);
  return match ? match[1] : null;
}

/**
 * The version string ships to integrators from two places that have no
 * mechanical link — the widget's own `version` field and the package manifest.
 * A release that bumps one and not the other publishes a package that lies
 * about itself, so this refuses to build rather than let them drift.
 */
function assertVersionsAgree(source) {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const widgetVersion = readVersion(source);
  if (widgetVersion !== pkg.version) {
    throw new Error(
      `version mismatch: client/fcaptcha.js says ${widgetVersion}, ` +
        `client/package.json says ${pkg.version}. Bump both.`
    );
  }
  return pkg.version;
}

/** Refuses to ship a bundle whose fingerprint inputs changed under the minifier. */
function assertFingerprintLiteralsSurvived(minified) {
  const lost = FINGERPRINT_LITERALS.filter((literal) => !minified.includes(literal));
  if (lost.length) {
    throw new Error(
      'minification altered fingerprint literals, which would change every ' +
        'fingerprint this widget produces: ' + lost.join(', ')
    );
  }
}

async function build({ integrityOnly = false } = {}) {
  const source = fs.readFileSync(SOURCE, 'utf8');
  const version = assertVersionsAgree(source);

  if (integrityOnly && fs.existsSync(OUTPUT)) {
    report(version, fs.readFileSync(SOURCE), fs.readFileSync(OUTPUT));
    return;
  }

  const esbuild = require('esbuild');
  const result = await esbuild.transform(source, {
    minify: true,
    // The widget is a classic script assigning to window; it is not a module and
    // must not be treated as one.
    format: 'iife',
    target: ['es2020'],
    legalComments: 'none',
  });

  assertFingerprintLiteralsSurvived(result.code);

  fs.mkdirSync(DIST, { recursive: true });
  fs.writeFileSync(OUTPUT, result.code);

  const sourceBuf = fs.readFileSync(SOURCE);
  const minBuf = fs.readFileSync(OUTPUT);

  // A machine-readable copy next to the artifact, so a release job can quote the
  // digest without re-deriving it.
  fs.writeFileSync(
    path.join(DIST, 'integrity.json'),
    JSON.stringify(
      {
        version,
        'fcaptcha.js': sriDigest(sourceBuf),
        'dist/fcaptcha.min.js': sriDigest(minBuf),
      },
      null,
      2
    ) + '\n'
  );

  report(version, sourceBuf, minBuf);
}

function report(version, sourceBuf, minBuf) {
  const zlib = require('zlib');
  const kb = (n) => (n / 1024).toFixed(1) + ' KB';

  console.log(`fcaptcha-client ${version}`);
  console.log(`  source     ${kb(sourceBuf.length)}`);
  console.log(
    `  minified   ${kb(minBuf.length)}  (gzip ${kb(zlib.gzipSync(minBuf).length)}` +
      `, brotli ${kb(zlib.brotliCompressSync(minBuf).length)})`
  );
  console.log('');
  console.log('  Subresource Integrity');
  console.log(`    fcaptcha.js           ${sriDigest(sourceBuf)}`);
  console.log(`    dist/fcaptcha.min.js  ${sriDigest(minBuf)}`);
}

build({ integrityOnly: process.argv.includes('--integrity') }).catch((err) => {
  console.error('build failed:', err.message);
  process.exit(1);
});
