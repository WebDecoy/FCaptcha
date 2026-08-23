'use strict';

// The version string lives in eight places (run: `node version.test.js`).
//
// Nothing checked they agreed, and they did not: the CDN snippet in README.md
// sat at 1.24.0 while the packages were at 1.28.1 — five minor versions of
// integrators copy-pasting an old widget. The "keep in sync when cutting a
// release" comments in client/fcaptcha.js and server-python/server.py listed
// some of the targets but not the docs, and a comment cannot fail a build.
//
// This test is the checklist. Add a location here when one appears rather than
// relying on a release-day grep.

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const repo = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(repo, rel), 'utf8');
const json = (rel) => JSON.parse(read(rel));

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// The release version, defined by the server package.
const VERSION = json('server-node/package.json').version;

// Every other place the same string has to appear. `pattern` must capture the
// version in group 1.
const LOCATIONS = [
  ['server-node/package-lock.json', /"name": "@webdecoy\/fcaptcha",\s*\n\s*"version": "([^"]+)"/],
  ['client/package.json', /"version": "([^"]+)"/],
  ['client/package-lock.json', /"name": "@webdecoy\/fcaptcha-client",\s*\n\s*"version": "([^"]+)"/],
  ['client/fcaptcha.js', /version: '([^']+)'/],
  ['server-python/server.py', /FastAPI\(title="FCaptcha", version="([^"]+)"\)/],
  ['charts/fcaptcha/Chart.yaml', /^appVersion: "([^"]+)"/m],
  // Integrators copy this snippet verbatim, so a stale pin ships a stale widget.
  ['README.md', /@webdecoy\/fcaptcha-client@([0-9]+\.[0-9]+\.[0-9]+)/],
];

test('the version string agrees everywhere it appears', () => {
  assert.match(VERSION, /^\d+\.\d+\.\d+$/, `unexpected version format: ${VERSION}`);
  for (const [file, pattern] of LOCATIONS) {
    const m = read(file).match(pattern);
    assert.ok(m, `no version found in ${file} — did its format change?`);
    assert.strictEqual(m[1], VERSION, `${file} says ${m[1]}, server-node/package.json says ${VERSION}`);
  }
});

test('the supported-versions table in SECURITY.md tracks the current minor', () => {
  // The table promises support for a minor line. Left behind, it advertises a
  // line that no longer gets fixes.
  const [major, minor] = VERSION.split('.');
  const security = read('SECURITY.md');
  assert.ok(
    security.includes(`| ${major}.${minor}.x`),
    `SECURITY.md does not list ${major}.${minor}.x as supported`
  );
  assert.ok(
    security.includes(`| < ${major}.${minor}`),
    `SECURITY.md does not mark < ${major}.${minor} unsupported`
  );
});

test('the CHANGELOG has an entry for this version', () => {
  assert.ok(
    read('CHANGELOG.md').includes(`## [${VERSION}]`),
    `CHANGELOG.md has no "## [${VERSION}]" section`
  );
});

let failed = 0;
for (const { name, fn } of tests) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL ${name}\n       ${err.message}`);
  }
}
console.log(`\n${tests.length - failed}/${tests.length} passed`);
process.exit(failed === 0 ? 0 : 1);
