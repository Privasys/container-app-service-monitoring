// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// Runs the page's in-browser verifier against a real evidence
// bundle, outside a browser.
//
// The status page claims a reader can check a proof for themselves, in the
// page, without trusting the monitor. That claim is only worth
// anything if the JavaScript agrees with the Go verifier down to the
// byte: the canonical encoding the signature covers has to be the same
// on both sides, and a difference as small as an empty field being
// omitted rather than blanked would make every signature fail. This is
// what keeps the two in step.
//
//   node tools/browser-verify.mjs <bundle.json> <key.json>
//
// Exits 0 when the bundle verifies and a tampered copy of it does not.

import { readFileSync } from 'node:fs';

const [bundlePath, keyPath] = process.argv.slice(2);
if (!bundlePath || !keyPath) {
  console.error('usage: node tools/browser-verify.mjs <bundle.json> <key.json>');
  process.exit(2);
}

// Load the page's verifier as the browser would: as a script that
// publishes itself on `window`.
const source = readFileSync(new URL('../internal/api/web/verify.js', import.meta.url), 'utf8');
globalThis.window = {};
const load = new Function(
  'window',
  'atob',
  `${source}\nreturn window.MonitorVerify;`,
);
const verifier = load(globalThis.window, (b) => Buffer.from(b, 'base64').toString('binary'));

const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
const key = JSON.parse(readFileSync(keyPath, 'utf8'));

const report = (label, checks) => {
  console.log(label);
  for (const c of checks) {
    const mark = c.state === 'pass' ? '✓' : c.state === 'fail' ? '✗' : '?';
    console.log(`  ${mark} ${c.name.padEnd(22)} ${c.why}`);
  }
};

const genuine = await verifier.verifyBundle(bundle, key.public_key);
report('genuine bundle', genuine);

const tampered = JSON.parse(JSON.stringify(bundle));
tampered.statement = 'something else entirely';
const edited = await verifier.verifyBundle(tampered, key.public_key);
report('edited bundle', edited);

const failures = genuine.filter((c) => c.state === 'fail');
if (failures.length) {
  console.error(`the browser verifier rejected a genuine bundle: ${failures.map((c) => c.name).join(', ')}`);
  process.exit(1);
}
if (!edited.some((c) => c.state === 'fail')) {
  console.error('the browser verifier accepted an edited bundle');
  process.exit(1);
}
console.log('\nthe page agrees with the monitor: genuine verifies, edited does not.');
