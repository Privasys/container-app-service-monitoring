// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// Verifies a delivered alert the way a receiver would.
//
// The monitor signs the exact bytes it sends, so this checks the exact
// bytes that arrived: no re-serialisation, no re-ordering of keys, no
// "close enough". It is also the worked example a customer copies into
// their own receiver.
//
//   node tools/verify-webhook.mjs <deliveries.json> <key.json>
//
// deliveries.json is what GET /hooks/received returns from the
// stand-in service; key.json is GET /api/v1/checkpoints/key or the
// signing_key object from /.well-known/privasys-monitor.json.
//
// Exits 0 when a delivery verifies and a tampered copy of it does not.

import { readFileSync } from 'node:fs';
import { createPublicKey, verify } from 'node:crypto';

const [deliveriesPath, keyPath] = process.argv.slice(2);
if (!deliveriesPath || !keyPath) {
  console.error('usage: node tools/verify-webhook.mjs <deliveries.json> <key.json>');
  process.exit(2);
}

const { deliveries } = JSON.parse(readFileSync(deliveriesPath, 'utf8'));
const key = JSON.parse(readFileSync(keyPath, 'utf8'));
const publicKey = key.public_key || key.signing_key?.public_key;

if (!deliveries || deliveries.length === 0) {
  console.error('no alert was delivered');
  process.exit(1);
}

// An Ed25519 public key is 32 raw bytes; Node wants SPKI, whose prefix
// for Ed25519 is fixed.
const spki = Buffer.concat([
  Buffer.from('302a300506032b6570032100', 'hex'),
  Buffer.from(publicKey, 'base64'),
]);
const verifier = createPublicKey({ key: spki, format: 'der', type: 'spki' });

const check = (body, signatureHeader) => {
  const prefix = 'ed25519=';
  if (!signatureHeader?.startsWith(prefix)) throw new Error('not an ed25519 signature');
  const signature = Buffer.from(signatureHeader.slice(prefix.length), 'base64');
  return verify(null, Buffer.from(body, 'utf8'), verifier, signature);
};

let checked = 0;
for (const delivery of deliveries) {
  const signature = delivery.headers['x-privasys-signature'];
  const keyId = delivery.headers['x-privasys-key-id'];
  const event = delivery.headers['x-privasys-event'];
  const body = JSON.parse(delivery.body);

  if (!check(delivery.body, signature)) {
    console.error(`the signature on ${event} does not verify`);
    process.exit(1);
  }
  if (keyId !== (key.key_id || key.signing_key?.key_id)) {
    console.error(`the delivery names key ${keyId}, which is not the published one`);
    process.exit(1);
  }
  // An alert is a pointer to evidence, not a claim: it names the state
  // the change it reports was recorded at.
  if (!body.ledger_root || !body.ledger_version) {
    console.error(`the ${event} alert carries no ledger coordinates`);
    process.exit(1);
  }
  console.log(`ok    ${event}: signed by ${keyId.slice(0, 16)}…, ` +
    `recorded at version ${body.ledger_version}`);
  checked++;
}

// And a body that was altered in transit must not verify.
const tampered = JSON.parse(deliveries[0].body);
tampered.payload = { component: 'something else entirely' };
if (check(JSON.stringify(tampered), deliveries[0].headers['x-privasys-signature'])) {
  console.error('an altered alert body verified');
  process.exit(1);
}

console.log(`\n${checked} delivered alert(s) verify, and an altered one does not.`);
