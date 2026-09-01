// Copyright (c) Privasys. Licensed under the AGPL-3.0.
//
// Client-side verification of an evidence bundle.
//
// This file exists so that "verified" means something the reader's own
// browser worked out. It recomputes the ledger root from the proof and
// checks the monitor's signature; neither step asks the monitor to be
// believed. The one thing it cannot do offline is bind a ledger key to
// its leaf position, because that mapping is under the commitment key,
// which stays inside the enclave; the monitor's signature over the
// bundle is what asserts it, and the assertion is attributable.

const LEAF_TAG = 'enclave-os-merkle:leaf:v1';
const NODE_TAG = 'enclave-os-merkle:node:v1';
const PLACEHOLDER_TAG = 'ENCLAVE_OS_MERKLE_PLACEHOLDER';

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) throw new Error('not hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

const encoder = new TextEncoder();

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

const leafHash = (path, vh) => sha256(concat(encoder.encode(LEAF_TAG), path, vh));
const nodeHash = (left, right) => sha256(concat(encoder.encode(NODE_TAG), left, right));
const placeholder = () => sha256(encoder.encode(PLACEHOLDER_TAG));

// decodeProof reads the wire format:
//   flags(1) [path(32) vh(32)] count(2, little endian) siblings(count * 32)
function decodeProof(hex) {
  const data = hexToBytes(hex);
  if (data.length === 0) throw new Error('empty proof');
  let off = 1;
  let leaf = null;
  if (data[0] === 1) {
    if (data.length < 65) throw new Error('truncated proof leaf');
    leaf = { path: data.slice(1, 33), vh: data.slice(33, 65) };
    off = 65;
  } else if (data[0] !== 0) {
    throw new Error('unknown proof flags');
  }
  if (data.length < off + 2) throw new Error('truncated proof');
  const count = data[off] | (data[off + 1] << 8);
  off += 2;
  if (data.length !== off + count * 32) throw new Error('proof length mismatch');
  const siblings = [];
  for (let i = 0; i < count; i++) siblings.push(data.slice(off + i * 32, off + (i + 1) * 32));
  return { leaf, siblings };
}

const bitAt = (path, i) => (path[Math.floor(i / 8)] & (0x80 >> (i % 8))) !== 0;

function commonPrefixBits(a, b) {
  for (let i = 0; i < 32; i++) {
    let x = a[i] ^ b[i];
    if (x !== 0) {
      let n = 0;
      while ((x & 0x80) === 0) { x = (x << 1) & 0xff; n++; }
      return i * 8 + n;
    }
  }
  return 256;
}

const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

// verifyProof recomputes the root and reports what the proof
// establishes about the position: present (with its value commitment)
// or absent.
async function verifyProof(rootHex, pathHex, proofHex) {
  const root = hexToBytes(rootHex);
  const path = hexToBytes(pathHex);
  const proof = decodeProof(proofHex);
  const n = proof.siblings.length;

  let acc;
  let present = false;
  if (proof.leaf) {
    if (equal(proof.leaf.path, path)) {
      present = true;
    } else if (commonPrefixBits(proof.leaf.path, path) < n) {
      throw new Error('the divergent leaf does not cover the proven position');
    }
    acc = await leafHash(proof.leaf.path, proof.leaf.vh);
  } else {
    acc = await placeholder();
  }

  for (let i = 0; i < n; i++) {
    const depth = n - 1 - i;
    const sib = proof.siblings[i];
    acc = bitAt(path, depth) ? await nodeHash(sib, acc) : await nodeHash(acc, sib);
  }

  if (!equal(acc, root)) {
    throw new Error(`the proof folds to ${bytesToHex(acc)}, not to the claimed root`);
  }
  return { present, vh: proof.leaf ? bytesToHex(proof.leaf.vh) : null };
}

// canonical renders a value the way the monitor hashes it: object
// members sorted by key, no insignificant whitespace, minimal escaping.
function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  throw new Error('cannot canonicalise ' + typeof value);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// verifySignature checks an Ed25519 signature over the canonical form
// of a document. Browsers without Ed25519 in WebCrypto report the check
// as unavailable rather than as passing.
async function verifySignature(publicKeyB64, signatureB64, document) {
  if (!publicKeyB64) return { ok: false, unavailable: true, why: 'no verification key fetched' };
  let key;
  try {
    key = await crypto.subtle.importKey('raw', base64ToBytes(publicKeyB64), { name: 'Ed25519' }, false, ['verify']);
  } catch (err) {
    return { ok: false, unavailable: true, why: 'this browser cannot verify Ed25519 signatures' };
  }
  const ok = await crypto.subtle.verify(
    { name: 'Ed25519' }, key,
    base64ToBytes(signatureB64),
    encoder.encode(canonical(document)),
  );
  return { ok, unavailable: false, why: ok ? '' : 'the signature does not match the bundle' };
}

// verifyBundle runs the whole chain and returns one result per check,
// so a partial failure says which part failed.
async function verifyBundle(bundle, publicKeyB64) {
  const checks = [];

  try {
    const result = await verifyProof(bundle.root, bundle.path, bundle.proof);
    if (result.present !== bundle.present) {
      checks.push({ name: 'Merkle proof', state: 'fail',
        why: `the bundle says the entry is ${bundle.present ? 'present' : 'absent'}, the proof says otherwise` });
    } else {
      checks.push({ name: 'Merkle proof', state: 'pass',
        why: `folds to the claimed root and shows the entry ${result.present ? 'present' : 'absent'}` });
    }
  } catch (err) {
    checks.push({ name: 'Merkle proof', state: 'fail', why: err.message });
  }

  // The monitor signs the bundle with its signature field emptied, not
  // removed: the field is always present in the encoding, so blanking it
  // is what reproduces the bytes that were signed.
  const unsigned = Object.assign({}, bundle, { signature: '' });
  const sig = await verifySignature(publicKeyB64, bundle.signature, unsigned);
  checks.push({
    name: 'Monitor signature',
    state: sig.unavailable ? 'unknown' : (sig.ok ? 'pass' : 'fail'),
    why: sig.ok ? `signed by key ${bundle.key_id.slice(0, 16)}…` : sig.why,
  });

  const anchor = bundle.checkpoint;
  if (!anchor) {
    checks.push({ name: 'Checkpoint anchor', state: 'unknown',
      why: 'the bundle carries no checkpoint; ask the monitor to issue one' });
  } else if (anchor.checkpoint.root === bundle.root && anchor.checkpoint.version === bundle.version) {
    const cpSig = await verifySignature(publicKeyB64, anchor.signature, anchor.checkpoint);
    checks.push({
      name: 'Checkpoint anchor',
      state: cpSig.unavailable ? 'unknown' : (cpSig.ok ? 'pass' : 'fail'),
      why: cpSig.ok
        ? `state ${bundle.version} is the state checkpoint ${anchor.checkpoint.version} attests`
        : cpSig.why,
    });
  } else {
    checks.push({ name: 'Checkpoint anchor', state: 'unknown',
      why: `read at version ${bundle.version}, latest checkpoint covers ${anchor.checkpoint.version}; ` +
           'compare against a checkpoint you hold for this version' });
  }

  return checks;
}

window.MonitorVerify = { verifyBundle, verifyProof, canonical, bytesToHex };
