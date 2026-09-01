// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package checkpoint signs and verifies the register's external
// anchors.
//
// The ledger's freshness model is strong while the process runs: live
// reads are bound to the in-memory root, so storage cannot roll state
// back or forge it. It has one residual, which no engine can close from
// the inside: a backend that replays an old checkpoint together with a
// matching old store is a consistent history, just not the current one.
// Signed root checkpoints, held by the customer rather than by the
// register, are what closes it. A rolled-back register cannot produce a
// checkpoint chain that reaches the version the customer already holds.
//
// Verification here is deliberately free of the store: the same
// functions run in the register and in the customer's verifier, over
// nothing but the bundle bytes and a public key.
package checkpoint

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-service-monitoring/internal/canon"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// Algorithm is the only signature algorithm the register issues.
const Algorithm = "ed25519"

// Sign produces a signed checkpoint.
func Sign(signer ed25519.PrivateKey, keyID string, cp model.Checkpoint) (*model.SignedCheckpoint, error) {
	body, err := canon.Marshal(cp)
	if err != nil {
		return nil, err
	}
	return &model.SignedCheckpoint{
		Checkpoint: cp,
		KeyID:      keyID,
		Algorithm:  Algorithm,
		Signature:  base64.StdEncoding.EncodeToString(ed25519.Sign(signer, body)),
	}, nil
}

// VerifyCheckpoint checks a signed checkpoint against a public key.
func VerifyCheckpoint(pub ed25519.PublicKey, sc *model.SignedCheckpoint) error {
	if sc.Algorithm != Algorithm {
		return fmt.Errorf("checkpoint: unsupported algorithm %q", sc.Algorithm)
	}
	body, err := canon.Marshal(sc.Checkpoint)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sc.Signature)
	if err != nil {
		return fmt.Errorf("checkpoint: signature: %w", err)
	}
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("checkpoint: signature does not verify")
	}
	return nil
}

// SignBundle signs an evidence bundle in place. The signature covers
// every field except the signature itself, so a bundle cannot be
// re-pointed at a different row, root or checkpoint after the fact.
func SignBundle(signer ed25519.PrivateKey, keyID string, b *model.EvidenceBundle) error {
	b.KeyID = keyID
	b.Algorithm = Algorithm
	b.Signature = ""
	body, err := canon.Marshal(b)
	if err != nil {
		return err
	}
	b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, body))
	return nil
}

// VerifyBundleSignature checks the register's assertion about the row.
func VerifyBundleSignature(pub ed25519.PublicKey, b *model.EvidenceBundle) error {
	if b.Algorithm != Algorithm {
		return fmt.Errorf("bundle: unsupported algorithm %q", b.Algorithm)
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("bundle: signature: %w", err)
	}
	unsigned := *b
	unsigned.Signature = ""
	body, err := canon.Marshal(&unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sig) {
		return errors.New("bundle: signature does not verify")
	}
	return nil
}

// VerifyBundleProof recomputes the ledger root from the bundle's proof
// and checks it against the root the bundle claims. This is the part
// that needs no trust at all: it is arithmetic over hashes.
func VerifyBundleProof(b *model.EvidenceBundle) error {
	rootBytes, err := hex.DecodeString(b.Root)
	if err != nil || len(rootBytes) != 32 {
		return errors.New("bundle: root is not a 32-byte hex value")
	}
	pathBytes, err := hex.DecodeString(b.Path)
	if err != nil || len(pathBytes) != 32 {
		return errors.New("bundle: path is not a 32-byte hex value")
	}
	proofBytes, err := hex.DecodeString(b.Proof)
	if err != nil {
		return fmt.Errorf("bundle: proof: %w", err)
	}
	proof, err := ledger.DecodeProof(proofBytes)
	if err != nil {
		return fmt.Errorf("bundle: proof: %w", err)
	}
	var root, path ledger.Hash
	copy(root[:], rootBytes)
	copy(path[:], pathBytes)
	verified, err := ledger.Verify(&root, &path, proof)
	if err != nil {
		return fmt.Errorf("bundle: proof does not hold: %w", err)
	}
	if verified.Present != b.Present {
		if b.Present {
			return errors.New("bundle: claims the row is present, the proof shows it absent")
		}
		return errors.New("bundle: claims the row is absent, the proof shows it present")
	}
	return nil
}

// VerifyBundleAgainstCheckpoint ties the state the bundle was read at
// to a checkpoint the customer holds. Without this step a bundle proves
// internal consistency only: that some state contained this row.
func VerifyBundleAgainstCheckpoint(b *model.EvidenceBundle, cp *model.Checkpoint) error {
	if cp.Version != b.Version {
		return fmt.Errorf("bundle: read at version %d, checkpoint covers version %d", b.Version, cp.Version)
	}
	if cp.Root != b.Root {
		return errors.New("bundle: the checkpoint's root is not the root the row was read at")
	}
	return nil
}

// ParsePublicKey decodes a base64 Ed25519 verification key.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("checkpoint: public key is %d bytes, expected %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
