// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package keys manages the key material the register keeps on its
// sealed volume.
//
// The volume's LUKS key is released at boot only to a measurement the
// app owner has approved, so what is written here is readable only by
// an approved build of this register on this machine. Two secrets live
// here: the master secret, from which the operational data-encryption
// key wrapper is derived, and the checkpoint signing key, which is what
// lets a customer hold externally verifiable evidence of the
// register's state.
//
// The ledger commitment key is deliberately not one of them by default.
// It is delivered through the attested configure call and held in
// memory; what is written to the volume is only a check value, so a
// restart can tell a wrong key from a corrupt store instead of opening
// one over the other.
package keys

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Material is the register's sealed key material.
type Material struct {
	// Master is the sealed master secret.
	Master [32]byte
	// Signer signs root checkpoints and evidence bundles.
	Signer ed25519.PrivateKey
	// KeyID is SHA-256 of the public signing key, hex encoded.
	KeyID string
	// Dir is the directory the material lives in.
	Dir string
}

// PublicKey returns the checkpoint verification key.
func (m *Material) PublicKey() ed25519.PublicKey {
	return m.Signer.Public().(ed25519.PublicKey)
}

// Load reads the key material from dir, generating anything that is not
// there yet. A fresh register generates both secrets on first boot; a
// restarted one finds them where the previous boot left them.
func Load(dir string) (*Material, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	m := &Material{Dir: dir}

	master, err := loadOrCreate(filepath.Join(dir, "master.key"), 32)
	if err != nil {
		return nil, err
	}
	copy(m.Master[:], master)

	seed, err := loadOrCreate(filepath.Join(dir, "checkpoint.ed25519"), ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	m.Signer = ed25519.NewKeyFromSeed(seed)
	sum := sha256.Sum256(m.PublicKey())
	m.KeyID = hex.EncodeToString(sum[:])
	return m, nil
}

func loadOrCreate(path string, size int) ([]byte, error) {
	buf, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(buf) != size {
			return nil, fmt.Errorf("keys: %s is %d bytes, expected %d", filepath.Base(path), len(buf), size)
		}
		return buf, nil
	case errors.Is(err, os.ErrNotExist):
		buf = make([]byte, size)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("keys: generate %s: %w", filepath.Base(path), err)
		}
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			return nil, fmt.Errorf("keys: write %s: %w", filepath.Base(path), err)
		}
		return buf, nil
	default:
		return nil, fmt.Errorf("keys: read %s: %w", filepath.Base(path), err)
	}
}

// Commitment-key sources, reported at /api/v1/health so an operator can
// see at a glance whether the register is holding its own key or being
// given one.
const (
	// SourceDelivered means the key arrived through the attested
	// configure call and exists only in memory.
	SourceDelivered = "delivered"
	// SourceDerived means the register derived the key from its own
	// sealed master secret. Convenient, and the right answer for a
	// single-custodian deployment, but the key is then only as separate
	// from the data as the volume is.
	SourceDerived = "derived"
)

// CommitmentKey resolves the ledger commitment key. When delivered is
// nil the key is derived from the master secret. Either way the result
// is checked against the value the store was created with, so a
// register never opens a store with the wrong key and reports the
// resulting mismatch as corruption.
func (m *Material) CommitmentKey(delivered *[32]byte) (ck [32]byte, source string, err error) {
	if delivered != nil {
		ck, source = *delivered, SourceDelivered
	} else {
		source = SourceDerived
		derived, dErr := hkdf.Key(sha256.New, m.Master[:], nil, "monitor/commitment-key/v1", 32)
		if dErr != nil {
			return ck, source, fmt.Errorf("keys: derive commitment key: %w", dErr)
		}
		copy(ck[:], derived)
	}
	if err := m.checkCommitmentKey(ck); err != nil {
		return ck, source, err
	}
	return ck, source, nil
}

// checkCommitmentKey records, and thereafter enforces, which key this
// store belongs to.
func (m *Material) checkCommitmentKey(ck [32]byte) error {
	mac := hmac.New(sha256.New, ck[:])
	mac.Write([]byte("monitor/ck-check/v1"))
	want := mac.Sum(nil)

	path := filepath.Join(m.Dir, "ck.check")
	have, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.WriteFile(path, want, 0o600)
	case err != nil:
		return fmt.Errorf("keys: read commitment-key check: %w", err)
	}
	if subtle.ConstantTimeCompare(have, want) != 1 {
		return errors.New("keys: the commitment key does not match the one this store was created with; " +
			"the store is intact, the key is wrong")
	}
	return nil
}

// Fingerprint is the value committed to the RA-TLS leaf so a verifying
// client can confirm the register was given exactly the commitment key
// the deployer delivered, without the key itself ever leaving the
// enclave.
func Fingerprint(ck [32]byte) []byte {
	sum := sha256.Sum256(append([]byte("monitor/ck-fingerprint/v1"), ck[:]...))
	return sum[:]
}
