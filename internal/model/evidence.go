// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package model

// Checkpoint is the monitor's external anchor: a signed statement that
// at this version the authenticated state had this root and this
// lineage head.
//
// A checkpoint is what a customer holds outside the system that
// produced it. The ledger's freshness guarantee is strong while the
// process runs, but a backend replayed from an old copy is a consistent
// history, just not the current one. A monitor that rolled its record
// back cannot produce a chain that reaches the version the customer
// already holds, and a customer's receipt of a checkpoint also bounds
// the enclave's clock claim against their own.
type Checkpoint struct {
	Instance string `json:"instance"`
	Version  uint64 `json:"version"`
	Root     string `json:"root"`
	// Head is the lineage-chain head at this version. The head commits
	// to every root before it, so a checkpoint carrying one anchors the
	// whole history rather than a single state.
	Head        string         `json:"head,omitempty"`
	IssuedAt    int64          `json:"issued_at"`
	Reason      string         `json:"reason"`
	ImageDigest string         `json:"image_digest,omitempty"`
	TxSeq       uint64         `json:"tx_seq"`
	Summary     map[string]any `json:"summary,omitempty"`
	// Previous names the checkpoint before this one, so the chain links
	// itself. A monitor that served two histories has to have signed two
	// chains, and the fork is visible in the links.
	Previous *CheckpointRef `json:"previous,omitempty"`
}

// CheckpointRef identifies one checkpoint by the state it attests.
type CheckpointRef struct {
	Version uint64 `json:"version"`
	Root    string `json:"root"`
}

// SignedCheckpoint is a checkpoint with its detached signature and the
// key that produced it.
type SignedCheckpoint struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	KeyID      string     `json:"key_id"`
	Algorithm  string     `json:"alg"`
	Signature  string     `json:"signature"`
}

// EvidenceBundle is the exportable proof package for one row: the
// ledger entry, its inclusion (or absence) proof, the state it was read
// at, and the signed checkpoint that anchors that state.
//
// The signature covers every field except the signature itself, which
// is blanked rather than removed before hashing. A verifier that
// removes the field instead computes different bytes and rejects every
// bundle, which is why the browser verifier is exercised against a real
// bundle in CI.
type EvidenceBundle struct {
	Instance    string         `json:"instance"`
	Statement   string         `json:"statement"`
	Table       string         `json:"table"`
	PrimaryKey  []any          `json:"primary_key"`
	Present     bool           `json:"present"`
	Row         map[string]any `json:"row,omitempty"`
	LedgerKey   string         `json:"ledger_key"`
	LedgerValue string         `json:"ledger_value,omitempty"`
	// Path is the leaf position the proof is about: the keyed hash of
	// the ledger key. An offline verifier needs it because the mapping
	// from key to path is under the commitment key, which stays in the
	// enclave.
	Path       string            `json:"path"`
	Proof      string            `json:"proof"`
	Root       string            `json:"root"`
	Version    uint64            `json:"version"`
	IssuedAt   int64             `json:"issued_at"`
	Checkpoint *SignedCheckpoint `json:"checkpoint,omitempty"`
	KeyID      string            `json:"key_id"`
	Algorithm  string            `json:"alg"`
	Signature  string            `json:"signature"`
}

// Lineage is the audit artefact that needs no key at all: two anchors
// and the public roots between them. An auditor folds the earlier head
// forward with a pure function and requires it to arrive at the later
// one. A monitor that rewrote a root in between cannot reach the
// anchored head; doing so would be a preimage attack.
type Lineage struct {
	From  *SignedCheckpoint `json:"from"`
	To    *SignedCheckpoint `json:"to"`
	Roots []RootAt          `json:"roots"`
}

// RootAt is one version's root, as published for auditing.
type RootAt struct {
	Version uint64 `json:"version"`
	Root    string `json:"root"`
}
