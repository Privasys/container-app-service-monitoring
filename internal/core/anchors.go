// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	ledger "github.com/Privasys/immutable-ledger/ledger"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/checkpoint"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Anchors: signed checkpoints, evidence bundles and the lineage an
// auditor folds.
//
// Everything else in this service is verifiable from the inside. A
// checkpoint is what a customer holds on the outside, so a monitor
// restored from an old copy of its own storage cannot pass that state
// off as the current one. It is also what bounds the clock: the
// enclave's timestamps are its own assertion, but a checkpoint received
// and timestamped by the customer's own systems bounds them from
// outside, and that receipt costs nothing to keep.
//
// # Why checkpoints are not ledger rows
//
// The obvious design stores each checkpoint as a row like everything
// else. It cannot work: a checkpoint states the root at a version, and
// writing it would advance the version past the one it states, so every
// checkpoint would attest a state the monitor had already left. They
// therefore live beside the ledger, and the chain carries its own
// integrity: each names the version and root of the one before it, and
// all of them are signed. A monitor that served two histories has to
// have signed both, which is exactly what the chain check looks for.

// Checkpoint reasons.
const (
	ReasonScheduled = "scheduled"
	ReasonEvent     = "event"
	ReasonManual    = "manual"
	ReasonBootstrap = "bootstrap"
	ReasonReport    = "report"
)

// checkpointPrefix is the backend keyspace checkpoints live in, outside
// every prefix the ledger and its SQL layer use.
const checkpointPrefix = 'K'

func checkpointKey(version uint64) []byte {
	k := make([]byte, 0, 9)
	k = append(k, checkpointPrefix)
	return binary.BigEndian.AppendUint64(k, version)
}

// IssueCheckpoint signs the current state and records it.
func (m *Monitor) IssueCheckpoint(reason string) (*model.SignedCheckpoint, error) {
	var signed *model.SignedCheckpoint
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		signed, err = m.issueCheckpoint(tx, reason)
		return err
	})
	if err != nil {
		return nil, err
	}
	if signed == nil {
		return m.LatestCheckpoint()
	}
	return signed, nil
}

func (m *Monitor) issueCheckpoint(tx *store.Tx, reason string) (*model.SignedCheckpoint, error) {
	root, version := tx.Root()
	previous, err := latestCheckpoint(tx)
	if err != nil {
		return nil, err
	}
	if previous != nil && previous.Checkpoint.Version == version {
		// The state has not moved. A checkpoint that repeats the previous
		// one is not more evidence.
		return nil, nil
	}

	summary, txSeq, err := m.checkpointSummary(tx)
	if err != nil {
		return nil, err
	}
	head, _, err := tx.HistoryHead()
	if err != nil {
		return nil, err
	}
	cp := model.Checkpoint{
		Instance: m.opts.Name, Version: version, Root: root, Head: head,
		IssuedAt: m.Now(), Reason: reason, ImageDigest: m.opts.ImageDigest,
		TxSeq: txSeq, Summary: summary,
	}
	if previous != nil {
		cp.Previous = &model.CheckpointRef{
			Version: previous.Checkpoint.Version, Root: previous.Checkpoint.Root,
		}
	}
	signed, err := checkpoint.Sign(m.mat.Signer, m.mat.KeyID, cp)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	if err := tx.Ledger().Backend().WriteBatch([]ledger.BatchOp{
		{Key: checkpointKey(version), Value: body},
	}); err != nil {
		return nil, fmt.Errorf("core: record checkpoint: %w", err)
	}
	return signed, nil
}

// anchorCurrentState makes sure the state a caller is about to be given
// evidence about is one the monitor has publicly committed to. Issuing
// a checkpoint moves no version, so the anchor is exact.
func (m *Monitor) anchorCurrentState(tx *store.Tx) (*model.SignedCheckpoint, error) {
	if signed, err := m.issueCheckpoint(tx, ReasonEvent); err != nil {
		return nil, err
	} else if signed != nil {
		return signed, nil
	}
	return latestCheckpoint(tx)
}

func (m *Monitor) checkpointSummary(tx *store.Tx) (map[string]any, uint64, error) {
	counts := map[string]int64{}
	for name, stmt := range map[string]string{
		"transactions": "SELECT COUNT(*) FROM `transactions`",
		"monitors":     "SELECT COUNT(*) FROM `monitors` WHERE enabled = TRUE",
		"samples":      "SELECT COUNT(*) FROM `samples` WHERE pruned = FALSE",
		"incidents":    "SELECT COUNT(*) FROM `incidents`",
		"reports":      "SELECT COUNT(*) FROM `reports`",
	} {
		n, err := tx.Count(stmt)
		if err != nil {
			return nil, 0, err
		}
		counts[name] = n
	}
	var seq uint64
	if row, err := tx.QueryOne("SELECT seq FROM `transactions` ORDER BY seq DESC LIMIT 1"); err == nil && row != nil {
		seq = row.Uint("seq")
	}
	return map[string]any{
		"transactions":        counts["transactions"],
		"monitors":            counts["monitors"],
		"samples":             counts["samples"],
		"incidents":           counts["incidents"],
		"reports":             counts["reports"],
		"vantage":             m.opts.Vantage,
		"commitment_key_from": m.opts.CommitmentSource,
	}, seq, nil
}

// LatestCheckpoint returns the most recent signed checkpoint.
func (m *Monitor) LatestCheckpoint() (*model.SignedCheckpoint, error) {
	var out *model.SignedCheckpoint
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = latestCheckpoint(tx)
		return err
	})
	return out, err
}

func latestCheckpoint(tx *store.Tx) (*model.SignedCheckpoint, error) {
	list, err := readCheckpoints(tx, 1, true)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return list[0], nil
}

// readCheckpoints scans the checkpoint keyspace. Versions are stored
// big-endian, so the scan is already in chain order.
func readCheckpoints(tx *store.Tx, limit int, newestFirst bool) ([]*model.SignedCheckpoint, error) {
	start := []byte{checkpointPrefix}
	end := []byte{checkpointPrefix + 1}
	var out []*model.SignedCheckpoint
	for {
		kvs, err := tx.Ledger().Backend().Scan(start, end, 256)
		if err != nil {
			return nil, fmt.Errorf("core: read checkpoints: %w", err)
		}
		if len(kvs) == 0 {
			break
		}
		for _, kv := range kvs {
			var sc model.SignedCheckpoint
			if err := json.Unmarshal(kv.Value, &sc); err != nil {
				return nil, fmt.Errorf("core: checkpoint record: %w", err)
			}
			out = append(out, &sc)
		}
		last := kvs[len(kvs)-1].Key
		start = append(append([]byte{}, last...), 0)
	}
	if newestFirst {
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Checkpoints returns the chain, newest first.
func (m *Monitor) Checkpoints(p *auth.Principal, limit int) ([]*model.SignedCheckpoint, error) {
	if !p.Can(auth.PermCheckpoints) {
		return nil, fmt.Errorf("%s may not read checkpoints", p.Acting)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []*model.SignedCheckpoint
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = readCheckpoints(tx, limit, true)
		return err
	})
	return out, err
}

// VerificationKey is the public half of the signing key, published so a
// customer can verify what the monitor signs without asking the monitor.
func (m *Monitor) VerificationKey() (keyID, publicKey string) {
	return m.mat.KeyID, base64.StdEncoding.EncodeToString(m.mat.PublicKey())
}

// Evidence returns a row with the proof that it is part of the
// monitor's authenticated state, signed, and anchored to a checkpoint.
func (m *Monitor) Evidence(p *auth.Principal, table string, pk []any, statement string) (*model.EvidenceBundle, error) {
	if !p.Can(auth.PermProofs) {
		return nil, fmt.Errorf("%s may not fetch proofs", p.Acting)
	}
	var out *model.EvidenceBundle
	err := m.st.Do(func(tx *store.Tx) error {
		bundle, err := m.evidence(tx, table, pk, statement)
		out = bundle
		return err
	})
	return out, err
}

func (m *Monitor) evidence(tx *store.Tx, table string, pk []any, statement string) (*model.EvidenceBundle, error) {
	// Anchor first. Issuing a checkpoint moves no version, so after this
	// the state the row is read at is exactly the state the checkpoint
	// attests, and the bundle verifies end to end without asking the
	// monitor for anything else.
	anchor, err := m.anchorCurrentState(tx)
	if err != nil {
		return nil, err
	}
	verified, err := tx.SQL().VerifiedGet(table, pk...)
	if err != nil {
		return nil, err
	}
	path, proof, err := tx.Prove(verified.Key)
	if err != nil {
		return nil, err
	}
	root, version := tx.Root()
	bundle := &model.EvidenceBundle{
		Instance: m.opts.Name, Statement: statement, Table: table, PrimaryKey: pk,
		Present:   verified.Row != nil,
		LedgerKey: hex.EncodeToString(verified.Key),
		Path:      hex.EncodeToString(path[:]),
		Proof:     hex.EncodeToString(proof.Encode()),
		Root:      root, Version: version, IssuedAt: m.Now(),
	}
	if verified.Value != nil {
		bundle.LedgerValue = hex.EncodeToString(verified.Value)
	}
	if verified.Row != nil {
		bundle.Row = map[string]any{}
		for i, col := range columnsOf(table, len(verified.Row)) {
			bundle.Row[col] = verified.Row[i]
		}
	}
	bundle.Checkpoint = anchor
	if err := checkpoint.SignBundle(m.mat.Signer, m.mat.KeyID, bundle); err != nil {
		return nil, err
	}
	return bundle, nil
}

func columnsOf(table string, n int) []string {
	if cols, ok := store.VerifiedColumns[table]; ok && len(cols) == n {
		return cols
	}
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("column_%d", i)
	}
	return out
}

// BucketEvidence proves one folded interval: the minute a dispute is
// about.
func (m *Monitor) BucketEvidence(p *auth.Principal, monitorID string, width, start int64) (*model.EvidenceBundle, error) {
	return m.Evidence(p, "buckets", []any{monitorID, width, start},
		fmt.Sprintf("the readings folded for %s over the %ds interval beginning %d", monitorID, width, start))
}

// SampleEvidence proves one reading.
func (m *Monitor) SampleEvidence(p *auth.Principal, id string) (*model.EvidenceBundle, error) {
	return m.Evidence(p, "samples", []any{id}, "the reading "+id)
}

// Lineage returns the current chain head with the proof that binds it
// to the live root.
func (m *Monitor) Lineage(p *auth.Principal) (*LineageStatus, error) {
	if !p.Can(auth.PermCheckpoints) {
		return nil, fmt.Errorf("%s may not read the lineage", p.Acting)
	}
	out := &LineageStatus{}
	err := m.st.Do(func(tx *store.Tx) error {
		out.Enabled = tx.HistoryEnabled()
		root, version := tx.Root()
		out.Root, out.Version = root, version
		if !out.Enabled {
			return nil
		}
		head, headVersion, err := tx.HistoryHead()
		if err != nil {
			return err
		}
		out.Head, out.HeadVersion = head, headVersion
		path, proof, err := tx.HistoryKeyProof()
		if err != nil {
			return err
		}
		out.Path = hex.EncodeToString(path[:])
		out.Proof = hex.EncodeToString(proof.Encode())
		return nil
	})
	return out, err
}

// LineageStatus is the chain head and its binding to the live root.
type LineageStatus struct {
	Enabled     bool   `json:"enabled"`
	Root        string `json:"root"`
	Version     uint64 `json:"version"`
	Head        string `json:"head,omitempty"`
	HeadVersion uint64 `json:"head_version,omitempty"`
	Path        string `json:"path,omitempty"`
	Proof       string `json:"proof,omitempty"`
}

// RootsBetween publishes the roots an auditor folds. Roots are not
// secret: folding them needs no key at all, which is why this is the
// check an auditor actually runs.
func (m *Monitor) RootsBetween(p *auth.Principal, from, to uint64) ([]model.RootAt, error) {
	if !p.Can(auth.PermCheckpoints) {
		return nil, fmt.Errorf("%s may not read the lineage", p.Acting)
	}
	if to < from {
		return nil, fmt.Errorf("the range ends before it starts")
	}
	if to-from > 100_000 {
		return nil, fmt.Errorf("the range is too wide; ask for it in parts")
	}
	var out []model.RootAt
	err := m.st.Do(func(tx *store.Tx) error {
		for v := from + 1; v <= to; v++ {
			root, err := tx.RootAt(v)
			if err != nil {
				return fmt.Errorf("core: root at version %d: %w", v, err)
			}
			out = append(out, model.RootAt{Version: v, Root: root})
		}
		return nil
	})
	return out, err
}
