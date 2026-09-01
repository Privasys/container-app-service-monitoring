// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"fmt"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Retention.
//
// Individual readings are kept for as long as a dispute about a single
// minute might need them, and then they go. What stays is the folded
// interval, which is what the arithmetic used anyway, and the mark
// saying that readings were removed under a policy. A record that
// quietly loses its oldest entries and a record that says "these were
// pruned on this date under this policy" look identical from the
// outside unless the second one is written down, so it is written down.
//
// The physical removal from the ledger is deliberately separate. The
// rows go first, as a signed transaction; the storage is reclaimed only
// after somebody has anchored the state, which is the audit-then-prune
// order: verify the lineage, review what changed, sign the anchor, and
// only then let the bytes go.

// PruneResult reports what a prune removed.
type PruneResult struct {
	Scope   string `json:"scope"`
	Before  int64  `json:"before"`
	Rows    int64  `json:"rows"`
	TxID    string `json:"txid"`
	Version uint64 `json:"version"`
}

// PruneSamples removes readings older than the retention window.
func (m *Monitor) PruneSamples(p *auth.Principal, before int64) (*PruneResult, error) {
	if !p.Can(auth.PermRetention) {
		return nil, fmt.Errorf("%s may not run a prune", p.Acting)
	}
	if before <= 0 {
		days := m.Config().RawRetentionDays
		if days <= 0 {
			days = DefaultRawRetentionDays
		}
		before = m.Now() - int64(days)*86400
	}

	out := &PruneResult{Scope: "samples", Before: before}
	err := m.st.Do(func(tx *store.Tx) error {
		// Only readings that have been folded are removed. A reading
		// whose interval was never folded is the only record of that
		// interval, and dropping it would turn evidence into a gap.
		watermark, err := m.watermark(tx, "fold.minute")
		if err != nil {
			return err
		}
		if watermark < before {
			before = watermark
			out.Before = before
		}
		if before <= 0 {
			return nil
		}
		rows, err := tx.Query("SELECT id FROM `samples` WHERE started_at < " + store.Lit(before) +
			" AND pruned = FALSE ORDER BY started_at LIMIT 5000")
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		ops := make([]model.WriteOp, 0, len(rows)+1)
		for _, row := range rows {
			ops = append(ops, model.WriteOp{
				Table: "samples", Key: map[string]any{"id": row.Str("id")}, Delete: true,
			})
		}
		ops = append(ops, model.WriteOp{
			Table: "prune_marks", Key: map[string]any{"txid": model.TxIDPlaceholder, "idx": uint64(0)},
			Values: map[string]any{
				"scope": "samples", "from_time": int64(0), "to_time": before,
				"rows_removed": int64(len(rows)), "policy": "raw-retention",
				"created_at": m.Now(),
			},
		})
		tr, err := m.commit(tx, model.Envelope{
			Kind: model.KindRetentionPrune, Author: p.Author(), Timestamp: m.Now(),
			Message: fmt.Sprintf("Prune %d readings older than the retention window", len(rows)),
		}, ops)
		if err != nil {
			return err
		}
		out.Rows = int64(len(rows))
		out.TxID = tr.TxID
		out.Version = tr.VersionAfter
		return nil
	})
	return out, err
}

// ReclaimStorage removes the ledger history behind a version whose
// state has been anchored.
//
// This is the second half of audit-then-prune, and it is irreversible.
// It refuses to run for a version no signed checkpoint covers, because
// the anchor is what lets an auditor verify the lineage up to that
// point after the detail behind it is gone.
func (m *Monitor) ReclaimStorage(p *auth.Principal, beforeVersion uint64) (int64, error) {
	if !p.Can(auth.PermRetention) {
		return 0, fmt.Errorf("%s may not reclaim storage", p.Acting)
	}
	var removed int64
	err := m.st.Do(func(tx *store.Tx) error {
		anchor, err := latestCheckpoint(tx)
		if err != nil {
			return err
		}
		if anchor == nil || anchor.Checkpoint.Version < beforeVersion {
			return fmt.Errorf("core: no signed checkpoint covers version %d; anchor the state first",
				beforeVersion)
		}
		stats, err := tx.Ledger().Prune(beforeVersion)
		if err != nil {
			return err
		}
		removed = int64(stats.RecordsDeleted + stats.RootRecordsDeleted)
		return nil
	})
	return removed, err
}
