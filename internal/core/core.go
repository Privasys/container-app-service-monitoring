// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package core is the monitor itself: the service model, the readings,
// the detection, the incidents, the reports and the transactions that
// carry all of them.
//
// One rule governs the package. Every state change is a transaction
// with a commit envelope, and every transaction is exactly one ledger
// commit, so the availability record moves one version at a time and
// each version has an author, an instant and a reason attached to it.
// Nothing writes rows directly.
package core

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/canon"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/keys"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Options configure a monitor instance.
type Options struct {
	// Name identifies the instance in checkpoints and reports.
	Name string
	// Vantage names the observation point this instance speaks for.
	Vantage string
	// Tenant is the customer this instance serves. One instance serves
	// one tenant: a customer's credentials do not share an enclave with
	// anyone else's.
	Tenant string
	// ImageDigest is the measurement of this build.
	ImageDigest string
	// CheckpointInterval is how often a quiet monitor anchors itself.
	CheckpointInterval time.Duration
	// CommitmentSource records whether the ledger key was delivered or
	// derived, for the health document.
	CommitmentSource string
	// Now is the clock, injectable for tests.
	Now func() time.Time
}

// Monitor is the running service.
type Monitor struct {
	st     *store.Store
	mat    *keys.Material
	vault  *secrets.Vault
	egress *journey.Allowlist
	engine *journey.Engine
	opts   Options

	// mu guards the configured flag and the in-memory view of the
	// service model the scheduler reads.
	mu         sync.RWMutex
	configured bool
	config     Config

	// hooks is where alert delivery is plugged in, so the core does not
	// depend on the transport.
	hooks Hooks
}

// Hooks lets the surrounding process observe what the core decides
// without the core knowing how notification works.
type Hooks struct {
	// OnAlert is called after an alert has been recorded. Delivery
	// happens outside the ledger transaction, and its attempts are
	// recorded by a later call to RecordDelivery.
	OnAlert func(alert Alert)
}

// Config is what the configure call established.
type Config struct {
	Tenant string `json:"tenant"`
	// CallbackHosts is the allowlist for outbound notifications. A
	// callback to a host nobody declared is refused.
	CallbackHosts []string `json:"callback_hosts,omitempty"`
	// PackRef names the service-model pack the instance was seeded from.
	PackRef string `json:"pack_ref,omitempty"`
	// RawRetentionDays is how long individual readings are kept before
	// the folded intervals stand alone.
	RawRetentionDays int `json:"raw_retention_days"`
	// MaintenanceLeadTime is the default notice a planned window needs
	// to leave agreed service time.
	MaintenanceLeadTime int64 `json:"maintenance_lead_time"`
	ConfiguredAt        int64 `json:"configured_at"`
}

// Defaults for a configuration that did not say.
const (
	DefaultRawRetentionDays    = 90
	DefaultMaintenanceLeadTime = int64(24 * 60 * 60)
	DefaultCoverageFloorPPM    = int64(990_000)
)

// New builds a monitor over an open store.
func New(st *store.Store, mat *keys.Material, vault *secrets.Vault, egress *journey.Allowlist, opts Options) *Monitor {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.CheckpointInterval <= 0 {
		opts.CheckpointInterval = 6 * time.Hour
	}
	m := &Monitor{
		st: st, mat: mat, vault: vault, egress: egress, opts: opts,
	}
	m.engine = journey.New(vault, egress)
	return m
}

// SetHooks installs the notification hooks.
func (m *Monitor) SetHooks(h Hooks) { m.hooks = h }

// Store exposes the store for the surfaces that read it directly.
func (m *Monitor) Store() *store.Store { return m.st }

// Engine exposes the journey engine, so a manual run can share it.
func (m *Monitor) Engine() *journey.Engine { return m.engine }

// Vault exposes the credential store.
func (m *Monitor) Vault() *secrets.Vault { return m.vault }

// Options returns the instance options.
func (m *Monitor) Options() Options { return m.opts }

// PublicKey is the verification key for checkpoints, bundles and
// reports.
func (m *Monitor) PublicKey() ed25519.PublicKey { return m.mat.PublicKey() }

// KeyID identifies the signing key.
func (m *Monitor) KeyID() string { return m.mat.KeyID }

// Now is the monitor's clock, in Unix seconds.
func (m *Monitor) Now() int64 { return m.opts.Now().Unix() }

// Configured reports whether the instance has been configured.
func (m *Monitor) Configured() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.configured
}

// Config returns the current configuration.
func (m *Monitor) Config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// -- transactions ----------------------------------------------------------

// pkColumns is the primary key of every table a write set may touch. A
// write set that names a table not listed here is refused before
// anything is written: an effect the core cannot key is an effect
// nobody can replay or compare.
var pkColumns = map[string][]string{
	"services":            {"id"},
	"components":          {"id"},
	"monitors":            {"id"},
	"monitor_versions":    {"monitor_id", "version"},
	"schedules":           {"id"},
	"objectives":          {"id"},
	"samples":             {"id"},
	"buckets":             {"monitor_id", "width_seconds", "bucket_start"},
	"incidents":           {"id"},
	"incident_updates":    {"id"},
	"maintenance_windows": {"id"},
	"secrets_meta":        {"name"},
	"alerts":              {"id"},
	"alert_deliveries":    {"id"},
	"reports":             {"id"},
	"runtime_events":      {"id"},
	"states":              {"subject"},
	"prune_marks":         {"txid", "idx"},
	"registry":            {"k"},
	"tx_refs":             {"txid", "idx"},
}

// commit runs one action: validate the envelope, write the transaction
// row ahead of its effects, and apply them, all inside one SQL
// transaction so the whole action is a single ledger commit.
func (m *Monitor) commit(tx *store.Tx, env model.Envelope, ops []model.WriteOp) (*model.Transaction, error) {
	if env.Tenant == "" {
		env.Tenant = m.opts.Tenant
	}
	if env.Timestamp == 0 {
		env.Timestamp = m.Now()
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	for _, op := range ops {
		if _, ok := pkColumns[op.Table]; !ok {
			return nil, fmt.Errorf("core: write set touches unknown table %q", op.Table)
		}
		if len(op.Key) == 0 {
			return nil, fmt.Errorf("core: write set entry for %q has no key", op.Table)
		}
	}

	envelope, err := canon.Marshal(env)
	if err != nil {
		return nil, err
	}
	writeSet, err := canon.Marshal(ops)
	if err != nil {
		return nil, err
	}
	txid := model.TxID(envelope, writeSet)

	if existing, err := m.transactionByID(tx, txid); err != nil {
		return nil, err
	} else if existing != nil {
		// The same envelope and the same effects at the same instant: a
		// retried request, not a second change.
		return existing, nil
	}

	rootBefore, versionBefore := tx.Root()
	if err := tx.Begin(); err != nil {
		return nil, fmt.Errorf("core: open transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	objectID := ""
	if len(env.ObjectIDs) > 0 {
		objectID = env.ObjectIDs[0]
	}
	if err := tx.Exec(store.Insert("transactions", map[string]any{
		"txid": txid, "tenant": env.Tenant, "kind": env.Kind,
		"service_id": env.Service, "object_id": objectID,
		"author_sub": env.Author.Sub, "author_display": env.Author.Display,
		"author_role": env.Author.Role, "summary": clip(env.Summary(), 255),
		"created_at":  env.Timestamp,
		"root_before": rootBefore, "version_before": versionBefore,
		"version_after": versionBefore + 1,
		"envelope":      envelope, "write_set": writeSet,
	})); err != nil {
		return nil, fmt.Errorf("core: record transaction: %w", err)
	}
	if err := m.apply(tx, txid, env, ops); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("core: commit: %w", err)
	}
	committed = true

	return &model.Transaction{
		TxID: txid, Envelope: env, WriteSet: ops,
		RootBefore: rootBefore, VersionBefore: versionBefore, VersionAfter: versionBefore + 1,
	}, nil
}

func (m *Monitor) apply(tx *store.Tx, txid string, env model.Envelope, ops []model.WriteOp) error {
	for i, op := range ops {
		if err := m.applyOne(tx, txid, op); err != nil {
			return fmt.Errorf("core: write set entry %d (%s): %w", i, op.Table, err)
		}
	}
	for i, ref := range env.Refs {
		if err := m.applyOne(tx, txid, model.WriteOp{
			Table:  "tx_refs",
			Key:    map[string]any{"txid": txid, "idx": uint64(i)},
			Values: map[string]any{"ref_type": ref.Type, "target": ref.Target},
		}); err != nil {
			return fmt.Errorf("core: reference %d: %w", i, err)
		}
	}
	return nil
}

// applyOne is an upsert or a delete keyed by primary key, so replaying
// a write set converges on the same rows.
func (m *Monitor) applyOne(tx *store.Tx, txid string, op model.WriteOp) error {
	keyCols := pkColumns[op.Table]
	key := make(map[string]any, len(op.Key))
	for k, v := range op.Key {
		key[k] = substitute(v, txid)
	}
	for _, col := range keyCols {
		if _, ok := key[col]; !ok {
			return fmt.Errorf("key column %q is missing", col)
		}
	}
	clauses := make([]string, 0, len(keyCols))
	for _, col := range keyCols {
		clauses = append(clauses, store.Ident(col)+" = "+store.Lit(key[col]))
	}
	where := strings.Join(clauses, " AND ")

	if op.Delete {
		return tx.Exec("DELETE FROM " + store.Ident(op.Table) + " WHERE " + where)
	}

	values := make(map[string]any, len(op.Values))
	for k, v := range op.Values {
		values[k] = substitute(v, txid)
	}
	exists, err := tx.Count("SELECT COUNT(*) FROM " + store.Ident(op.Table) + " WHERE " + where)
	if err != nil {
		return err
	}
	if exists > 0 {
		if len(values) == 0 {
			return nil
		}
		return tx.Exec(store.Update(op.Table, values, where))
	}
	for col, v := range key {
		values[col] = v
	}
	return tx.Exec(store.Insert(op.Table, values))
}

// substitute resolves the transaction-id placeholder and restores the
// types a JSON round trip flattens.
func substitute(v any, txid string) any {
	switch t := v.(type) {
	case string:
		if t == model.TxIDPlaceholder {
			return txid
		}
		return t
	case model.Binary:
		return []byte(t)
	case map[string]any:
		if decoded, ok := model.DecodeBinary(t); ok {
			return decoded
		}
		return t
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	case int:
		return int64(t)
	}
	return v
}

func (m *Monitor) transactionByID(tx *store.Tx, txid string) (*model.Transaction, error) {
	row, err := tx.QueryOne("SELECT * FROM `transactions` WHERE txid = " + store.Lit(txid))
	if err != nil || row == nil {
		return nil, err
	}
	return rowToTransaction(row)
}

func rowToTransaction(row store.Row) (*model.Transaction, error) {
	t := &model.Transaction{
		Seq: row.Uint("seq"), TxID: row.Str("txid"),
		RootBefore: row.Str("root_before"), VersionBefore: row.Uint("version_before"),
		VersionAfter: row.Uint("version_after"),
	}
	if raw := row.Bytes("envelope"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &t.Envelope); err != nil {
			return nil, fmt.Errorf("core: transaction %s envelope: %w", t.TxID, err)
		}
	}
	if raw := row.Bytes("write_set"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &t.WriteSet); err != nil {
			return nil, fmt.Errorf("core: transaction %s write set: %w", t.TxID, err)
		}
	}
	return t, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// jsonBytes marshals a value for a BLOB column.
func jsonBytes(v any) (model.Binary, error) {
	raw, err := canon.Marshal(v)
	if err != nil {
		return nil, err
	}
	return model.Binary(raw), nil
}

// csv joins identifiers for the small VARCHAR list columns. The lists
// are short by construction (the components an incident touches, the
// samples that opened it) and keeping them inline keeps a status-page
// read to one row.
func csv(list []string) string { return strings.Join(list, ",") }

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// summarise renders a name into a commit summary line.
//
// The envelope refuses a summary that ends with a full stop, which is
// the right rule for a message somebody wrote and the wrong reason to
// reject a reading. A component called "API." would otherwise make its
// own transactions unwritable, so generated summaries are trimmed here
// rather than defended against everywhere they are built.
func summarise(s string, n int) string {
	return strings.TrimRight(clip(strings.TrimSpace(s), n), ". ")
}
