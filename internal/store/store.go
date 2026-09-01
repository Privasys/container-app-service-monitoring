// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package store binds the register to immutable-ledger: the
// authenticated key-value core and the MySQL-dialect SQL layer that
// runs over it.
//
// Everything the register persists is a ledger entry. Rows, the
// catalogue, the transaction log and the checkpoints all live under the
// same sparse Merkle tree, so one 32-byte root attests the whole
// database, and any row can be returned with an inclusion proof that
// verifies against that root offline.
//
// The SQL engine is embedded in-process with no network listener: the
// register is the only policy boundary in front of its data.
package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gms "github.com/dolthub/go-mysql-server/sql"

	"github.com/cockroachdb/pebble/v2"

	pebblebackend "github.com/Privasys/immutable-ledger/backend/pebble"
	ledger "github.com/Privasys/immutable-ledger/ledger"
	"github.com/Privasys/immutable-ledger/sqlledger"
)

// DBName is the SQL database the register serves.
const DBName = "monitoring"

// Store is the register's handle on the ledger and its SQL layer.
//
// Access is serialised through one mutex. The ledger core is
// single-writer by design, and serialising reads alongside writes is
// also what gives a governance action one unambiguous position in the
// transaction log: while an action holds the store, no other statement
// can slip between its write-set and the commit that marks it applied.
type Store struct {
	mu      sync.Mutex
	led     *ledger.Store
	sql     *sqlledger.Store
	engine  *sqlledger.Engine
	backend *pebblebackend.Backend
	dir     string
	closed  bool
	ck      [32]byte
}

// Open opens (or creates) the register's store under dir with the given
// commitment key.
func Open(dir string, ck [32]byte) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: data directory: %w", err)
	}
	backend, err := pebblebackend.Open(filepath.Join(dir, "ledger"), &pebblebackend.Options{
		// Pebble logs recovery and compaction detail to standard error by
		// default. The register emits structured JSON, and a register's
		// log lines are read by operators rather than by storage
		// engineers, so the engine's chatter is discarded and only its
		// failures reach the caller as errors.
		Pebble: &pebble.Options{Logger: quietLogger{}},
	})
	if err != nil {
		return nil, fmt.Errorf("store: open backend: %w", err)
	}
	// The history chain is what makes the register auditable: every
	// commit extends a hash chain over the root sequence, and the chain
	// head is itself a leaf, so the live root pins the entire lineage.
	// It is a create-time choice — a store made without it cannot gain
	// it — so a register created before the chain existed opens without
	// one and says so at /api/v1/status rather than refusing to start.
	led, err := ledger.OpenOrCreate(backend, ck, ledger.WithHistoryChain())
	if err != nil {
		led, err = ledger.OpenOrCreate(backend, ck)
		if err != nil {
			backend.Close()
			return nil, fmt.Errorf("store: open ledger: %w", err)
		}
	}
	sqlStore, err := sqlledger.Open(led, backend, DBName)
	if err != nil {
		backend.Close()
		return nil, fmt.Errorf("store: open sql layer: %w", err)
	}
	return &Store{
		led:     led,
		sql:     sqlStore,
		engine:  sqlledger.NewEngine(sqlStore),
		backend: backend,
		dir:     dir,
		ck:      ck,
	}, nil
}

// Prove returns the leaf position of a ledger key together with its
// inclusion or absence proof.
//
// The position is the keyed hash of the key, HMAC-SHA-256 under the
// commitment key with the ledger's path tag. The ledger computes the
// same value internally and does not expose it, but an offline verifier
// needs it: a proof of absence has no leaf at the proven position to
// read it from. Recomputing it here is safe because it is checked
// against the ledger's own answer on every present key, and the store
// tests fail loudly if the two ever diverge.
func (t *Tx) Prove(key []byte) (path [32]byte, proof *ledger.Proof, err error) {
	mac := hmac.New(sha256.New, t.s.ck[:])
	mac.Write([]byte("p"))
	mac.Write(key)
	copy(path[:], mac.Sum(nil))

	proof, err = t.s.led.Prove(key)
	if err != nil {
		return path, nil, err
	}
	if leaf := proof.Leaf; leaf != nil && leaf.Path != path {
		// Present keys must agree. A mismatch would mean the ledger's
		// path commitment has changed under us.
		if _, ok, gErr := t.s.led.Get(key); gErr == nil && ok {
			return path, nil, fmt.Errorf("store: leaf position disagrees with the ledger for key %q", key)
		}
	}
	return path, proof, nil
}

// quietLogger discards the storage engine's informational output.
type quietLogger struct{}

func (quietLogger) Infof(string, ...any)  {}
func (quietLogger) Errorf(string, ...any) {}
func (quietLogger) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf("store: storage engine: "+format, args...))
}

// Close releases the backend. Closing twice is not an error: shutdown
// paths overlap, and a double close should not be a panic.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.backend.Close()
}

// Dir is the directory the store lives in.
func (s *Store) Dir() string { return s.dir }

// Do runs fn with exclusive access to the store. Everything that
// touches the ledger goes through it.
func (s *Store) Do(fn func(*Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// One session for the whole block. A SQL transaction is session
	// state, so a fresh context per statement would silently discard
	// BEGIN and commit each statement on its own.
	return fn(&Tx{s: s, ctx: s.engine.NewContext(context.Background())})
}

// Tx is exclusive access to the store, handed to a Do callback, and one
// SQL session. Statements run outside Begin are autocommit — one atomic
// ledger commit each; between Begin and Commit they buffer and land as a
// single commit, so a governance action occupies exactly one version.
type Tx struct {
	s   *Store
	ctx *gms.Context
}

// Ledger exposes the authenticated core for proofs, history and
// pruning.
func (t *Tx) Ledger() *ledger.Store { return t.s.led }

// SQL exposes the SQL layer (verified reads, catalogue).
func (t *Tx) SQL() *sqlledger.Store { return t.s.sql }

// Root returns the current authenticated state as (hex root, version).
func (t *Tx) Root() (string, uint64) {
	root, version := t.s.led.Root()
	return hex.EncodeToString(root[:]), version
}

// HistoryEnabled reports whether this store maintains the lineage
// chain. Stores created before the chain existed do not, and cannot be
// converted.
func (t *Tx) HistoryEnabled() bool { return t.s.led.HistoryEnabled() }

// HistoryHead returns the current chain head and the version it covers.
// Anchoring (root, version, head) together is what lets a later audit
// verify the lineage back to this point and prune everything before it.
func (t *Tx) HistoryHead() (string, uint64, error) {
	if !t.s.led.HistoryEnabled() {
		return "", 0, nil
	}
	head, version, err := t.s.led.HistoryHead()
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(head[:]), version, nil
}

// VerifyHistory confirms that the recorded root sequence from a
// previously anchored (version, head) is the unique lineage the live
// root commits to.
func (t *Tx) VerifyHistory(fromVersion uint64, fromHead string) error {
	if !t.s.led.HistoryEnabled() {
		return fmt.Errorf("store: this register has no lineage chain")
	}
	var head [32]byte
	if fromHead != "" {
		// An empty head means genesis, whose head is 32 zero bytes.
		// Auditing from the beginning should not require the caller to
		// know that.
		parsed, err := ParseHash(fromHead)
		if err != nil {
			return fmt.Errorf("store: anchor head: %w", err)
		}
		head = parsed
	} else if fromVersion != 0 {
		return fmt.Errorf("store: an anchor at version %d needs its head", fromVersion)
	}
	return t.s.led.VerifyHistory(fromVersion, head)
}

// RootAt returns the root recorded for a historical version. Roots and
// chain heads are not secret: an auditor recomputes the lineage from
// them with the pure link function, needing no commitment key.
func (t *Tx) RootAt(version uint64) (string, error) {
	root, err := t.s.led.RootAt(version)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(root[:]), nil
}

// ChangesAt reports what one commit changed, as leaf-level differences.
// Paths are keyed hashes, so logical keys are not recoverable from
// them.
func (t *Tx) ChangesAt(version uint64) ([]ledger.Change, error) {
	return t.s.led.ChangesAt(version)
}

// HistoryKeyProof proves the chain head is the value the live root
// commits to, so an auditor can bind a head to an anchored root without
// trusting the answer.
func (t *Tx) HistoryKeyProof() (path [32]byte, proof *ledger.Proof, err error) {
	return t.Prove(ledger.HistoryKey)
}

// ParseHash decodes a 32-byte hex hash.
func ParseHash(encoded string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// Exec runs one statement. Outside a transaction a data-modifying
// statement is one atomic ledger commit; inside one it buffers.
func (t *Tx) Exec(stmt string) error {
	_, err := t.Query(stmt)
	return err
}

// Query runs one statement and materialises its rows as maps keyed by
// column name, with values normalised to plain Go types.
func (t *Tx) Query(stmt string) ([]Row, error) {
	schema, iter, _, err := t.s.engine.Query(t.ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("sql: %w (%s)", err, truncate(stmt, 240))
	}
	rows, err := gms.RowIterToRows(t.ctx, iter)
	if err != nil {
		return nil, fmt.Errorf("sql: %w (%s)", err, truncate(stmt, 240))
	}
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		m := make(Row, len(schema))
		for i, col := range schema {
			if i < len(r) {
				m[strings.ToLower(col.Name)] = normalise(r[i])
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// Begin opens a SQL transaction on this session. Everything until Commit
// buffers and lands as one ledger commit, so an action that writes a
// dozen rows still moves the version once and adds one link to the
// lineage chain.
func (t *Tx) Begin() error { return t.Exec("BEGIN") }

// Commit applies the buffered statements as a single atomic commit.
func (t *Tx) Commit() error { return t.Exec("COMMIT") }

// Rollback discards them. Nothing reached storage, so there is no
// half-applied state to recover from.
func (t *Tx) Rollback() error { return t.Exec("ROLLBACK") }

// QueryOne returns the first row, or nil when the result set is empty.
func (t *Tx) QueryOne(stmt string) (Row, error) {
	rows, err := t.Query(stmt)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

// Count runs a single-value aggregate and returns it as an integer.
func (t *Tx) Count(stmt string) (int64, error) {
	row, err := t.QueryOne(stmt)
	if err != nil {
		return 0, err
	}
	for _, v := range row {
		return AsInt(v), nil
	}
	return 0, nil
}

// Tables lists the tables in the register database, lower-cased.
func (t *Tx) Tables() (map[string]bool, error) {
	rows, err := t.Query("SHOW TABLES")
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range rows {
		for _, v := range r {
			if name, ok := v.(string); ok {
				out[strings.ToLower(name)] = true
			}
		}
	}
	return out, nil
}

// Query is the read-only convenience wrapper for callers with nothing
// else to do under the lock.
func (s *Store) Query(stmt string) ([]Row, error) {
	var out []Row
	err := s.Do(func(tx *Tx) error {
		var err error
		out, err = tx.Query(stmt)
		return err
	})
	return out, err
}

// Row is one result row.
type Row map[string]any

// Str reads a column as a string.
func (r Row) Str(col string) string {
	switch v := r[col].(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// Bytes reads a column as raw bytes.
func (r Row) Bytes(col string) []byte {
	switch v := r[col].(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return nil
	}
}

// Int reads a column as an int64.
func (r Row) Int(col string) int64 { return AsInt(r[col]) }

// Uint reads a column as a uint64.
func (r Row) Uint(col string) uint64 {
	if v, ok := r[col].(uint64); ok {
		return v
	}
	n := AsInt(r[col])
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// Bool reads a column as a boolean. The SQL layer stores BOOLEAN as a
// small integer, so anything non-zero is true.
func (r Row) Bool(col string) bool { return AsInt(r[col]) != 0 }

// Has reports whether the row carries a non-NULL value for col.
func (r Row) Has(col string) bool {
	v, ok := r[col]
	return ok && v != nil
}

// AsInt coerces a SQL value to an int64.
func AsInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int32:
		return int64(n)
	case int16:
		return int64(n)
	case int8:
		return int64(n)
	case int:
		return int64(n)
	case uint64:
		return int64(n)
	case uint32:
		return int64(n)
	case uint16:
		return int64(n)
	case uint8:
		return int64(n)
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	case bool:
		if n {
			return 1
		}
		return 0
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	case []byte:
		i, _ := strconv.ParseInt(string(n), 10, 64)
		return i
	}
	return 0
}

// normalise converts engine values to types that survive JSON encoding.
func normalise(v any) any {
	switch t := v.(type) {
	case time.Time:
		return t.UTC().Format(time.RFC3339)
	case []byte:
		return append([]byte(nil), t...)
	default:
		return v
	}
}

// -- statement construction ------------------------------------------------
//
// The embedded engine exposes no bound-parameter API, so the register
// builds statement text. Every value goes through Lit and every
// identifier through Ident; nothing else is concatenated into a
// statement. Lit is exhaustive over the types the register stores and
// panics on anything else rather than emitting a value it has not
// escaped.

// Ident quotes an identifier. Register identifiers are generated from
// schema and pack names, which are constrained to [A-Za-z0-9_] before
// they reach here; the quoting is defence in depth.
func Ident(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// Lit renders a value as a SQL literal.
func Lit(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case bool:
		if t {
			return "TRUE"
		}
		return "FALSE"
	case string:
		return quote(t)
	case []byte:
		if len(t) == 0 {
			return "''"
		}
		return "X'" + hex.EncodeToString(t) + "'"
	case int:
		return strconv.FormatInt(int64(t), 10)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint:
		return strconv.FormatUint(uint64(t), 10)
	case uint32:
		return strconv.FormatUint(uint64(t), 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'g', -1, 32)
	case time.Time:
		return quote(t.UTC().Format("2006-01-02 15:04:05"))
	}
	panic(fmt.Sprintf("store: no SQL literal for %T", v))
}

// quote renders a string as a single-quoted literal with MySQL escapes.
// Backslash is an escape character inside MySQL string literals, so it
// is escaped alongside the quote.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case 0:
			b.WriteString(`\0`)
		case '\'':
			b.WriteString(`\'`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case 0x1a:
			b.WriteString(`\Z`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// Insert builds an INSERT for one row.
func Insert(table string, values map[string]any) string {
	cols, vals := columnsAndValues(values)
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		Ident(table), strings.Join(cols, ", "), strings.Join(vals, ", "))
}

// Update builds an UPDATE constrained by a WHERE clause the caller
// builds with Ident and Lit.
func Update(table string, values map[string]any, where string) string {
	cols, vals := columnsAndValues(values)
	sets := make([]string, len(cols))
	for i := range cols {
		sets[i] = cols[i] + " = " + vals[i]
	}
	return fmt.Sprintf("UPDATE %s SET %s WHERE %s", Ident(table), strings.Join(sets, ", "), where)
}

func columnsAndValues(values map[string]any) (cols, vals []string) {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cols = append(cols, Ident(name))
		vals = append(vals, Lit(values[name]))
	}
	return cols, vals
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
