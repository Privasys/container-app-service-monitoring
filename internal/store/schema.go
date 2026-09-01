// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package store

import "fmt"

// The monitor's base tables. Every one of them is ordinary ledger
// state: the root commits to the transaction log, the service model,
// the readings, the incidents, the maintenance windows and the reports
// alike. Nothing lives outside the tree, so nothing can be adjusted
// without moving the root.
//
// Constraints the SQL layer imposes, and how the monitor lives with
// them: every table declares a primary key; there are no foreign keys,
// so referential rules are enforced in the core; there are no column
// defaults, so every INSERT names every column; and there is no
// DECIMAL, JSON or ENUM, so structured values travel as canonical JSON
// in BLOB columns, timestamps as Unix seconds, and every ratio as an
// integer in parts per million. A contractual threshold is the last
// place to accept binary floating point rounding.
var baseTables = []tableDDL{
	{
		name: "transactions",
		ddl: `CREATE TABLE ` + "`transactions`" + ` (
			seq BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
			txid CHAR(64) NOT NULL,
			tenant VARCHAR(64) NOT NULL,
			kind VARCHAR(48) NOT NULL,
			service_id VARCHAR(96) NOT NULL,
			object_id VARCHAR(96) NOT NULL,
			author_sub VARCHAR(160) NOT NULL,
			author_display VARCHAR(160) NOT NULL,
			author_role VARCHAR(64) NOT NULL,
			summary VARCHAR(255) NOT NULL,
			created_at BIGINT NOT NULL,
			root_before CHAR(64) NOT NULL,
			version_before BIGINT UNSIGNED NOT NULL,
			version_after BIGINT UNSIGNED NOT NULL,
			envelope BLOB NOT NULL,
			write_set BLOB NOT NULL
		)`,
		indexes: []string{
			"CREATE UNIQUE INDEX `tx_txid` ON `transactions` (txid)",
			"CREATE INDEX `tx_time` ON `transactions` (created_at)",
			"CREATE INDEX `tx_kind` ON `transactions` (kind, seq)",
			"CREATE INDEX `tx_object` ON `transactions` (object_id, seq)",
			"CREATE INDEX `tx_author` ON `transactions` (author_sub)",
		},
	},
	{
		name: "tx_refs",
		ddl: `CREATE TABLE ` + "`tx_refs`" + ` (
			txid CHAR(64) NOT NULL,
			idx INT UNSIGNED NOT NULL,
			ref_type VARCHAR(24) NOT NULL,
			target VARCHAR(160) NOT NULL,
			PRIMARY KEY (txid, idx)
		)`,
		indexes: []string{
			"CREATE INDEX `ref_target` ON `tx_refs` (target)",
		},
	},
	{
		name: "services",
		ddl: `CREATE TABLE ` + "`services`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			tenant VARCHAR(64) NOT NULL,
			name VARCHAR(160) NOT NULL,
			slug VARCHAR(96) NOT NULL,
			description VARCHAR(1024) NOT NULL,
			timezone VARCHAR(64) NOT NULL,
			schedule_id VARCHAR(96) NOT NULL,
			visibility VARCHAR(16) NOT NULL,
			maintenance_lead_time BIGINT NOT NULL,
			coverage_floor_ppm BIGINT NOT NULL,
			callback_url VARCHAR(512) NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL
		)`,
		indexes: []string{
			"CREATE UNIQUE INDEX `svc_slug` ON `services` (tenant, slug)",
		},
	},
	{
		name: "components",
		ddl: `CREATE TABLE ` + "`components`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			service_id VARCHAR(96) NOT NULL,
			parent_id VARCHAR(96) NOT NULL,
			name VARCHAR(160) NOT NULL,
			description VARCHAR(1024) NOT NULL,
			user_weight BIGINT NOT NULL,
			rollup VARCHAR(16) NOT NULL,
			sort_order BIGINT NOT NULL,
			showcase BOOLEAN NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `cmp_service` ON `components` (service_id, sort_order)",
		},
	},
	{
		// The live definition of a monitor. Its history is in
		// monitor_versions, and a reading names the version it was taken
		// under, so a report can state what it measured and not only what
		// the answer was.
		name: "monitors",
		ddl: `CREATE TABLE ` + "`monitors`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			service_id VARCHAR(96) NOT NULL,
			component_id VARCHAR(96) NOT NULL,
			name VARCHAR(160) NOT NULL,
			version BIGINT UNSIGNED NOT NULL,
			enabled BOOLEAN NOT NULL,
			interval_seconds INT NOT NULL,
			timeout_seconds INT NOT NULL,
			failure_threshold INT NOT NULL,
			recovery_threshold INT NOT NULL,
			latency_budget_ms INT NOT NULL,
			steps BLOB NOT NULL,
			retired BOOLEAN NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `mon_service` ON `monitors` (service_id, name)",
			"CREATE INDEX `mon_component` ON `monitors` (component_id)",
		},
	},
	{
		name: "monitor_versions",
		ddl: `CREATE TABLE ` + "`monitor_versions`" + ` (
			monitor_id VARCHAR(96) NOT NULL,
			version BIGINT UNSIGNED NOT NULL,
			txid CHAR(64) NOT NULL,
			definition BLOB NOT NULL,
			created_at BIGINT NOT NULL,
			PRIMARY KEY (monitor_id, version)
		)`,
	},
	{
		name: "schedules",
		ddl: `CREATE TABLE ` + "`schedules`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			service_id VARCHAR(96) NOT NULL,
			name VARCHAR(96) NOT NULL,
			timezone VARCHAR(64) NOT NULL,
			version BIGINT UNSIGNED NOT NULL,
			definition BLOB NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL
		)`,
	},
	{
		name: "objectives",
		ddl: `CREATE TABLE ` + "`objectives`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			service_id VARCHAR(96) NOT NULL,
			name VARCHAR(160) NOT NULL,
			metric VARCHAR(32) NOT NULL,
			target_ppm BIGINT NOT NULL,
			window_kind VARCHAR(24) NOT NULL,
			latency_budget_ms INT NOT NULL,
			credits BLOB NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `obj_service` ON `objectives` (service_id)",
		},
	},
	{
		// One row per journey execution. The atom of the record: pruned
		// on a retention policy, folded into buckets before that, and
		// individually provable while it is here.
		name: "samples",
		ddl: `CREATE TABLE ` + "`samples`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			monitor_id VARCHAR(96) NOT NULL,
			monitor_version BIGINT UNSIGNED NOT NULL,
			component_id VARCHAR(96) NOT NULL,
			service_id VARCHAR(96) NOT NULL,
			vantage VARCHAR(64) NOT NULL,
			started_at BIGINT NOT NULL,
			duration_ms INT NOT NULL,
			verdict VARCHAR(16) NOT NULL,
			failed_step VARCHAR(96) NOT NULL,
			error_class VARCHAR(24) NOT NULL,
			detail VARCHAR(1024) NOT NULL,
			steps BLOB NOT NULL,
			manual BOOLEAN NOT NULL,
			in_maintenance BOOLEAN NOT NULL,
			pruned BOOLEAN NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `smp_monitor_time` ON `samples` (monitor_id, started_at)",
			"CREATE INDEX `smp_service_time` ON `samples` (service_id, started_at)",
			"CREATE INDEX `smp_verdict` ON `samples` (verdict, started_at)",
		},
	},
	{
		// Folded readings. The primary key is (monitor, width, start) so
		// a range scan over a period is a primary-key scan, and the
		// evidence a report bundles is a contiguous run of rows.
		name: "buckets",
		ddl: `CREATE TABLE ` + "`buckets`" + ` (
			monitor_id VARCHAR(96) NOT NULL,
			width_seconds BIGINT NOT NULL,
			bucket_start BIGINT NOT NULL,
			component_id VARCHAR(96) NOT NULL,
			service_id VARCHAR(96) NOT NULL,
			up_count INT NOT NULL,
			degraded_count INT NOT NULL,
			down_count INT NOT NULL,
			error_count INT NOT NULL,
			maint_count INT NOT NULL,
			latency_p50 INT NOT NULL,
			latency_p95 INT NOT NULL,
			latency_max INT NOT NULL,
			verdict VARCHAR(16) NOT NULL,
			PRIMARY KEY (monitor_id, width_seconds, bucket_start)
		)`,
		indexes: []string{
			"CREATE INDEX `bkt_service` ON `buckets` (service_id, width_seconds, bucket_start)",
			"CREATE INDEX `bkt_component` ON `buckets` (component_id, width_seconds, bucket_start)",
		},
	},
	{
		name: "incidents",
		ddl: `CREATE TABLE ` + "`incidents`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			service_id VARCHAR(96) NOT NULL,
			title VARCHAR(255) NOT NULL,
			impact VARCHAR(16) NOT NULL,
			status VARCHAR(24) NOT NULL,
			components VARCHAR(1024) NOT NULL,
			opened_at BIGINT NOT NULL,
			resolved_at BIGINT NOT NULL,
			auto BOOLEAN NOT NULL,
			trigger_samples VARCHAR(1024) NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `inc_service_time` ON `incidents` (service_id, opened_at)",
			"CREATE INDEX `inc_status` ON `incidents` (status, opened_at)",
		},
	},
	{
		name: "incident_updates",
		ddl: `CREATE TABLE ` + "`incident_updates`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			incident_id VARCHAR(96) NOT NULL,
			status VARCHAR(24) NOT NULL,
			body VARCHAR(4096) NOT NULL,
			author_sub VARCHAR(160) NOT NULL,
			author_display VARCHAR(160) NOT NULL,
			author_role VARCHAR(64) NOT NULL,
			created_at BIGINT NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `iu_incident` ON `incident_updates` (incident_id, created_at)",
		},
	},
	{
		// declared_at is not a decoration. The gap between it and
		// starts_at decides whether the window leaves agreed service
		// time, and a report states it either way.
		name: "maintenance_windows",
		ddl: `CREATE TABLE ` + "`maintenance_windows`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			service_id VARCHAR(96) NOT NULL,
			components VARCHAR(1024) NOT NULL,
			class VARCHAR(32) NOT NULL,
			title VARCHAR(255) NOT NULL,
			description VARCHAR(4096) NOT NULL,
			declared_at BIGINT NOT NULL,
			starts_at BIGINT NOT NULL,
			ends_at BIGINT NOT NULL,
			excluded BOOLEAN NOT NULL,
			lead_time BIGINT NOT NULL,
			published BOOLEAN NOT NULL,
			cancelled BOOLEAN NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `mw_service_time` ON `maintenance_windows` (service_id, starts_at)",
		},
	},
	{
		// Secret values never appear here. What is recorded is the name,
		// the host binding that stops the credential travelling anywhere
		// else, and a keyed fingerprint so an operator can confirm a
		// rotation changed something.
		name: "secrets_meta",
		ddl: `CREATE TABLE ` + "`secrets_meta`" + ` (
			name VARCHAR(96) PRIMARY KEY,
			hosts VARCHAR(1024) NOT NULL,
			description VARCHAR(512) NOT NULL,
			fingerprint CHAR(64) NOT NULL,
			created_at BIGINT NOT NULL,
			rotated_at BIGINT NOT NULL,
			destroyed_at BIGINT NOT NULL,
			used_at BIGINT NOT NULL
		)`,
	},
	{
		name: "alerts",
		ddl: `CREATE TABLE ` + "`alerts`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			service_id VARCHAR(96) NOT NULL,
			event_type VARCHAR(48) NOT NULL,
			subject VARCHAR(96) NOT NULL,
			dedup_key VARCHAR(160) NOT NULL,
			payload BLOB NOT NULL,
			created_at BIGINT NOT NULL,
			ledger_root CHAR(64) NOT NULL,
			ledger_version BIGINT UNSIGNED NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `alert_service_time` ON `alerts` (service_id, created_at)",
			"CREATE INDEX `alert_dedup` ON `alerts` (dedup_key)",
		},
	},
	{
		// Every attempt, not just the successful one. "You never told us"
		// is then a question with an answer.
		name: "alert_deliveries",
		ddl: `CREATE TABLE ` + "`alert_deliveries`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			alert_id VARCHAR(96) NOT NULL,
			attempt INT NOT NULL,
			url VARCHAR(512) NOT NULL,
			status INT NOT NULL,
			duration_ms INT NOT NULL,
			error VARCHAR(512) NOT NULL,
			delivered BOOLEAN NOT NULL,
			created_at BIGINT NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `del_alert` ON `alert_deliveries` (alert_id, attempt)",
		},
	},
	{
		// The report row commits to a hash over the exact evidence the
		// arithmetic used, so one inclusion proof covers the whole
		// document.
		name: "reports",
		ddl: `CREATE TABLE ` + "`reports`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			service_id VARCHAR(96) NOT NULL,
			period_from BIGINT NOT NULL,
			period_to BIGINT NOT NULL,
			label VARCHAR(96) NOT NULL,
			availability_ppm BIGINT NOT NULL,
			user_availability_ppm BIGINT NOT NULL,
			coverage_ppm BIGINT NOT NULL,
			downtime_seconds BIGINT NOT NULL,
			outages INT NOT NULL,
			evidence_hash CHAR(64) NOT NULL,
			evidence BLOB NOT NULL,
			document BLOB NOT NULL,
			generated_at BIGINT NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `rep_service_period` ON `reports` (service_id, period_from)",
		},
	},
	{
		// A gap in the record is otherwise indistinguishable from a quiet
		// period. A restart is written down.
		name: "runtime_events",
		ddl: `CREATE TABLE ` + "`runtime_events`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			kind VARCHAR(32) NOT NULL,
			at_time BIGINT NOT NULL,
			detail VARCHAR(1024) NOT NULL,
			image_digest VARCHAR(160) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `rt_kind_time` ON `runtime_events` (kind, at_time)",
		},
	},
	{
		name: "states",
		ddl: `CREATE TABLE ` + "`states`" + ` (
			subject VARCHAR(96) PRIMARY KEY,
			kind VARCHAR(16) NOT NULL,
			verdict VARCHAR(16) NOT NULL,
			raw VARCHAR(16) NOT NULL,
			since BIGINT NOT NULL,
			consecutive INT NOT NULL,
			flaps INT NOT NULL,
			flaps_since BIGINT NOT NULL,
			incident_id VARCHAR(96) NOT NULL,
			updated_at BIGINT NOT NULL
		)`,
	},
	{
		name: "prune_marks",
		ddl: `CREATE TABLE ` + "`prune_marks`" + ` (
			txid CHAR(64) NOT NULL,
			idx INT UNSIGNED NOT NULL,
			scope VARCHAR(32) NOT NULL,
			from_time BIGINT NOT NULL,
			to_time BIGINT NOT NULL,
			rows_removed BIGINT NOT NULL,
			policy VARCHAR(64) NOT NULL,
			created_at BIGINT NOT NULL,
			PRIMARY KEY (txid, idx)
		)`,
	},
	{
		name: "registry",
		ddl: `CREATE TABLE ` + "`registry`" + ` (
			k VARCHAR(96) PRIMARY KEY,
			v VARBINARY(8192) NOT NULL,
			updated_at BIGINT NOT NULL
		)`,
	},
}

type tableDDL struct {
	name    string
	ddl     string
	indexes []string
}

// Migrate creates any base table that does not exist yet. Creating a
// table is itself a ledger commit, so a fresh monitor's first
// transactions are the ones that bring its own catalogue into being.
func (s *Store) Migrate() error {
	return s.Do(func(tx *Tx) error {
		existing, err := tx.Tables()
		if err != nil {
			return err
		}
		for _, t := range baseTables {
			if existing[t.name] {
				continue
			}
			if err := tx.Exec(t.ddl); err != nil {
				return fmt.Errorf("store: create %s: %w", t.name, err)
			}
			for _, idx := range t.indexes {
				if err := tx.Exec(idx); err != nil {
					return fmt.Errorf("store: index on %s: %w", t.name, err)
				}
			}
		}
		return nil
	})
}

// VerifiedColumns names the columns of the tables an evidence bundle
// can be built over, in schema order. Rows come back from the SQL layer
// as positional values, and a bundle that mislabels them is a bundle
// nobody can check.
var VerifiedColumns = map[string][]string{
	"buckets": {"monitor_id", "width_seconds", "bucket_start", "component_id", "service_id",
		"up_count", "degraded_count", "down_count", "error_count", "maint_count",
		"latency_p50", "latency_p95", "latency_max", "verdict"},
	"samples": {"id", "monitor_id", "monitor_version", "component_id", "service_id",
		"vantage", "started_at", "duration_ms", "verdict", "failed_step",
		"error_class", "detail", "steps", "manual", "in_maintenance", "pruned"},
	"reports": {"id", "service_id", "period_from", "period_to", "label",
		"availability_ppm", "user_availability_ppm", "coverage_ppm",
		"downtime_seconds", "outages", "evidence_hash", "evidence", "document",
		"generated_at", "txid"},
	"maintenance_windows": {"id", "service_id", "components", "class", "title",
		"description", "declared_at", "starts_at", "ends_at", "excluded",
		"lead_time", "published", "cancelled", "txid"},
	"incidents": {"id", "service_id", "title", "impact", "status", "components",
		"opened_at", "resolved_at", "auto", "trigger_samples", "txid"},
}
