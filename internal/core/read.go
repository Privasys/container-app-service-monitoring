// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"fmt"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Reads. Everything here goes through the ledger's SQL layer, so a row
// served to a caller has been re-read and re-verified through the tree
// rather than served out of an index.

// Services lists the services this instance watches.
func (m *Monitor) Services() ([]model.Service, error) {
	var out []model.Service
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `services` ORDER BY name")
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, *serviceFromRow(row))
		}
		return nil
	})
	return out, err
}

// ServiceBySlug resolves the identifier a status-page URL carries.
func (m *Monitor) ServiceBySlug(slug string) (*model.Service, error) {
	var out *model.Service
	err := m.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT * FROM `services` WHERE slug = " + store.Lit(slug))
		if err != nil || row == nil {
			return err
		}
		out = serviceFromRow(row)
		return nil
	})
	return out, err
}

// Service reads one service.
func (m *Monitor) Service(id string) (*model.Service, error) {
	var out *model.Service
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = readService(tx, id)
		return err
	})
	return out, err
}

// Components lists a service's components in display order.
func (m *Monitor) Components(serviceID string) ([]model.Component, error) {
	var out []model.Component
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = listComponents(tx, serviceID)
		return err
	})
	return out, err
}

// Monitors lists a service's monitors.
func (m *Monitor) Monitors(serviceID string) ([]model.Monitor, error) {
	var out []model.Monitor
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = listMonitors(tx, serviceID)
		return err
	})
	return out, err
}

// Monitor reads one monitor definition.
func (m *Monitor) Monitor(id string) (*model.Monitor, error) {
	var out *model.Monitor
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = readMonitor(tx, id)
		return err
	})
	return out, err
}

// Objectives lists a service's objectives.
func (m *Monitor) Objectives(serviceID string) ([]model.Objective, error) {
	var out []model.Objective
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = listObjectives(tx, serviceID)
		return err
	})
	return out, err
}

// Schedule reads a service's agreed service time.
func (m *Monitor) Schedule(id string) (*model.Schedule, error) {
	var out *model.Schedule
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = readSchedule(tx, id)
		return err
	})
	return out, err
}

// Buckets reads folded intervals for a service over a range, at one
// width. The status page's uptime bars are hour buckets; a report's
// evidence is both widths.
func (m *Monitor) Buckets(serviceID string, width, from, to int64) ([]model.Bucket, error) {
	var out []model.Bucket
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `buckets` WHERE service_id = " + store.Lit(serviceID) +
			" AND width_seconds = " + store.Lit(width) +
			" AND bucket_start >= " + store.Lit(from) +
			" AND bucket_start < " + store.Lit(to) + " ORDER BY bucket_start")
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, bucketFromRow(row))
		}
		return nil
	})
	return out, err
}

// Samples lists readings, newest first.
func (m *Monitor) Samples(p *auth.Principal, monitorID string, from, to int64, limit int) ([]model.Sample, error) {
	if !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the readings", p.Acting)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []model.Sample
	err := m.st.Do(func(tx *store.Tx) error {
		where := "pruned = FALSE"
		if monitorID != "" {
			where += " AND monitor_id = " + store.Lit(monitorID)
		}
		if from > 0 {
			where += " AND started_at >= " + store.Lit(from)
		}
		if to > 0 {
			where += " AND started_at < " + store.Lit(to)
		}
		rows, err := tx.Query("SELECT * FROM `samples` WHERE " + where +
			" ORDER BY started_at DESC LIMIT " + store.Lit(int64(limit)))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, sampleFromRow(row))
		}
		return nil
	})
	return out, err
}

// Log returns the transaction log, newest first: who changed what, when
// and why, with the roots either side.
func (m *Monitor) Log(p *auth.Principal, kind string, limit int) ([]model.Transaction, error) {
	if !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the log", p.Acting)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		where := "1 = 1"
		if kind != "" {
			where = "kind = " + store.Lit(kind)
		}
		rows, err := tx.Query("SELECT * FROM `transactions` WHERE " + where +
			" ORDER BY seq DESC LIMIT " + store.Lit(int64(limit)))
		if err != nil {
			return err
		}
		for _, row := range rows {
			t, err := rowToTransaction(row)
			if err != nil {
				return err
			}
			out = append(out, *t)
		}
		return nil
	})
	return out, err
}

// Transaction reads one entry of the log in full.
func (m *Monitor) Transaction(p *auth.Principal, txid string) (*model.Transaction, error) {
	if !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the log", p.Acting)
	}
	var out *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		out, err = m.transactionByID(tx, txid)
		return err
	})
	return out, err
}

// Alerts lists what the monitor sent, with the delivery attempts.
func (m *Monitor) Alerts(p *auth.Principal, serviceID string, limit int) ([]AlertRecord, error) {
	if !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the alerts", p.Acting)
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []AlertRecord
	err := m.st.Do(func(tx *store.Tx) error {
		where := "1 = 1"
		if serviceID != "" {
			where = "service_id = " + store.Lit(serviceID)
		}
		rows, err := tx.Query("SELECT * FROM `alerts` WHERE " + where +
			" ORDER BY created_at DESC LIMIT " + store.Lit(int64(limit)))
		if err != nil {
			return err
		}
		for _, row := range rows {
			rec := AlertRecord{
				Alert: Alert{
					ID: row.Str("id"), ServiceID: row.Str("service_id"),
					Event: row.Str("event_type"), Subject: row.Str("subject"),
					DedupKey: row.Str("dedup_key"), CreatedAt: row.Int("created_at"),
					LedgerRoot: row.Str("ledger_root"), LedgerVersion: row.Uint("ledger_version"),
				},
			}
			if raw := row.Bytes("payload"); len(raw) > 0 {
				_ = jsonUnmarshal(raw, &rec.Alert.Payload)
			}
			deliveries, err := tx.Query("SELECT * FROM `alert_deliveries` WHERE alert_id = " +
				store.Lit(rec.Alert.ID) + " ORDER BY attempt")
			if err != nil {
				return err
			}
			for _, d := range deliveries {
				rec.Deliveries = append(rec.Deliveries, Delivery{
					Attempt: int(d.Int("attempt")), URL: d.Str("url"),
					Status: int(d.Int("status")), DurationMs: int(d.Int("duration_ms")),
					Error: d.Str("error"), Delivered: d.Bool("delivered"),
					CreatedAt: d.Int("created_at"),
				})
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, err
}

// AlertRecord is an alert with everything that happened to it.
type AlertRecord struct {
	Alert      Alert      `json:"alert"`
	Deliveries []Delivery `json:"deliveries,omitempty"`
}

// Delivery is one attempt to hand an alert to a callback.
type Delivery struct {
	Attempt    int    `json:"attempt"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	DurationMs int    `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	Delivered  bool   `json:"delivered"`
	CreatedAt  int64  `json:"created_at"`
}

// RuntimeEvents lists what happened to the monitor itself: the boots,
// the reconfigurations, the gaps. A monitor that was down cannot
// certify uptime, so its own history is part of the record.
func (m *Monitor) RuntimeEvents(limit int) ([]model.RuntimeEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []model.RuntimeEvent
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `runtime_events` ORDER BY at_time DESC LIMIT " +
			store.Lit(int64(limit)))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, model.RuntimeEvent{
				ID: row.Str("id"), Kind: row.Str("kind"), At: row.Int("at_time"),
				Detail: row.Str("detail"), ImageDigest: row.Str("image_digest"),
			})
		}
		return nil
	})
	return out, err
}

// -- shared row helpers ----------------------------------------------------

func listComponents(tx *store.Tx, serviceID string) ([]model.Component, error) {
	rows, err := tx.Query("SELECT * FROM `components` WHERE service_id = " + store.Lit(serviceID) +
		" ORDER BY sort_order, name")
	if err != nil {
		return nil, err
	}
	out := make([]model.Component, 0, len(rows))
	for _, row := range rows {
		out = append(out, *componentFromRow(row))
	}
	return out, nil
}

func listMonitors(tx *store.Tx, serviceID string) ([]model.Monitor, error) {
	where := "1 = 1"
	if serviceID != "" {
		where = "service_id = " + store.Lit(serviceID)
	}
	rows, err := tx.Query("SELECT * FROM `monitors` WHERE " + where + " ORDER BY name")
	if err != nil {
		return nil, err
	}
	out := make([]model.Monitor, 0, len(rows))
	for _, row := range rows {
		mon, err := monitorFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *mon)
	}
	return out, nil
}

func listObjectives(tx *store.Tx, serviceID string) ([]model.Objective, error) {
	rows, err := tx.Query("SELECT * FROM `objectives` WHERE service_id = " + store.Lit(serviceID) +
		" ORDER BY name")
	if err != nil {
		return nil, err
	}
	out := make([]model.Objective, 0, len(rows))
	for _, row := range rows {
		o, err := objectiveFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, *o)
	}
	return out, nil
}

func maintenanceBetween(tx *store.Tx, serviceID string, from, to int64) ([]model.MaintenanceWindow, error) {
	rows, err := tx.Query("SELECT * FROM `maintenance_windows` WHERE service_id = " + store.Lit(serviceID) +
		" AND cancelled = FALSE AND starts_at < " + store.Lit(to) +
		" AND ends_at > " + store.Lit(from) + " ORDER BY starts_at")
	if err != nil {
		return nil, err
	}
	out := make([]model.MaintenanceWindow, 0, len(rows))
	for _, row := range rows {
		out = append(out, *maintenanceFromRow(row))
	}
	return out, nil
}

func incidentsBetween(tx *store.Tx, serviceID string, from, to int64) ([]model.Incident, error) {
	rows, err := tx.Query("SELECT * FROM `incidents` WHERE service_id = " + store.Lit(serviceID) +
		" AND opened_at < " + store.Lit(to) +
		" AND (resolved_at = 0 OR resolved_at > " + store.Lit(from) + ")" +
		" ORDER BY opened_at")
	if err != nil {
		return nil, err
	}
	out := make([]model.Incident, 0, len(rows))
	for _, row := range rows {
		inc := incidentFromRow(row)
		inc.Updates, err = incidentUpdates(tx, inc.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, *inc)
	}
	return out, nil
}

func sampleFromRow(row store.Row) model.Sample {
	s := model.Sample{
		ID: row.Str("id"), MonitorID: row.Str("monitor_id"),
		MonitorVersion: row.Uint("monitor_version"), ComponentID: row.Str("component_id"),
		ServiceID: row.Str("service_id"), Vantage: row.Str("vantage"),
		StartedAt: row.Int("started_at"), DurationMs: int(row.Int("duration_ms")),
		Verdict: row.Str("verdict"), FailedStep: row.Str("failed_step"),
		ErrorClass: row.Str("error_class"), Detail: row.Str("detail"),
		Manual: row.Bool("manual"), InMaintenance: row.Bool("in_maintenance"),
	}
	if raw := row.Bytes("steps"); len(raw) > 0 {
		_ = jsonUnmarshal(raw, &s.Steps)
	}
	if raw := row.Bytes("captures"); len(raw) > 0 {
		_ = jsonUnmarshal(raw, &s.Captures)
	}
	return s
}
