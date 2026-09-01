// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// The service model: services, components, monitors, schedules and
// objectives. All five are ordinary ledger state written through
// transactions, so "who changed the monitor, when, and why" is answered
// by the same log that answers "when was the service down".

// NewID mints an identifier with a readable prefix.
func NewID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}

// Slug renders a name as a URL-safe identifier for the status page.
func Slug(name string) string {
	var b strings.Builder
	lastDash := true
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// UpsertService creates or amends a service.
func (m *Monitor) UpsertService(p *auth.Principal, s model.Service, message string) (*model.Service, *model.Transaction, error) {
	if !p.Can(auth.PermModel) {
		return nil, nil, fmt.Errorf("%s may not change the service model", p.Acting)
	}
	if strings.TrimSpace(s.Name) == "" {
		return nil, nil, fmt.Errorf("a service needs a name")
	}
	if s.Timezone == "" {
		s.Timezone = "UTC"
	}
	if s.Visibility == "" {
		s.Visibility = model.VisibilityPublic
	}
	if s.MaintenanceLeadTime <= 0 {
		s.MaintenanceLeadTime = m.Config().MaintenanceLeadTime
	}
	if s.CoverageFloorPPM <= 0 {
		s.CoverageFloorPPM = DefaultCoverageFloorPPM
	}
	now := m.Now()
	s.Tenant = m.opts.Tenant
	s.UpdatedAt = now
	if s.Slug == "" {
		s.Slug = Slug(s.Name)
	}

	var out *model.Service
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		existing, err := readService(tx, s.ID)
		if err != nil {
			return err
		}
		kind := model.KindServiceUpsert
		if existing == nil {
			if s.ID == "" {
				if s.ID, err = NewID("svc"); err != nil {
					return err
				}
			}
			s.CreatedAt = now
		} else {
			s.CreatedAt = existing.CreatedAt
			if s.ScheduleID == "" {
				s.ScheduleID = existing.ScheduleID
			}
		}

		ops := []model.WriteOp{serviceOp(s)}

		// A service with no agreed service time cannot be measured, so a
		// new one gets 24x7 until somebody says otherwise. Writing it
		// down as a schedule rather than assuming it is the point: the
		// denominator of the availability formula is a decision, and a
		// decision belongs in the record.
		if s.ScheduleID == "" {
			id, err := NewID("sch")
			if err != nil {
				return err
			}
			sched := model.AlwaysOn(id, s.ID, s.Timezone, now)
			op, err := scheduleOp(sched)
			if err != nil {
				return err
			}
			ops = append(ops, op)
			s.ScheduleID = id
			ops[0] = serviceOp(s)
		}

		tr, err = m.commit(tx, model.Envelope{
			Kind: kind, Service: s.ID, ObjectIDs: []string{s.ID},
			Author: p.Author(), Timestamp: now, Message: message,
		}, ops)
		if err != nil {
			return err
		}
		out = &s
		return nil
	})
	return out, tr, err
}

func serviceOp(s model.Service) model.WriteOp {
	return model.WriteOp{
		Table: "services", Key: map[string]any{"id": s.ID},
		Values: map[string]any{
			"tenant": s.Tenant, "name": s.Name, "slug": s.Slug,
			"description": s.Description, "timezone": s.Timezone,
			"schedule_id": s.ScheduleID, "visibility": s.Visibility,
			"maintenance_lead_time": s.MaintenanceLeadTime,
			"coverage_floor_ppm":    s.CoverageFloorPPM,
			"callback_url":          s.CallbackURL,
			"created_at":            s.CreatedAt, "updated_at": s.UpdatedAt,
		},
	}
}

// UpsertComponent creates or amends a component.
func (m *Monitor) UpsertComponent(p *auth.Principal, c model.Component, message string) (*model.Component, *model.Transaction, error) {
	if !p.Can(auth.PermModel) {
		return nil, nil, fmt.Errorf("%s may not change the service model", p.Acting)
	}
	if c.ServiceID == "" || strings.TrimSpace(c.Name) == "" {
		return nil, nil, fmt.Errorf("a component needs a service and a name")
	}
	if c.Rollup == "" {
		c.Rollup = model.RollupAny
	}
	now := m.Now()
	c.UpdatedAt = now

	var out *model.Component
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		existing, err := readComponent(tx, c.ID)
		if err != nil {
			return err
		}
		if existing == nil {
			if c.ID == "" {
				if c.ID, err = NewID("cmp"); err != nil {
					return err
				}
			}
			c.CreatedAt = now
		} else {
			c.CreatedAt = existing.CreatedAt
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindComponentUpsert, Service: c.ServiceID, ObjectIDs: []string{c.ID},
			Author: p.Author(), Timestamp: now, Message: message,
		}, []model.WriteOp{{
			Table: "components", Key: map[string]any{"id": c.ID},
			Values: map[string]any{
				"service_id": c.ServiceID, "parent_id": c.ParentID, "name": c.Name,
				"description": c.Description, "user_weight": c.UserWeight,
				"rollup": c.Rollup, "sort_order": c.Position, "showcase": c.Showcase,
				"created_at": c.CreatedAt, "updated_at": c.UpdatedAt,
			},
		}})
		if err != nil {
			return err
		}
		out = &c
		return nil
	})
	return out, tr, err
}

// UpsertMonitor creates a monitor or publishes a new version of one.
//
// A monitor is never edited in place. Editing appends a version and
// leaves the old definition readable, so a report can name what was
// being measured at the time rather than what is being measured now.
// The version is also what a reading records, which is what makes the
// two match up months later.
func (m *Monitor) UpsertMonitor(p *auth.Principal, mon model.Monitor, message string) (*model.Monitor, *model.Transaction, error) {
	if !p.Can(auth.PermModel) {
		return nil, nil, fmt.Errorf("%s may not change the service model", p.Acting)
	}
	if mon.IntervalSeconds == 0 {
		mon.IntervalSeconds = model.DefaultInterval
	}
	if mon.TimeoutSeconds == 0 {
		mon.TimeoutSeconds = min(model.DefaultTimeout, mon.IntervalSeconds)
	}
	if mon.FailureThreshold == 0 {
		mon.FailureThreshold = 2
	}
	if mon.RecoveryThreshold == 0 {
		mon.RecoveryThreshold = 2
	}
	if err := mon.Validate(); err != nil {
		return nil, nil, err
	}
	now := m.Now()
	mon.UpdatedAt = now

	var out *model.Monitor
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		component, err := readComponent(tx, mon.ComponentID)
		if err != nil {
			return err
		}
		if component == nil {
			return fmt.Errorf("no component %s", mon.ComponentID)
		}
		mon.ServiceID = component.ServiceID

		existing, err := readMonitor(tx, mon.ID)
		if err != nil {
			return err
		}
		if existing == nil {
			if mon.ID == "" {
				if mon.ID, err = NewID("mon"); err != nil {
					return err
				}
			}
			mon.Version = 1
			mon.CreatedAt = now
			mon.Enabled = true
		} else {
			mon.Version = existing.Version + 1
			mon.CreatedAt = existing.CreatedAt
		}

		steps, err := jsonBytes(mon.Steps)
		if err != nil {
			return err
		}
		definition, err := jsonBytes(mon)
		if err != nil {
			return err
		}
		ops := []model.WriteOp{
			{
				Table: "monitors", Key: map[string]any{"id": mon.ID},
				Values: map[string]any{
					"service_id": mon.ServiceID, "component_id": mon.ComponentID,
					"name": mon.Name, "version": mon.Version, "enabled": mon.Enabled,
					"interval_seconds": mon.IntervalSeconds, "timeout_seconds": mon.TimeoutSeconds,
					"failure_threshold": mon.FailureThreshold, "recovery_threshold": mon.RecoveryThreshold,
					"latency_budget_ms": mon.LatencyBudgetMs, "steps": steps, "retired": false,
					"created_at": mon.CreatedAt, "updated_at": mon.UpdatedAt,
				},
			},
			{
				Table: "monitor_versions",
				Key:   map[string]any{"monitor_id": mon.ID, "version": mon.Version},
				Values: map[string]any{
					"txid": model.TxIDPlaceholder, "definition": definition, "created_at": now,
				},
			},
		}

		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindMonitorUpsert, Service: mon.ServiceID, ObjectIDs: []string{mon.ID},
			Author: p.Author(), Timestamp: now, Message: message,
		}, ops)
		if err != nil {
			return err
		}
		out = &mon
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	m.refreshEgress()
	return out, tr, nil
}

// SetMonitorEnabled turns a monitor on or off. Disabling is a signed
// transaction like any other: switching off the check that would have
// caught an outage is exactly the kind of act a record exists for.
func (m *Monitor) SetMonitorEnabled(p *auth.Principal, id string, enabled bool, message string) (*model.Transaction, error) {
	if !p.Can(auth.PermModel) {
		return nil, fmt.Errorf("%s may not change the service model", p.Acting)
	}
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		mon, err := readMonitor(tx, id)
		if err != nil {
			return err
		}
		if mon == nil {
			return fmt.Errorf("no monitor %s", id)
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindMonitorRetire, Service: mon.ServiceID, ObjectIDs: []string{id},
			Author: p.Author(), Timestamp: m.Now(), Message: message,
		}, []model.WriteOp{{
			Table: "monitors", Key: map[string]any{"id": id},
			Values: map[string]any{"enabled": enabled, "updated_at": m.Now()},
		}})
		return err
	})
	return tr, err
}

// UpsertSchedule replaces a service's agreed service time definition.
func (m *Monitor) UpsertSchedule(p *auth.Principal, s model.Schedule, message string) (*model.Schedule, *model.Transaction, error) {
	if !p.Can(auth.PermModel) {
		return nil, nil, fmt.Errorf("%s may not change the service model", p.Acting)
	}
	if s.ServiceID == "" {
		return nil, nil, fmt.Errorf("a schedule belongs to a service")
	}
	if s.Timezone == "" {
		s.Timezone = "UTC"
	}
	now := m.Now()
	s.UpdatedAt = now

	var out *model.Schedule
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		existing, err := readSchedule(tx, s.ID)
		if err != nil {
			return err
		}
		if existing == nil {
			if s.ID == "" {
				if s.ID, err = NewID("sch"); err != nil {
					return err
				}
			}
			s.Version = 1
			s.CreatedAt = now
		} else {
			s.Version = existing.Version + 1
			s.CreatedAt = existing.CreatedAt
		}
		op, err := scheduleOp(s)
		if err != nil {
			return err
		}
		ops := []model.WriteOp{op}
		svc, err := readService(tx, s.ServiceID)
		if err != nil {
			return err
		}
		if svc != nil && svc.ScheduleID != s.ID {
			svc.ScheduleID = s.ID
			svc.UpdatedAt = now
			ops = append(ops, serviceOp(*svc))
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindScheduleUpsert, Service: s.ServiceID, ObjectIDs: []string{s.ID},
			Author: p.Author(), Timestamp: now, Message: message,
		}, ops)
		if err != nil {
			return err
		}
		out = &s
		return nil
	})
	return out, tr, err
}

func scheduleOp(s model.Schedule) (model.WriteOp, error) {
	definition, err := jsonBytes(s)
	if err != nil {
		return model.WriteOp{}, err
	}
	return model.WriteOp{
		Table: "schedules", Key: map[string]any{"id": s.ID},
		Values: map[string]any{
			"service_id": s.ServiceID, "name": s.Name, "timezone": s.Timezone,
			"version": s.Version, "definition": definition,
			"created_at": s.CreatedAt, "updated_at": s.UpdatedAt,
		},
	}, nil
}

// UpsertObjective creates or amends a service-level objective.
func (m *Monitor) UpsertObjective(p *auth.Principal, o model.Objective, message string) (*model.Objective, *model.Transaction, error) {
	if !p.Can(auth.PermModel) {
		return nil, nil, fmt.Errorf("%s may not change the service model", p.Acting)
	}
	if o.ServiceID == "" || o.Metric == "" || o.Window == "" {
		return nil, nil, fmt.Errorf("an objective needs a service, a metric and a window")
	}
	if o.TargetPPM <= 0 || o.TargetPPM > 1_000_000 {
		return nil, nil, fmt.Errorf("a target is between 1 and 1000000 parts per million")
	}
	now := m.Now()
	o.UpdatedAt = now

	var out *model.Objective
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		existing, err := readObjective(tx, o.ID)
		if err != nil {
			return err
		}
		if existing == nil {
			if o.ID == "" {
				if o.ID, err = NewID("slo"); err != nil {
					return err
				}
			}
			o.CreatedAt = now
		} else {
			o.CreatedAt = existing.CreatedAt
		}
		credits, err := jsonBytes(o.Credits)
		if err != nil {
			return err
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindObjectiveUpsert, Service: o.ServiceID, ObjectIDs: []string{o.ID},
			Author: p.Author(), Timestamp: now, Message: message,
		}, []model.WriteOp{{
			Table: "objectives", Key: map[string]any{"id": o.ID},
			Values: map[string]any{
				"service_id": o.ServiceID, "name": o.Name, "metric": o.Metric,
				"target_ppm": o.TargetPPM, "window_kind": o.Window,
				"latency_budget_ms": o.LatencyBudgetMs, "credits": credits,
				"created_at": o.CreatedAt, "updated_at": o.UpdatedAt,
			},
		}})
		if err != nil {
			return err
		}
		out = &o
		return nil
	})
	return out, tr, err
}

// -- reads -----------------------------------------------------------------

func readService(tx *store.Tx, id string) (*model.Service, error) {
	if id == "" {
		return nil, nil
	}
	row, err := tx.QueryOne("SELECT * FROM `services` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return nil, err
	}
	return serviceFromRow(row), nil
}

func serviceFromRow(row store.Row) *model.Service {
	return &model.Service{
		ID: row.Str("id"), Tenant: row.Str("tenant"), Name: row.Str("name"),
		Slug: row.Str("slug"), Description: row.Str("description"),
		Timezone: row.Str("timezone"), ScheduleID: row.Str("schedule_id"),
		Visibility:          row.Str("visibility"),
		MaintenanceLeadTime: row.Int("maintenance_lead_time"),
		CoverageFloorPPM:    row.Int("coverage_floor_ppm"),
		CallbackURL:         row.Str("callback_url"),
		CreatedAt:           row.Int("created_at"), UpdatedAt: row.Int("updated_at"),
	}
}

func readComponent(tx *store.Tx, id string) (*model.Component, error) {
	if id == "" {
		return nil, nil
	}
	row, err := tx.QueryOne("SELECT * FROM `components` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return nil, err
	}
	return componentFromRow(row), nil
}

func componentFromRow(row store.Row) *model.Component {
	return &model.Component{
		ID: row.Str("id"), ServiceID: row.Str("service_id"), ParentID: row.Str("parent_id"),
		Name: row.Str("name"), Description: row.Str("description"),
		UserWeight: row.Int("user_weight"), Rollup: row.Str("rollup"),
		Position: row.Int("sort_order"), Showcase: row.Bool("showcase"),
		CreatedAt: row.Int("created_at"), UpdatedAt: row.Int("updated_at"),
	}
}

func readMonitor(tx *store.Tx, id string) (*model.Monitor, error) {
	if id == "" {
		return nil, nil
	}
	row, err := tx.QueryOne("SELECT * FROM `monitors` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return nil, err
	}
	return monitorFromRow(row)
}

func monitorFromRow(row store.Row) (*model.Monitor, error) {
	mon := &model.Monitor{
		ID: row.Str("id"), ServiceID: row.Str("service_id"), ComponentID: row.Str("component_id"),
		Name: row.Str("name"), Version: row.Uint("version"), Enabled: row.Bool("enabled"),
		IntervalSeconds: int(row.Int("interval_seconds")), TimeoutSeconds: int(row.Int("timeout_seconds")),
		FailureThreshold: int(row.Int("failure_threshold")), RecoveryThreshold: int(row.Int("recovery_threshold")),
		LatencyBudgetMs: int(row.Int("latency_budget_ms")),
		CreatedAt:       row.Int("created_at"), UpdatedAt: row.Int("updated_at"),
	}
	if raw := row.Bytes("steps"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &mon.Steps); err != nil {
			return nil, fmt.Errorf("core: monitor %s steps: %w", mon.ID, err)
		}
	}
	return mon, nil
}

func readSchedule(tx *store.Tx, id string) (*model.Schedule, error) {
	if id == "" {
		return nil, nil
	}
	row, err := tx.QueryOne("SELECT * FROM `schedules` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return nil, err
	}
	var s model.Schedule
	if raw := row.Bytes("definition"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("core: schedule %s: %w", id, err)
		}
	}
	s.ID = row.Str("id")
	s.ServiceID = row.Str("service_id")
	s.Version = row.Uint("version")
	return &s, nil
}

func readObjective(tx *store.Tx, id string) (*model.Objective, error) {
	if id == "" {
		return nil, nil
	}
	row, err := tx.QueryOne("SELECT * FROM `objectives` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return nil, err
	}
	return objectiveFromRow(row)
}

func objectiveFromRow(row store.Row) (*model.Objective, error) {
	o := &model.Objective{
		ID: row.Str("id"), ServiceID: row.Str("service_id"), Name: row.Str("name"),
		Metric: row.Str("metric"), TargetPPM: row.Int("target_ppm"),
		Window: row.Str("window_kind"), LatencyBudgetMs: int(row.Int("latency_budget_ms")),
		CreatedAt: row.Int("created_at"), UpdatedAt: row.Int("updated_at"),
	}
	if raw := row.Bytes("credits"); len(raw) > 0 {
		if err := json.Unmarshal(raw, &o.Credits); err != nil {
			return nil, fmt.Errorf("core: objective %s credits: %w", o.ID, err)
		}
	}
	return o, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
