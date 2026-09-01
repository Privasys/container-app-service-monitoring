// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Detection: turning readings into a state, and a state change into an
// incident and a notification.
//
// Three rules shape it, and all three exist because of how a monitor is
// wrong in practice rather than in theory.
//
// A single failure is not an outage. A monitor declares down after a
// declared number of consecutive failures and up again after a declared
// number of consecutive passes, so one dropped packet does not open an
// incident at three in the morning.
//
// An error is not downtime. A reading the monitor could not take does
// not advance either threshold: it neither declares the service down
// nor lets it look up. It is recorded, and it costs coverage.
//
// Maintenance suppresses notification, never observation. Readings
// continue and are recorded through a declared window, marked as taken
// inside it. Only the alerting and the arithmetic change.

// Alert is a notification the monitor decided to send.
type Alert struct {
	ID            string         `json:"id"`
	ServiceID     string         `json:"service_id"`
	Event         string         `json:"event"`
	Subject       string         `json:"subject"`
	DedupKey      string         `json:"dedup_key"`
	Payload       map[string]any `json:"payload"`
	CreatedAt     int64          `json:"created_at"`
	LedgerRoot    string         `json:"ledger_root"`
	LedgerVersion uint64         `json:"ledger_version"`
}

// Alert events.
const (
	EventComponentDown = "component.down"
	EventComponentUp   = "component.up"
	EventFlapping      = "component.flapping"
	EventIncidentOpen  = "incident.opened"
	EventIncidentClose = "incident.resolved"
	EventCheckpoint    = "checkpoint.issued"
	EventReport        = "report.issued"
)

// Flap damping. A component that changes state more often than this in
// the window is announced once as flapping and then left alone until it
// settles: the fifteenth alert about the same thing is not information.
const (
	flapWindow    = int64(3600)
	flapThreshold = 6
)

// detect updates the monitor and component states from a tick's
// readings and returns the alerts the changes call for, together with
// the write operations that record them.
func (m *Monitor) detect(tx *store.Tx, samples []model.Sample, now int64) ([]Alert, []model.WriteOp, error) {
	var ops []model.WriteOp
	var alerts []Alert

	// Group by monitor, keeping the last reading of each: a tick
	// normally carries one reading per monitor, and if a manual run
	// slipped in it does not move the state.
	latest := map[string]model.Sample{}
	for _, s := range samples {
		if s.Manual {
			continue
		}
		if prev, ok := latest[s.MonitorID]; !ok || s.StartedAt >= prev.StartedAt {
			latest[s.MonitorID] = s
		}
	}
	if len(latest) == 0 {
		return nil, nil, nil
	}

	monitorIDs := make([]string, 0, len(latest))
	for id := range latest {
		monitorIDs = append(monitorIDs, id)
	}
	sort.Strings(monitorIDs)

	touchedComponents := map[string]bool{}
	states := map[string]*model.State{}

	for _, id := range monitorIDs {
		s := latest[id]
		mon, err := readMonitor(tx, id)
		if err != nil {
			return nil, nil, err
		}
		if mon == nil {
			continue
		}
		st, err := readState(tx, id)
		if err != nil {
			return nil, nil, err
		}
		if st == nil {
			st = &model.State{Subject: id, Kind: model.StateMonitor, Verdict: model.VerdictUp, Since: now}
		}
		before := st.Verdict
		advanceMonitor(st, mon, s.Verdict, now)
		states[id] = st
		ops = append(ops, stateOp(st))
		if st.Verdict != before {
			touchedComponents[s.ComponentID] = true
		}
		// A component whose state is unknown is evaluated anyway on the
		// first reading after a restart, so a service that came back
		// while the monitor was down is noticed.
		if before == "" {
			touchedComponents[s.ComponentID] = true
		}
	}

	componentIDs := make([]string, 0, len(touchedComponents))
	for id := range touchedComponents {
		componentIDs = append(componentIDs, id)
	}
	sort.Strings(componentIDs)

	for _, componentID := range componentIDs {
		componentAlerts, componentOps, err := m.rollUpComponent(tx, componentID, states, latest, now)
		if err != nil {
			return nil, nil, err
		}
		ops = append(ops, componentOps...)
		alerts = append(alerts, componentAlerts...)
	}
	return alerts, ops, nil
}

// advanceMonitor applies one reading to a monitor's state.
func advanceMonitor(st *model.State, mon *model.Monitor, verdict string, now int64) {
	st.UpdatedAt = now
	if verdict == model.VerdictError {
		// Not a reading of the service. It moves no threshold in either
		// direction, and the run of whatever came before is left intact
		// rather than reset, so an intermittent configuration problem
		// cannot mask a real recovery or a real failure.
		st.Raw = model.VerdictError
		return
	}
	if st.Raw == verdict {
		st.Consecutive++
	} else {
		st.Raw = verdict
		st.Consecutive = 1
	}
	switch {
	case st.Verdict != model.VerdictDown && verdict == model.VerdictDown:
		if st.Consecutive >= mon.FailureThreshold {
			st.Verdict = model.VerdictDown
			st.Since = now
		}
	case st.Verdict == model.VerdictDown && verdict != model.VerdictDown:
		if st.Consecutive >= mon.RecoveryThreshold {
			st.Verdict = verdict
			st.Since = now
		}
	default:
		if st.Verdict != verdict {
			st.Verdict = verdict
			st.Since = now
		}
	}
}

// rollUpComponent recomputes a component's state from its monitors and
// decides what that change means.
func (m *Monitor) rollUpComponent(tx *store.Tx, componentID string, updated map[string]*model.State,
	samples map[string]model.Sample, now int64) ([]Alert, []model.WriteOp, error) {

	component, err := readComponent(tx, componentID)
	if err != nil || component == nil {
		return nil, nil, err
	}
	rows, err := tx.Query("SELECT id FROM `monitors` WHERE component_id = " + store.Lit(componentID) +
		" AND enabled = TRUE")
	if err != nil {
		return nil, nil, err
	}

	seen, down := 0, 0
	worst := model.VerdictUp
	for _, row := range rows {
		id := row.Str("id")
		st, ok := updated[id]
		if !ok {
			st, err = readState(tx, id)
			if err != nil {
				return nil, nil, err
			}
			if st == nil {
				continue
			}
		}
		if st.Verdict == "" || st.Raw == model.VerdictError && st.Verdict == model.VerdictUp && st.Since == 0 {
			continue
		}
		seen++
		if st.Verdict == model.VerdictDown {
			down++
		}
		worst = model.WorseVerdict(worst, st.Verdict)
	}
	if seen == 0 {
		return nil, nil, nil
	}

	verdict := model.VerdictUp
	switch component.Rollup {
	case model.RollupAll:
		if down == seen {
			verdict = model.VerdictDown
		} else {
			verdict = worst
			if verdict == model.VerdictDown {
				verdict = model.VerdictDegraded
			}
		}
	case model.RollupMajority:
		if down*2 > seen {
			verdict = model.VerdictDown
		} else {
			verdict = worst
			if verdict == model.VerdictDown {
				verdict = model.VerdictDegraded
			}
		}
	default:
		verdict = worst
	}

	st, err := readState(tx, componentID)
	if err != nil {
		return nil, nil, err
	}
	if st == nil {
		st = &model.State{Subject: componentID, Kind: model.StateComponent, Verdict: model.VerdictUp, Since: now}
	}
	if st.Verdict == verdict {
		return nil, nil, nil
	}

	previous := st.Verdict
	st.Verdict = verdict
	st.Since = now
	st.UpdatedAt = now
	st.Kind = model.StateComponent
	if now-st.FlapsSince > flapWindow {
		st.Flaps = 1
		st.FlapsSince = now
	} else {
		st.Flaps++
	}

	ops := []model.WriteOp{}
	var alerts []Alert

	// Was this change observed inside a declared maintenance window? If
	// so the state still moves and is still recorded; only the
	// notification is held back.
	inMaintenance := false
	for _, s := range samples {
		if s.ComponentID == componentID && s.InMaintenance {
			inMaintenance = true
		}
	}
	flapping := st.Flaps > flapThreshold

	switch {
	case verdict == model.VerdictDown:
		incidentID, incidentOps, err := m.openAutoIncident(tx, component, samples, now)
		if err != nil {
			return nil, nil, err
		}
		ops = append(ops, incidentOps...)
		st.IncidentID = incidentID
		if !inMaintenance && !flapping {
			alert, alertOps, err := m.raise(tx, component.ServiceID, EventComponentDown, componentID,
				fmt.Sprintf("%s:%s:%d", componentID, model.VerdictDown, now),
				map[string]any{
					"component": component.Name, "component_id": componentID,
					"previous": previous, "current": verdict,
					"incident_id": incidentID,
					"detail":      detailOf(samples, componentID),
					"since":       now,
				}, now)
			if err != nil {
				return nil, nil, err
			}
			ops = append(ops, alertOps...)
			alerts = append(alerts, alert)
		}

	case previous == model.VerdictDown:
		if st.IncidentID != "" {
			resolveOps, err := m.resolveAutoIncident(tx, st.IncidentID, now)
			if err != nil {
				return nil, nil, err
			}
			ops = append(ops, resolveOps...)
		}
		if !inMaintenance && !flapping {
			alert, alertOps, err := m.raise(tx, component.ServiceID, EventComponentUp, componentID,
				fmt.Sprintf("%s:%s:%d", componentID, model.VerdictUp, now),
				map[string]any{
					"component": component.Name, "component_id": componentID,
					"previous": previous, "current": verdict,
					"incident_id": st.IncidentID, "since": now,
				}, now)
			if err != nil {
				return nil, nil, err
			}
			ops = append(ops, alertOps...)
			alerts = append(alerts, alert)
		}
		st.IncidentID = ""
	}

	if flapping && st.Flaps == flapThreshold+1 && !inMaintenance {
		alert, alertOps, err := m.raise(tx, component.ServiceID, EventFlapping, componentID,
			fmt.Sprintf("%s:flapping:%d", componentID, st.FlapsSince),
			map[string]any{
				"component": component.Name, "component_id": componentID,
				"changes": st.Flaps, "window_seconds": flapWindow,
			}, now)
		if err != nil {
			return nil, nil, err
		}
		ops = append(ops, alertOps...)
		alerts = append(alerts, alert)
	}

	ops = append(ops, stateOp(st))
	return alerts, ops, nil
}

func detailOf(samples map[string]model.Sample, componentID string) string {
	for _, s := range samples {
		if s.ComponentID == componentID && s.Detail != "" {
			return s.Detail
		}
	}
	return ""
}

// raise records an alert. Recording it is part of the same transaction
// as the change that caused it, so the alert's ledger coordinates are
// exact and a consumer can ask for the readings behind it.
func (m *Monitor) raise(tx *store.Tx, serviceID, event, subject, dedup string,
	payload map[string]any, now int64) (Alert, []model.WriteOp, error) {

	id, err := NewID("alt")
	if err != nil {
		return Alert{}, nil, err
	}
	a := Alert{
		ID: id, ServiceID: serviceID, Event: event, Subject: subject,
		DedupKey: dedup, Payload: payload, CreatedAt: now,
	}
	body, err := jsonBytes(payload)
	if err != nil {
		return Alert{}, nil, err
	}
	root, version := tx.Root()
	return a, []model.WriteOp{{
		Table: "alerts", Key: map[string]any{"id": id},
		Values: map[string]any{
			"service_id": serviceID, "event_type": event, "subject": subject,
			"dedup_key": dedup, "payload": body, "created_at": now,
			"ledger_root": root, "ledger_version": version,
		},
	}}, nil
}

// -- states ----------------------------------------------------------------

func readState(tx *store.Tx, subject string) (*model.State, error) {
	row, err := tx.QueryOne("SELECT * FROM `states` WHERE subject = " + store.Lit(subject))
	if err != nil || row == nil {
		return nil, err
	}
	return &model.State{
		Subject: row.Str("subject"), Kind: row.Str("kind"), Verdict: row.Str("verdict"),
		Raw: row.Str("raw"), Since: row.Int("since"), Consecutive: int(row.Int("consecutive")),
		Flaps: int(row.Int("flaps")), FlapsSince: row.Int("flaps_since"),
		IncidentID: row.Str("incident_id"), UpdatedAt: row.Int("updated_at"),
	}, nil
}

func stateOp(st *model.State) model.WriteOp {
	return model.WriteOp{
		Table: "states", Key: map[string]any{"subject": st.Subject},
		Values: map[string]any{
			"kind": st.Kind, "verdict": st.Verdict, "raw": st.Raw, "since": st.Since,
			"consecutive": st.Consecutive, "flaps": st.Flaps, "flaps_since": st.FlapsSince,
			"incident_id": st.IncidentID, "updated_at": st.UpdatedAt,
		},
	}
}

// States returns the current state of every subject, for the status
// page and the health document.
func (m *Monitor) States() (map[string]model.State, error) {
	out := map[string]model.State{}
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `states`")
		if err != nil {
			return err
		}
		for _, row := range rows {
			out[row.Str("subject")] = model.State{
				Subject: row.Str("subject"), Kind: row.Str("kind"), Verdict: row.Str("verdict"),
				Raw: row.Str("raw"), Since: row.Int("since"), Consecutive: int(row.Int("consecutive")),
				Flaps: int(row.Int("flaps")), FlapsSince: row.Int("flaps_since"),
				IncidentID: row.Str("incident_id"), UpdatedAt: row.Int("updated_at"),
			}
		}
		return nil
	})
	return out, err
}

// openAutoIncident opens an incident the monitor decided on itself.
func (m *Monitor) openAutoIncident(tx *store.Tx, c *model.Component,
	samples map[string]model.Sample, now int64) (string, []model.WriteOp, error) {

	// An incident already open on this component is not reopened: the
	// timeline of one interruption is one timeline.
	row, err := tx.QueryOne("SELECT id FROM `incidents` WHERE service_id = " + store.Lit(c.ServiceID) +
		" AND status <> " + store.Lit(model.IncidentResolved) +
		" AND components LIKE " + store.Lit("%"+c.ID+"%") + " ORDER BY opened_at DESC LIMIT 1")
	if err != nil {
		return "", nil, err
	}
	if row != nil {
		return row.Str("id"), nil, nil
	}

	id, err := NewID("inc")
	if err != nil {
		return "", nil, err
	}
	updateID, err := NewID("iup")
	if err != nil {
		return "", nil, err
	}
	var triggers []string
	detail := ""
	for _, s := range samples {
		if s.ComponentID == c.ID {
			triggers = append(triggers, s.ID)
			if detail == "" {
				detail = s.Detail
			}
		}
	}
	sort.Strings(triggers)

	title := c.Name + " is not responding"
	body := "The monitor watching " + c.Name + " has failed its threshold of consecutive checks."
	if detail != "" {
		body += " The last failure was: " + detail
	}

	return id, []model.WriteOp{
		{
			Table: "incidents", Key: map[string]any{"id": id},
			Values: map[string]any{
				"service_id": c.ServiceID, "title": clip(title, 255), "impact": model.ImpactMajor,
				"status": model.IncidentInvestigating, "components": c.ID,
				"opened_at": now, "resolved_at": int64(0), "auto": true,
				"trigger_samples": clip(csv(triggers), 1024), "txid": model.TxIDPlaceholder,
			},
		},
		{
			Table: "incident_updates", Key: map[string]any{"id": updateID},
			Values: map[string]any{
				"incident_id": id, "status": model.IncidentInvestigating,
				"body": clip(body, 4096), "author_sub": "system", "author_display": "Monitor",
				"author_role": "system", "created_at": now, "txid": model.TxIDPlaceholder,
			},
		},
	}, nil
}

// resolveAutoIncident closes an incident the monitor opened, once the
// readings say the component is back. An incident a human opened is
// left alone: the monitor knows the component answers again, which is
// not the same as knowing the incident is over.
func (m *Monitor) resolveAutoIncident(tx *store.Tx, incidentID string, now int64) ([]model.WriteOp, error) {
	row, err := tx.QueryOne("SELECT * FROM `incidents` WHERE id = " + store.Lit(incidentID))
	if err != nil || row == nil {
		return nil, err
	}
	if !row.Bool("auto") || row.Str("status") == model.IncidentResolved {
		return nil, nil
	}
	updateID, err := NewID("iup")
	if err != nil {
		return nil, err
	}
	return []model.WriteOp{
		{
			Table: "incidents", Key: map[string]any{"id": incidentID},
			Values: map[string]any{"status": model.IncidentResolved, "resolved_at": now},
		},
		{
			Table: "incident_updates", Key: map[string]any{"id": updateID},
			Values: map[string]any{
				"incident_id": incidentID, "status": model.IncidentResolved,
				"body":       "The monitor's checks are passing again.",
				"author_sub": "system", "author_display": "Monitor", "author_role": "system",
				"created_at": now, "txid": model.TxIDPlaceholder,
			},
		},
	}, nil
}

// RecordDelivery writes the outcome of one attempt to deliver an alert.
//
// Every attempt is recorded, not only the one that worked. "You never
// told us" then has an answer, and so does "you told us six hours
// late".
func (m *Monitor) RecordDelivery(alertID, url string, attempt, status, durationMs int, deliverErr string, delivered bool) error {
	id, err := NewID("dlv")
	if err != nil {
		return err
	}
	now := m.Now()
	return m.st.Do(func(tx *store.Tx) error {
		outcome := "failed"
		if delivered {
			outcome = "accepted"
		}
		_, err := m.commit(tx, model.Envelope{
			Kind: model.KindAlertDeliver, ObjectIDs: []string{alertID},
			Author: model.SystemAuthor(), Timestamp: now,
			Message: fmt.Sprintf("Delivery attempt %d %s", attempt, outcome),
		}, []model.WriteOp{{
			Table: "alert_deliveries", Key: map[string]any{"id": id},
			Values: map[string]any{
				"alert_id": alertID, "attempt": attempt, "url": clip(url, 512),
				"status": status, "duration_ms": durationMs,
				"error":     clip(strings.TrimSpace(deliverErr), 512),
				"delivered": delivered, "created_at": now,
			},
		}})
		return err
	})
}
