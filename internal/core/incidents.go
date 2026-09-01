// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"fmt"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Incidents are the narrative beside the readings.
//
// The readings say what happened; the incident says what was understood
// about it and when. Both are transactions, so the timeline a customer
// reads on the status page is the same object the report cites, and an
// update cannot be quietly edited afterwards to say something better.

// OpenIncident opens an incident a person decided on.
func (m *Monitor) OpenIncident(p *auth.Principal, inc model.Incident, body, message string) (*model.Incident, *model.Transaction, error) {
	if !p.Can(auth.PermRespond) {
		return nil, nil, fmt.Errorf("%s may not open incidents", p.Acting)
	}
	if inc.ServiceID == "" || strings.TrimSpace(inc.Title) == "" {
		return nil, nil, fmt.Errorf("an incident needs a service and a title")
	}
	if strings.TrimSpace(body) == "" {
		return nil, nil, fmt.Errorf("an incident needs a first update saying what is known")
	}
	if inc.Impact == "" {
		inc.Impact = model.ImpactMinor
	}
	if inc.Status == "" {
		inc.Status = model.IncidentInvestigating
	}
	now := m.Now()
	inc.OpenedAt = now
	inc.Auto = false

	var out *model.Incident
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		if inc.ID == "" {
			if inc.ID, err = NewID("inc"); err != nil {
				return err
			}
		}
		updateID, err := NewID("iup")
		if err != nil {
			return err
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindIncidentOpen, Service: inc.ServiceID, ObjectIDs: []string{inc.ID},
			Author: p.Author(), Timestamp: now, Message: message,
		}, []model.WriteOp{
			{
				Table: "incidents", Key: map[string]any{"id": inc.ID},
				Values: map[string]any{
					"service_id": inc.ServiceID, "title": clip(inc.Title, 255),
					"impact": inc.Impact, "status": inc.Status,
					"components": clip(csv(inc.Components), 1024),
					"opened_at":  now, "resolved_at": int64(0), "auto": false,
					"trigger_samples": "", "txid": model.TxIDPlaceholder,
				},
			},
			{
				Table: "incident_updates", Key: map[string]any{"id": updateID},
				Values: map[string]any{
					"incident_id": inc.ID, "status": inc.Status, "body": clip(body, 4096),
					"author_sub": p.Sub, "author_display": p.Display, "author_role": p.Acting,
					"created_at": now, "txid": model.TxIDPlaceholder,
				},
			},
		})
		if err != nil {
			return err
		}
		out = &inc
		return nil
	})
	return out, tr, err
}

// UpdateIncident adds an entry to an incident's timeline, and moves its
// status. Resolution needs a message like every other change: an
// incident that ends without anybody saying what happened is a gap in
// the record, not a resolution.
func (m *Monitor) UpdateIncident(p *auth.Principal, incidentID, status, body, message string) (*model.IncidentUpdate, *model.Transaction, error) {
	if !p.Can(auth.PermRespond) {
		return nil, nil, fmt.Errorf("%s may not update incidents", p.Acting)
	}
	if strings.TrimSpace(body) == "" {
		return nil, nil, fmt.Errorf("an update needs a body")
	}
	if !validStatus(status) {
		return nil, nil, fmt.Errorf("%q is not an incident status", status)
	}
	now := m.Now()

	var out *model.IncidentUpdate
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		inc, err := readIncident(tx, incidentID)
		if err != nil {
			return err
		}
		if inc == nil {
			return fmt.Errorf("no incident %s", incidentID)
		}
		updateID, err := NewID("iup")
		if err != nil {
			return err
		}
		incidentValues := map[string]any{"status": status}
		if status == model.IncidentResolved {
			incidentValues["resolved_at"] = now
		} else if inc.Status == model.IncidentResolved {
			// Reopening is allowed and is visible: the resolution stays in
			// the timeline above the reopening.
			incidentValues["resolved_at"] = int64(0)
		}

		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindIncidentUpdate, Service: inc.ServiceID, ObjectIDs: []string{incidentID},
			Author: p.Author(), Timestamp: now, Message: message,
			Refs: []model.Ref{{Type: model.RefRelates, Target: incidentID}},
		}, []model.WriteOp{
			{
				Table: "incident_updates", Key: map[string]any{"id": updateID},
				Values: map[string]any{
					"incident_id": incidentID, "status": status, "body": clip(body, 4096),
					"author_sub": p.Sub, "author_display": p.Display, "author_role": p.Acting,
					"created_at": now, "txid": model.TxIDPlaceholder,
				},
			},
			{
				Table: "incidents", Key: map[string]any{"id": incidentID},
				Values: incidentValues,
			},
		})
		if err != nil {
			return err
		}
		out = &model.IncidentUpdate{
			ID: updateID, IncidentID: incidentID, Status: status, Body: body,
			CreatedAt: now, Author: p.Author(), TxID: tr.TxID,
		}
		return nil
	})
	return out, tr, err
}

// Incidents lists a service's incidents, newest first.
func (m *Monitor) Incidents(serviceID string, from, to int64, limit int) ([]model.Incident, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []model.Incident
	err := m.st.Do(func(tx *store.Tx) error {
		// An empty service means every service: the explorer asks that
		// way, and an instance normally watches one.
		where := "1 = 1"
		if serviceID != "" {
			where = "service_id = " + store.Lit(serviceID)
		}
		if from > 0 {
			where += " AND opened_at >= " + store.Lit(from)
		}
		if to > 0 {
			where += " AND opened_at < " + store.Lit(to)
		}
		rows, err := tx.Query("SELECT * FROM `incidents` WHERE " + where +
			" ORDER BY opened_at DESC LIMIT " + store.Lit(int64(limit)))
		if err != nil {
			return err
		}
		for _, row := range rows {
			inc := incidentFromRow(row)
			updates, err := incidentUpdates(tx, inc.ID)
			if err != nil {
				return err
			}
			inc.Updates = updates
			out = append(out, *inc)
		}
		return nil
	})
	return out, err
}

// Incident reads one incident with its whole timeline.
func (m *Monitor) Incident(id string) (*model.Incident, error) {
	var out *model.Incident
	err := m.st.Do(func(tx *store.Tx) error {
		inc, err := readIncident(tx, id)
		if err != nil || inc == nil {
			return err
		}
		inc.Updates, err = incidentUpdates(tx, id)
		out = inc
		return err
	})
	return out, err
}

// OpenIncidents lists what is currently unresolved, which is what the
// status page banner is about.
func (m *Monitor) OpenIncidents(serviceID string) ([]model.Incident, error) {
	var out []model.Incident
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `incidents` WHERE service_id = " + store.Lit(serviceID) +
			" AND status <> " + store.Lit(model.IncidentResolved) + " ORDER BY opened_at DESC LIMIT 50")
		if err != nil {
			return err
		}
		for _, row := range rows {
			inc := incidentFromRow(row)
			inc.Updates, err = incidentUpdates(tx, inc.ID)
			if err != nil {
				return err
			}
			out = append(out, *inc)
		}
		return nil
	})
	return out, err
}

func readIncident(tx *store.Tx, id string) (*model.Incident, error) {
	row, err := tx.QueryOne("SELECT * FROM `incidents` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return nil, err
	}
	return incidentFromRow(row), nil
}

func incidentFromRow(row store.Row) *model.Incident {
	return &model.Incident{
		ID: row.Str("id"), ServiceID: row.Str("service_id"), Title: row.Str("title"),
		Impact: row.Str("impact"), Status: row.Str("status"),
		Components: splitCSV(row.Str("components")),
		OpenedAt:   row.Int("opened_at"), ResolvedAt: row.Int("resolved_at"),
		Auto: row.Bool("auto"), TriggerSamples: splitCSV(row.Str("trigger_samples")),
	}
}

func incidentUpdates(tx *store.Tx, incidentID string) ([]model.IncidentUpdate, error) {
	rows, err := tx.Query("SELECT * FROM `incident_updates` WHERE incident_id = " +
		store.Lit(incidentID) + " ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	out := make([]model.IncidentUpdate, 0, len(rows))
	for _, row := range rows {
		out = append(out, model.IncidentUpdate{
			ID: row.Str("id"), IncidentID: incidentID, Status: row.Str("status"),
			Body: row.Str("body"), CreatedAt: row.Int("created_at"), TxID: row.Str("txid"),
			Author: model.Author{
				Sub: row.Str("author_sub"), Display: row.Str("author_display"),
				Role: row.Str("author_role"),
			},
		})
	}
	return out, nil
}

func validStatus(status string) bool {
	for _, s := range model.IncidentStatuses {
		if s == status {
			return true
		}
	}
	return false
}
