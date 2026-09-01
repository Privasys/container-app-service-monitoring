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

// Maintenance windows, and the one property that makes them worth
// anything in a dispute.
//
// Whether a window leaves the agreed service time is decided once, when
// it is declared, from its class and how much notice it carried. The
// decision and the notice are both written into the record, so a report
// does not only say that an interval was excluded: it says when the
// exclusion was declared, and a window entered after the outage it
// covers appears as exactly that, with its negative lead time on the
// page. Nobody has to be trusted to have been honest about the order of
// events, because the order of events is in the ledger.

// DeclareMaintenance records a maintenance window.
func (m *Monitor) DeclareMaintenance(p *auth.Principal, w model.MaintenanceWindow, message string) (*model.MaintenanceWindow, *model.Transaction, error) {
	if !p.Can(auth.PermMaintenance) {
		return nil, nil, fmt.Errorf("%s may not declare maintenance", p.Acting)
	}
	if w.ServiceID == "" {
		return nil, nil, fmt.Errorf("a maintenance window belongs to a service")
	}
	if strings.TrimSpace(w.Title) == "" {
		return nil, nil, fmt.Errorf("a maintenance window needs a title")
	}
	if w.EndsAt <= w.StartsAt {
		return nil, nil, fmt.Errorf("a maintenance window ends after it starts")
	}
	if w.Class == "" {
		w.Class = model.ClassPlannedMaintenance
	}
	if !validClass(w.Class) {
		return nil, nil, fmt.Errorf("%q is not an exclusion class", w.Class)
	}

	now := m.Now()
	w.DeclaredAt = now
	w.LeadTime = w.StartsAt - now

	var out *model.MaintenanceWindow
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		svc, err := readService(tx, w.ServiceID)
		if err != nil {
			return err
		}
		if svc == nil {
			return fmt.Errorf("no service %s", w.ServiceID)
		}
		lead := svc.MaintenanceLeadTime
		if lead <= 0 {
			lead = DefaultMaintenanceLeadTime
		}

		// The decision, made once and recorded. Only a planned window
		// with the agreed notice leaves the denominator; everything else
		// is recorded, shown, and left in it. Whether a third-party or
		// force-majeure window is excluded is a matter for the contract,
		// not for the monitor, so the monitor declines to assume.
		w.Excluded = w.Class == model.ClassPlannedMaintenance && w.LeadTime >= lead

		if w.ID == "" {
			if w.ID, err = NewID("mw"); err != nil {
				return err
			}
		}
		if !w.Published {
			w.Published = w.Class == model.ClassPlannedMaintenance
		}

		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindMaintenanceDeclare, Service: w.ServiceID, ObjectIDs: []string{w.ID},
			Author: p.Author(), Timestamp: now, Message: message,
		}, []model.WriteOp{{
			Table: "maintenance_windows", Key: map[string]any{"id": w.ID},
			Values: map[string]any{
				"service_id": w.ServiceID, "components": clip(csv(w.Components), 1024),
				"class": w.Class, "title": clip(w.Title, 255), "description": clip(w.Description, 4096),
				"declared_at": w.DeclaredAt, "starts_at": w.StartsAt, "ends_at": w.EndsAt,
				"excluded": w.Excluded, "lead_time": w.LeadTime,
				"published": w.Published, "cancelled": false, "txid": model.TxIDPlaceholder,
			},
		}})
		if err != nil {
			return err
		}
		w.TxID = tr.TxID
		out = &w
		return nil
	})
	return out, tr, err
}

// CancelMaintenance withdraws a window. The window stays in the record,
// marked cancelled: a declaration that was made and then withdrawn is a
// different fact from one that was never made.
func (m *Monitor) CancelMaintenance(p *auth.Principal, id, message string) (*model.Transaction, error) {
	if !p.Can(auth.PermMaintenance) {
		return nil, fmt.Errorf("%s may not declare maintenance", p.Acting)
	}
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		w, err := readMaintenance(tx, id)
		if err != nil {
			return err
		}
		if w == nil {
			return fmt.Errorf("no maintenance window %s", id)
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindMaintenanceCancel, Service: w.ServiceID, ObjectIDs: []string{id},
			Author: p.Author(), Timestamp: m.Now(), Message: message,
			Refs: []model.Ref{{Type: model.RefSupersedes, Target: w.TxID}},
		}, []model.WriteOp{{
			Table: "maintenance_windows", Key: map[string]any{"id": id},
			Values: map[string]any{"cancelled": true},
		}})
		return err
	})
	return tr, err
}

// ActiveMaintenance returns the windows covering an instant, so the
// scheduler can mark readings as taken inside one.
func (m *Monitor) ActiveMaintenance(at int64) ([]model.MaintenanceWindow, error) {
	var out []model.MaintenanceWindow
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `maintenance_windows` WHERE cancelled = FALSE" +
			" AND starts_at <= " + store.Lit(at) + " AND ends_at > " + store.Lit(at))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, *maintenanceFromRow(row))
		}
		return nil
	})
	return out, err
}

// MaintenanceBetween lists the windows intersecting a period, which is
// what a report and the status page both need.
func (m *Monitor) MaintenanceBetween(serviceID string, from, to int64) ([]model.MaintenanceWindow, error) {
	var out []model.MaintenanceWindow
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `maintenance_windows` WHERE service_id = " + store.Lit(serviceID) +
			" AND cancelled = FALSE AND starts_at < " + store.Lit(to) +
			" AND ends_at > " + store.Lit(from) + " ORDER BY starts_at")
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, *maintenanceFromRow(row))
		}
		return nil
	})
	return out, err
}

// UpcomingMaintenance lists published windows that have not ended.
func (m *Monitor) UpcomingMaintenance(serviceID string, at int64) ([]model.MaintenanceWindow, error) {
	var out []model.MaintenanceWindow
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `maintenance_windows` WHERE service_id = " + store.Lit(serviceID) +
			" AND cancelled = FALSE AND published = TRUE AND ends_at > " + store.Lit(at) +
			" ORDER BY starts_at LIMIT 50")
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, *maintenanceFromRow(row))
		}
		return nil
	})
	return out, err
}

func readMaintenance(tx *store.Tx, id string) (*model.MaintenanceWindow, error) {
	row, err := tx.QueryOne("SELECT * FROM `maintenance_windows` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return nil, err
	}
	return maintenanceFromRow(row), nil
}

func maintenanceFromRow(row store.Row) *model.MaintenanceWindow {
	return &model.MaintenanceWindow{
		ID: row.Str("id"), ServiceID: row.Str("service_id"),
		Components: splitCSV(row.Str("components")), Class: row.Str("class"),
		Title: row.Str("title"), Description: row.Str("description"),
		DeclaredAt: row.Int("declared_at"), StartsAt: row.Int("starts_at"),
		EndsAt: row.Int("ends_at"), Excluded: row.Bool("excluded"),
		LeadTime: row.Int("lead_time"), Published: row.Bool("published"),
		Cancelled: row.Bool("cancelled"), TxID: row.Str("txid"),
	}
}

func validClass(class string) bool {
	for _, c := range model.ExclusionClasses {
		if c == class {
			return true
		}
	}
	return false
}
