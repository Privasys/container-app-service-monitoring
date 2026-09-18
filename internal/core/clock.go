// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// The platform clock's record.
//
// The orchestration (polling, NTS, the platform calls) lives in the
// clock package. What lives here is what every other part of the
// monitor also goes through: the transaction, its envelope and its
// write set, so a clock reading is ledgered, rooted and explorable the
// same way a journey reading is.

// ClockServiceID is the subject the platform clock's alerts are raised
// under. It is not a service in the catalogue: it names the fleet.
const ClockServiceID = "platform-clock"

// Clock alert events.
const (
	EventClockQuarantined     = "clock.quarantined"
	EventClockReleased        = "clock.released"
	EventClockActionFailed    = "clock.action_failed"
	EventClockMonitorWrong    = "clock.monitor_clock_wrong"
	EventClockTrustedTimeLost = "clock.trusted_time_lost"
	EventClockConfigMissing   = "clock.runtime_config_missing"
	// A vault is never quarantined: its clock problems are alerts, and
	// the next clean poll after one is a recovered alert.
	EventClockVaultHostClockWrong = "clock.vault_host_clock_wrong"
	EventClockVaultUnreachable    = "clock.vault_unreachable"
	EventClockVaultRecovered      = "clock.vault_recovered"
	// An enclave whose runtime has not acknowledged the current clock
	// config is never quarantined either: what would quarantine one that
	// holds it raises these instead, once per change. Recovered is raised
	// by the next clean poll, or when the runtime acknowledges the config
	// (from then on it is held to the clock like any other).
	EventClockUnconfiguredClockWrong  = "clock.unconfigured_clock_wrong"
	EventClockUnconfiguredUnreachable = "clock.unconfigured_unreachable"
	EventClockUnconfiguredRecovered   = "clock.unconfigured_recovered"
)

// clockAlertSubject names the runtime an alert standing in
// clock_vault_alerts is about: a vault, or an enclave that does not hold
// the clock config.
func clockAlertSubject(event string) string {
	if strings.HasPrefix(event, "clock.unconfigured_") {
		return "enclave "
	}
	return "vault "
}

// normalisePlatformClock validates the clock part of a configure call.
// The clock's alerts go to the configure call's callback unless the
// clock names its own.
func normalisePlatformClock(req *PlatformClock, callbackURL string) (*PlatformClock, error) {
	if req == nil || !req.Enabled {
		return nil, nil
	}
	out := *req
	out.ManagementURL = strings.TrimRight(strings.TrimSpace(out.ManagementURL), "/")
	u, err := url.Parse(out.ManagementURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("configure: platform_clock needs the management_url of the platform")
	}
	out.CallbackURL = strings.TrimSpace(out.CallbackURL)
	if out.CallbackURL == "" {
		out.CallbackURL = strings.TrimSpace(callbackURL)
	}
	return &out, nil
}

// PlatformClockConfig returns the clock's configuration, or nil when
// the instance does not run it.
func (m *Monitor) PlatformClockConfig() *PlatformClock {
	cfg := m.Config()
	if cfg.PlatformClock == nil || !cfg.PlatformClock.Enabled {
		return nil
	}
	c := *cfg.PlatformClock
	return &c
}

// AlertCallback returns where an alert raised under serviceID is
// delivered: the service's own callback, or for the platform clock the
// clock's.
func (m *Monitor) AlertCallback(serviceID string) string {
	if serviceID == ClockServiceID {
		if c := m.PlatformClockConfig(); c != nil {
			return c.CallbackURL
		}
		return ""
	}
	svc, err := m.Service(serviceID)
	if err != nil || svc == nil {
		return ""
	}
	return svc.CallbackURL
}

// RecordClockReadings writes one round of polls, and the fleet
// positions they produced, as a single transaction.
func (m *Monitor) RecordClockReadings(readings []model.ClockReading, states []model.ClockEnclave, message string) (*model.Transaction, error) {
	if len(readings) == 0 {
		return nil, nil
	}
	var tr *model.Transaction
	now := m.Now()
	err := m.st.Do(func(tx *store.Tx) error {
		ops := make([]model.WriteOp, 0, len(readings)+len(states))
		ids := make([]string, 0, len(readings))
		for _, r := range readings {
			ops = append(ops, clockReadingOp(r))
			ids = append(ids, r.ID)
		}
		for _, st := range states {
			ops = append(ops, clockEnclaveOp(st))
		}
		var err error
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindClockReadings, Service: ClockServiceID, ObjectIDs: ids,
			Author: model.SystemAuthor(), Timestamp: now, Message: summarise(message, 72),
		}, ops)
		return err
	})
	return tr, err
}

// RecordClockIncident writes an incident report as it was received.
func (m *Monitor) RecordClockIncident(inc model.ClockIncident) (*model.Transaction, error) {
	var tr *model.Transaction
	now := m.Now()
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindClockIncident, Service: ClockServiceID, ObjectIDs: []string{inc.ID},
			Author: model.SystemAuthor(), Timestamp: now,
			Message: summarise("Receive a "+inc.Reason+" report from "+inc.EnclaveID, 72),
		}, []model.WriteOp{{
			Table: "clock_incidents", Key: map[string]any{"id": inc.ID},
			Values: map[string]any{
				"enclave_id": inc.EnclaveID, "reason": clip(inc.Reason, 64),
				"host_ms": inc.HostMs, "floor_ms": inc.FloorMs, "nts_ms": inc.NTSMs,
				"nonce": clip(inc.Nonce, 64), "received_ms": inc.ReceivedMs,
				"known_enclave": inc.KnownFleet, "remote_addr": clip(inc.RemoteAddr, 96),
			},
		}})
		return err
	})
	return tr, err
}

// RecordClockAction writes a quarantine or a release, the enclave's new
// position, and the alert that goes with it, as one transaction. The
// alert is then handed to delivery.
func (m *Monitor) RecordClockAction(a model.ClockAction, st model.ClockEnclave, event string,
	payload map[string]any) (*model.Transaction, error) {

	var tr *model.Transaction
	var alert *Alert
	now := m.Now()
	err := m.st.Do(func(tx *store.Tx) error {
		evidence, err := jsonBytes(a.Evidence)
		if err != nil {
			return err
		}
		ops := []model.WriteOp{
			{
				Table: "clock_actions", Key: map[string]any{"id": a.ID},
				Values: map[string]any{
					"enclave_id": a.EnclaveID, "op_kind": a.Op, "reason": clip(a.Reason, 255),
					"reading_id": a.ReadingID, "evidence": evidence, "applied": a.Applied,
					"http_status": int64(a.HTTPStatus), "error_text": clip(a.Error, 512),
					"at_ms": a.AtMs,
				},
			},
			clockEnclaveOp(st),
		}
		if event != "" {
			raised, alertOps, err := m.raise(tx, ClockServiceID, event, a.EnclaveID,
				event+":"+a.EnclaveID+":"+a.ID, payload, now)
			if err != nil {
				return err
			}
			ops = append(ops, alertOps...)
			alert = &raised
		}
		kind, verb := model.KindClockQuarantine, "Quarantine"
		if a.Op == model.ClockOpRelease {
			kind, verb = model.KindClockRelease, "Release"
		}
		message := verb + " " + orString(st.Name, a.EnclaveID)
		if !a.Applied {
			message = "Record a refused " + strings.ToLower(verb) + " of " + orString(st.Name, a.EnclaveID)
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: kind, Service: ClockServiceID, ObjectIDs: []string{a.ID, a.EnclaveID},
			Author: model.SystemAuthor(), Timestamp: now,
			Message: summarise(message, 72) + "\n\n" + a.Reason,
		}, ops)
		if err != nil {
			return err
		}
		if alert != nil {
			alert.LedgerRoot, alert.LedgerVersion = tx.Root()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if alert != nil && m.hooks.OnAlert != nil {
		m.hooks.OnAlert(*alert)
	}
	return tr, nil
}

// RaiseClockAlert records an alert about the platform clock itself,
// such as its own time being wrong, and hands it to delivery.
func (m *Monitor) RaiseClockAlert(event, subject, message string, payload map[string]any) error {
	var alert Alert
	now := m.Now()
	err := m.st.Do(func(tx *store.Tx) error {
		raised, ops, err := m.raise(tx, ClockServiceID, event, subject,
			fmt.Sprintf("%s:%s:%d", event, subject, now/300), payload, now)
		if err != nil {
			return err
		}
		if _, err := m.commit(tx, model.Envelope{
			Kind: model.KindAlertEmit, Service: ClockServiceID, ObjectIDs: []string{raised.ID},
			Author: model.SystemAuthor(), Timestamp: now, Message: summarise(message, 72),
		}, ops); err != nil {
			return err
		}
		raised.LedgerRoot, raised.LedgerVersion = tx.Root()
		alert = raised
		return nil
	})
	if err != nil {
		return err
	}
	if m.hooks.OnAlert != nil {
		m.hooks.OnAlert(alert)
	}
	return nil
}

// ClockEnclaves returns the monitor's position on every enclave it has
// polled.
func (m *Monitor) ClockEnclaves() ([]model.ClockEnclave, error) {
	var out []model.ClockEnclave
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `clock_enclaves` ORDER BY name, enclave_id")
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, rowToClockEnclave(row))
		}
		return nil
	})
	return out, err
}

// ClockEnclave returns the monitor's position on one enclave, or nil
// when it has never polled it.
func (m *Monitor) ClockEnclave(enclaveID string) (*model.ClockEnclave, error) {
	var out *model.ClockEnclave
	err := m.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT * FROM `clock_enclaves` WHERE enclave_id = " + store.Lit(enclaveID))
		if err != nil || row == nil {
			return err
		}
		st := rowToClockEnclave(row)
		out = &st
		return nil
	})
	return out, err
}

// ClockReadings returns the latest readings, newest first, optionally
// for one enclave.
func (m *Monitor) ClockReadings(enclaveID string, limit int) ([]model.ClockReading, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	where := ""
	if enclaveID != "" {
		where = " WHERE enclave_id = " + store.Lit(enclaveID)
	}
	var out []model.ClockReading
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `clock_readings`" + where +
			fmt.Sprintf(" ORDER BY monitor_ms DESC, seq DESC LIMIT %d", limit))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, rowToClockReading(row))
		}
		return nil
	})
	return out, err
}

// ClockIncidents returns the latest incident reports, newest first.
func (m *Monitor) ClockIncidents(limit int) ([]model.ClockIncident, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var out []model.ClockIncident
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query(fmt.Sprintf(
			"SELECT * FROM `clock_incidents` ORDER BY received_ms DESC LIMIT %d", limit))
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, model.ClockIncident{
				ID: row.Str("id"), EnclaveID: row.Str("enclave_id"), Reason: row.Str("reason"),
				HostMs: row.Int("host_ms"), FloorMs: row.Int("floor_ms"), NTSMs: row.Int("nts_ms"),
				Nonce: row.Str("nonce"), ReceivedMs: row.Int("received_ms"),
				KnownFleet: row.Bool("known_enclave"), RemoteAddr: row.Str("remote_addr"),
			})
		}
		return nil
	})
	return out, err
}

// ClockActions returns the latest quarantines and releases, newest
// first.
func (m *Monitor) ClockActions(limit int) ([]model.ClockAction, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var out []model.ClockAction
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query(fmt.Sprintf(
			"SELECT * FROM `clock_actions` ORDER BY at_ms DESC LIMIT %d", limit))
		if err != nil {
			return err
		}
		for _, row := range rows {
			a := model.ClockAction{
				ID: row.Str("id"), EnclaveID: row.Str("enclave_id"), Op: row.Str("op_kind"),
				Reason: row.Str("reason"), ReadingID: row.Str("reading_id"),
				Applied: row.Bool("applied"), HTTPStatus: int(row.Int("http_status")),
				Error: row.Str("error_text"), AtMs: row.Int("at_ms"),
			}
			if raw := row.Bytes("evidence"); len(raw) > 0 {
				_ = json.Unmarshal(raw, &a.Evidence)
			}
			out = append(out, a)
		}
		return nil
	})
	return out, err
}

// ClockHighWater returns the highest floor sequence number and the
// latest trusted time in the record, so a restarted instance never
// reuses a sequence number and never believes a time earlier than one
// it already signed.
func (m *Monitor) ClockHighWater() (seq, monitorMs int64, err error) {
	err = m.st.Do(func(tx *store.Tx) error {
		if seq, err = tx.Count("SELECT COALESCE(MAX(seq), 0) FROM `clock_readings`"); err != nil {
			return err
		}
		monitorMs, err = tx.Count("SELECT COALESCE(MAX(monitor_ms), 0) FROM `clock_readings`")
		return err
	})
	return seq, monitorMs, err
}

func clockReadingOp(r model.ClockReading) model.WriteOp {
	return model.WriteOp{
		Table: "clock_readings", Key: map[string]any{"id": r.ID},
		Values: map[string]any{
			"enclave_id": r.EnclaveID, "enclave_name": clip(r.EnclaveName, 160),
			"tee_type": clip(r.TeeType, 16), "cause": r.Cause, "incident_id": r.IncidentID,
			"seq": r.Seq, "sent_ms": r.SentMs, "monitor_ms": r.MonitorMs, "rtt_ms": r.RTTMs,
			"outcome": r.Outcome, "error_text": clip(r.Error, 512),
			"http_status":  int64(r.HTTPStatus),
			"runtime_kind": clip(r.Runtime, 16), "host_ms": r.HostMs, "trusted_ms": r.TrustedMs,
			"floor_ms": r.FloorMs, "flagged": r.Flagged, "reason": clip(r.Reason, 64),
			"verdict": clip(r.Verdict, 32), "nts_ms": r.NTSMs,
			"nts_servers":   clip(csv(r.NTSServers), 512),
			"config_key_id": clip(r.ConfigKeyID, 32), "platform_id": clip(r.PlatformID, 96),
			"drift_ms": r.DriftMs,
		},
	}
}

func rowToClockReading(row store.Row) model.ClockReading {
	return model.ClockReading{
		ID: row.Str("id"), EnclaveID: row.Str("enclave_id"), EnclaveName: row.Str("enclave_name"),
		TeeType: row.Str("tee_type"), Cause: row.Str("cause"), IncidentID: row.Str("incident_id"),
		Seq: row.Int("seq"), SentMs: row.Int("sent_ms"), MonitorMs: row.Int("monitor_ms"),
		RTTMs: row.Int("rtt_ms"), Outcome: row.Str("outcome"), Error: row.Str("error_text"),
		HTTPStatus: int(row.Int("http_status")), Runtime: row.Str("runtime_kind"),
		HostMs: row.Int("host_ms"), TrustedMs: row.Int("trusted_ms"), FloorMs: row.Int("floor_ms"),
		Flagged: row.Bool("flagged"), Reason: row.Str("reason"), Verdict: row.Str("verdict"),
		NTSMs: row.Int("nts_ms"), NTSServers: splitCSV(row.Str("nts_servers")),
		ConfigKeyID: row.Str("config_key_id"), PlatformID: row.Str("platform_id"),
		DriftMs: row.Int("drift_ms"),
	}
}

func clockEnclaveOp(st model.ClockEnclave) model.WriteOp {
	return model.WriteOp{
		Table: "clock_enclaves", Key: map[string]any{"enclave_id": st.EnclaveID},
		Values: map[string]any{
			"name": clip(st.Name, 160), "tee_type": clip(st.TeeType, 16),
			"mgr_hostname":    clip(st.MgrHostname, 255),
			"last_reading_id": st.LastReadingID, "last_outcome": st.LastOutcome,
			"last_ms": st.LastMs, "last_ok_ms": st.LastOKMs,
			"last_verdict": clip(st.LastVerdict, 32), "last_flagged": st.LastFlagged,
			"last_reason": clip(st.LastReason, 64), "last_drift_ms": st.LastDriftMs,
			"last_host_ms": st.LastHostMs, "last_config_key_id": clip(st.LastConfigKey, 32),
			"config_missing": st.ConfigMissing, "failed_polls": int64(st.FailedPolls),
			"quarantined": st.Quarantined, "quarantined_ms": st.QuarantinedMs,
			"quarantine_reason": clip(st.QuarantineReason, 255), "updated_ms": st.UpdatedMs,
		},
	}
}

func rowToClockEnclave(row store.Row) model.ClockEnclave {
	return model.ClockEnclave{
		EnclaveID: row.Str("enclave_id"), Name: row.Str("name"), TeeType: row.Str("tee_type"),
		MgrHostname: row.Str("mgr_hostname"), LastReadingID: row.Str("last_reading_id"),
		LastOutcome: row.Str("last_outcome"), LastMs: row.Int("last_ms"),
		LastOKMs: row.Int("last_ok_ms"), LastVerdict: row.Str("last_verdict"),
		LastFlagged: row.Bool("last_flagged"), LastReason: row.Str("last_reason"),
		LastDriftMs: row.Int("last_drift_ms"), LastHostMs: row.Int("last_host_ms"),
		LastConfigKey: row.Str("last_config_key_id"), ConfigMissing: row.Bool("config_missing"),
		FailedPolls:   int(row.Int("failed_polls")),
		Quarantined:   row.Bool("quarantined"),
		QuarantinedMs: row.Int("quarantined_ms"), QuarantineReason: row.Str("quarantine_reason"),
		UpdatedMs: row.Int("updated_ms"),
	}
}

// RecordClockVaultAlert writes the alert standing on a vault, or on an
// enclave whose runtime does not hold the clock config, and raises event
// with payload, as one transaction, then hands the alert to delivery.
// Neither is ever quarantined, so this is the whole of what the monitor
// does about a clock problem on one.
func (m *Monitor) RecordClockVaultAlert(st model.ClockVaultAlert, event string, payload map[string]any) (*model.Transaction, error) {
	var tr *model.Transaction
	var alert Alert
	now := m.Now()
	err := m.st.Do(func(tx *store.Tx) error {
		raised, ops, err := m.raise(tx, ClockServiceID, event, st.EnclaveID,
			event+":"+st.EnclaveID+":"+st.ReadingID, payload, now)
		if err != nil {
			return err
		}
		ops = append(ops, model.WriteOp{
			Table: "clock_vault_alerts", Key: map[string]any{"enclave_id": st.EnclaveID},
			Values: map[string]any{
				"name": clip(st.Name, 160), "alert_event": clip(st.Event, 48),
				"reason": clip(st.Reason, 255), "reading_id": st.ReadingID,
				"raised_ms": st.RaisedMs, "updated_ms": st.UpdatedMs,
			},
		})
		verb := "Alert on the clock of " + clockAlertSubject(event)
		if event == EventClockVaultRecovered || event == EventClockUnconfiguredRecovered {
			verb = "Record the recovery of the clock of " + clockAlertSubject(event)
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindAlertEmit, Service: ClockServiceID, ObjectIDs: []string{raised.ID, st.EnclaveID},
			Author: model.SystemAuthor(), Timestamp: now,
			Message: summarise(verb+orString(st.Name, st.EnclaveID), 72) + "\n\n" + st.Reason,
		}, ops)
		if err != nil {
			return err
		}
		raised.LedgerRoot, raised.LedgerVersion = tx.Root()
		alert = raised
		return nil
	})
	if err != nil {
		return nil, err
	}
	if m.hooks.OnAlert != nil {
		m.hooks.OnAlert(alert)
	}
	return tr, nil
}

// ClockVaultAlert returns the alert standing on a vault, or nil when none
// was ever raised on it.
func (m *Monitor) ClockVaultAlert(enclaveID string) (*model.ClockVaultAlert, error) {
	var out *model.ClockVaultAlert
	err := m.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT * FROM `clock_vault_alerts` WHERE enclave_id = " + store.Lit(enclaveID))
		if err != nil || row == nil {
			return err
		}
		a := rowToClockVaultAlert(row)
		out = &a
		return nil
	})
	return out, err
}

// ClockVaultAlerts returns the alert position on every vault that ever had
// one.
func (m *Monitor) ClockVaultAlerts() ([]model.ClockVaultAlert, error) {
	var out []model.ClockVaultAlert
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `clock_vault_alerts` ORDER BY name, enclave_id")
		if err != nil {
			return err
		}
		for _, row := range rows {
			out = append(out, rowToClockVaultAlert(row))
		}
		return nil
	})
	return out, err
}

func rowToClockVaultAlert(row store.Row) model.ClockVaultAlert {
	return model.ClockVaultAlert{
		EnclaveID: row.Str("enclave_id"), Name: row.Str("name"), Event: row.Str("alert_event"),
		Reason: row.Str("reason"), ReadingID: row.Str("reading_id"),
		RaisedMs: row.Int("raised_ms"), UpdatedMs: row.Int("updated_ms"),
	}
}
