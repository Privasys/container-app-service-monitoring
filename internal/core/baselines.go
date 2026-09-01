// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"fmt"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Visual baselines.
//
// A baseline is "this is what the page is supposed to look like", and
// the interesting question about one is not what it is but who said so.
// So it lives on the monitor definition rather than in a table of its
// own: approving a new one publishes a new monitor version, with an
// author, a timestamp and a message saying why the page is allowed to
// look different now. The same machinery that lets a report name the
// definition in force during a period therefore also answers "and who
// decided that this was acceptable".
//
// It also means a baseline cannot be changed quietly. Moving the bar
// after a failure is a transaction in the log, sitting next to the
// failure it excuses.

// ApproveBaseline adopts what a monitor last saw as the approved
// appearance of a step.
func (m *Monitor) ApproveBaseline(p *auth.Principal, monitorID, step, message string) (*model.Monitor, *model.Transaction, error) {
	if !p.Can(auth.PermModel) {
		return nil, nil, fmt.Errorf("%s may not change the service model", p.Acting)
	}

	mon, err := m.Monitor(monitorID)
	if err != nil {
		return nil, nil, err
	}
	if mon == nil {
		return nil, nil, fmt.Errorf("no monitor %s", monitorID)
	}
	if mon.Engine != model.EngineBrowser {
		return nil, nil, fmt.Errorf("%s does not run in a browser, so it has nothing to look like", mon.Name)
	}

	capture, err := m.lastCapture(monitorID, step)
	if err != nil {
		return nil, nil, err
	}
	if capture == nil {
		return nil, nil, fmt.Errorf(
			"no screenshot has been taken of %q yet; run the monitor first", step)
	}

	found := false
	for i := range mon.Steps {
		s := &mon.Steps[i]
		if s.Name != step {
			continue
		}
		if s.Screenshot == nil {
			return nil, nil, fmt.Errorf("step %q does not capture a screenshot", step)
		}
		if s.Screenshot.Baseline == capture.Hash {
			return nil, nil, fmt.Errorf("that is already the approved appearance of %q", step)
		}
		s.Screenshot.Baseline = capture.Hash
		found = true
	}
	if !found {
		return nil, nil, fmt.Errorf("%s has no step named %q", mon.Name, step)
	}

	return m.UpsertMonitor(p, *mon, message)
}

// lastCapture finds the most recent screenshot a monitor took of a
// step.
func (m *Monitor) lastCapture(monitorID, step string) (*model.Capture, error) {
	var out *model.Capture
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `samples` WHERE monitor_id = " + store.Lit(monitorID) +
			" AND pruned = FALSE ORDER BY started_at DESC LIMIT 20")
		if err != nil {
			return err
		}
		for _, row := range rows {
			sample := sampleFromRow(row)
			for i := range sample.Captures {
				if sample.Captures[i].Step == step {
					out = &sample.Captures[i]
					return nil
				}
			}
		}
		return nil
	})
	return out, err
}

// Captures lists the screenshots a monitor has taken, newest first, so
// an operator can see what changed before approving a new baseline.
func (m *Monitor) Captures(p *auth.Principal, monitorID string, limit int) ([]CaptureRecord, error) {
	if !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read the readings", p.Acting)
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []CaptureRecord
	err := m.st.Do(func(tx *store.Tx) error {
		where := "pruned = FALSE"
		if monitorID != "" {
			where += " AND monitor_id = " + store.Lit(monitorID)
		}
		rows, err := tx.Query("SELECT * FROM `samples` WHERE " + where +
			" ORDER BY started_at DESC LIMIT " + store.Lit(int64(limit)))
		if err != nil {
			return err
		}
		for _, row := range rows {
			sample := sampleFromRow(row)
			for _, c := range sample.Captures {
				out = append(out, CaptureRecord{
					Sample: sample.ID, MonitorID: sample.MonitorID,
					TakenAt: sample.StartedAt, Verdict: sample.Verdict, Capture: c,
				})
			}
		}
		return nil
	})
	return out, err
}

// CaptureRecord is a screenshot with the reading it belongs to.
type CaptureRecord struct {
	Sample    string        `json:"sample"`
	MonitorID string        `json:"monitor_id"`
	TakenAt   int64         `json:"taken_at"`
	Verdict   string        `json:"verdict"`
	Capture   model.Capture `json:"capture"`
}
