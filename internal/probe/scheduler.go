// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package probe runs the monitors on their schedule.
//
// The loop ticks once a second, works out which journeys are due, runs
// them concurrently, and writes the tick's readings as one transaction.
// One commit a second keeps the record's version count proportional to
// time rather than to how many things are being watched, and it means a
// reading and the state change it caused land together.
//
// Each monitor gets a deterministic phase offset from its own
// identifier, so a hundred monitors on the same interval spread across
// it instead of firing on the same second and measuring the watched
// service's response to a stampede we created.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// Scheduler drives the monitors.
type Scheduler struct {
	mon    *core.Monitor
	engine *journey.Engine
	log    *slog.Logger

	// Workers bounds how many journeys run at once.
	Workers int
	// Tick is the scheduling resolution.
	Tick time.Duration
	// Reload is how often the monitor definitions are re-read.
	Reload time.Duration
	// RollupLag is how far behind the present the folder works, so it
	// only folds intervals that are closed.
	RollupLag time.Duration
	// CheckpointInterval is how often a quiet monitor anchors itself.
	CheckpointInterval time.Duration
	// RetentionInterval is how often the retention policy runs.
	RetentionInterval time.Duration

	mu       sync.Mutex
	monitors []model.Monitor
	lastRun  map[string]int64
}

// New returns a scheduler with sensible defaults.
func New(mon *core.Monitor, log *slog.Logger) *Scheduler {
	return &Scheduler{
		mon: mon, engine: mon.Engine(), log: log,
		Workers: 16, Tick: time.Second, Reload: 30 * time.Second,
		RollupLag: 90 * time.Second, CheckpointInterval: 6 * time.Hour,
		RetentionInterval: 6 * time.Hour,
		lastRun:           map[string]int64{},
	}
}

// Run drives the loop until the context is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	s.reload()

	ticker := time.NewTicker(s.Tick)
	defer ticker.Stop()
	reload := time.NewTicker(s.Reload)
	defer reload.Stop()
	fold := time.NewTicker(30 * time.Second)
	defer fold.Stop()
	anchor := time.NewTicker(s.CheckpointInterval)
	defer anchor.Stop()
	retain := time.NewTicker(s.RetentionInterval)
	defer retain.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			s.reload()
		case <-fold.C:
			s.fold()
		case <-anchor.C:
			if _, err := s.mon.IssueCheckpoint(core.ReasonScheduled); err != nil {
				s.log.Error("could not anchor the state", "error", err)
			}
		case <-retain.C:
			s.prune()
		case now := <-ticker.C:
			s.tick(ctx, now.Unix())
		}
	}
}

// tick runs everything due this second.
func (s *Scheduler) tick(ctx context.Context, now int64) {
	due := s.due(now)
	if len(due) == 0 {
		return
	}

	// A reading taken inside a declared window is still taken and still
	// recorded. Only the alerting and the arithmetic treat it
	// differently, which is the difference between suppressing a
	// notification and looking away.
	windows, err := s.mon.ActiveMaintenance(now)
	if err != nil {
		s.log.Error("could not read the maintenance windows", "error", err)
	}
	underMaintenance := map[string]bool{}
	blanket := false
	for _, w := range windows {
		if len(w.Components) == 0 {
			blanket = true
		}
		for _, c := range w.Components {
			underMaintenance[c] = true
		}
	}

	results := make([]model.Sample, len(due))
	sem := make(chan struct{}, s.Workers)
	var wg sync.WaitGroup
	for i := range due {
		wg.Add(1)
		go func(i int, mon model.Monitor) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = s.run(ctx, mon, now, underMaintenance[mon.ComponentID] || blanket, false)
		}(i, due[i])
	}
	wg.Wait()

	if _, _, err := s.mon.RecordSamples(results); err != nil {
		s.log.Error("could not record the readings", "error", err, "count", len(results))
	}
}

// run executes one journey and turns it into a reading.
func (s *Scheduler) run(ctx context.Context, mon model.Monitor, now int64, inMaintenance, manual bool) model.Sample {
	res := s.engine.Run(ctx, &mon)
	return model.Sample{
		MonitorID: mon.ID, MonitorVersion: mon.Version,
		ComponentID: mon.ComponentID, ServiceID: mon.ServiceID,
		Vantage: s.mon.Options().Vantage, StartedAt: now,
		DurationMs: res.DurationMs, Verdict: res.Verdict,
		FailedStep: res.FailedStep, ErrorClass: res.ErrorClass, Detail: res.Detail,
		Steps: res.Steps, Manual: manual, InMaintenance: inMaintenance,
	}
}

// RunOnce executes a monitor out of band.
//
// The reading is recorded and visible, and marked manual so it never
// enters the availability series: an operator pressing the button while
// diagnosing an outage must not be able to change what the month's
// report says.
func (s *Scheduler) RunOnce(ctx context.Context, monitorID string) (*model.Sample, error) {
	mon, err := s.mon.Monitor(monitorID)
	if err != nil {
		return nil, err
	}
	if mon == nil {
		return nil, errNotFound(monitorID)
	}
	sample := s.run(ctx, *mon, time.Now().Unix(), false, true)
	if _, _, err := s.mon.RecordSamples([]model.Sample{sample}); err != nil {
		return nil, err
	}
	return &sample, nil
}

type errNotFound string

func (e errNotFound) Error() string { return "no monitor " + string(e) }

// due lists the monitors whose next run has arrived.
func (s *Scheduler) due(now int64) []model.Monitor {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Monitor
	for _, mon := range s.monitors {
		if !mon.Enabled || mon.IntervalSeconds <= 0 {
			continue
		}
		interval := int64(mon.IntervalSeconds)
		// The phase offset spreads monitors that share an interval, and
		// it is derived from the identifier so it survives restarts: a
		// monitor that moved its slot on every boot would leave a
		// systematic hole in the coverage record.
		if (now+offsetOf(mon.ID, interval))%interval != 0 {
			continue
		}
		if last, ok := s.lastRun[mon.ID]; ok && now-last < interval {
			continue
		}
		s.lastRun[mon.ID] = now
		out = append(out, mon)
	}
	return out
}

func offsetOf(id string, interval int64) int64 {
	sum := sha256.Sum256([]byte(id))
	return int64(binary.BigEndian.Uint64(sum[:8])%uint64(interval)) % interval
}

func (s *Scheduler) reload() {
	monitors, err := s.mon.Monitors("")
	if err != nil {
		s.log.Error("could not read the monitors", "error", err)
		return
	}
	s.mu.Lock()
	s.monitors = monitors
	s.mu.Unlock()
}

func (s *Scheduler) fold() {
	before := time.Now().Add(-s.RollupLag).Unix()
	if _, err := s.mon.Fold(before); err != nil {
		s.log.Error("could not fold the readings", "error", err)
	}
}

func (s *Scheduler) prune() {
	p := systemPrincipal(s.mon)
	if _, err := s.mon.PruneSamples(p, 0); err != nil {
		s.log.Error("could not apply the retention policy", "error", err)
	}
}

// systemPrincipal is the identity the scheduler acts under for the
// housekeeping it performs on its own initiative. It is not reachable
// from a request.
func systemPrincipal(m *core.Monitor) *auth.Principal {
	return auth.System(m.Config().Tenant)
}
