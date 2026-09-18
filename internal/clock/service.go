// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/clock/timesource"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// DefaultInterval is how often every enclave is polled. It is also the
// longest an expired credential can be accepted by a runtime whose host
// rolled its clock back, so it is not a tuning knob to raise lightly.
const DefaultInterval = 5 * time.Minute

// PlatformAPI is the part of the control plane the service uses.
type PlatformAPI interface {
	Enclaves(ctx context.Context) ([]Enclave, error)
	Quarantine(ctx context.Context, enclaveID, reason string, evidence map[string]any) (int, error)
	Release(ctx context.Context, enclaveID, reason string, evidence map[string]any) (int, error)
	AttestationCredentials(ctx context.Context) (server, token string, expires time.Time, err error)
}

// Clock is the source of trusted time.
type Clock interface {
	Now() (time.Time, bool)
	Floor() time.Time
	SetFloor(time.Time)
	Refresh(ctx context.Context) ([]timesource.Sample, error)
	Status() timesource.Status
}

// Factory builds the control-plane client and the poller for a
// configuration. The process supplies the real one; tests supply fakes.
type Factory func(cfg core.PlatformClock, now func() time.Time, creds CredentialSource) (PlatformAPI, Poller)

// CycleStatus describes the last polling round.
type CycleStatus struct {
	StartedMs  int64  `json:"started_ms,omitempty"`
	FinishedMs int64  `json:"finished_ms,omitempty"`
	Enclaves   int    `json:"enclaves"`
	Answered   int    `json:"answered"`
	Error      string `json:"error,omitempty"`
}

// Service runs the platform clock.
type Service struct {
	mon     *core.Monitor
	signer  *Signer
	clock   Clock
	factory Factory
	log     *slog.Logger

	// Interval is how often the fleet is polled.
	Interval time.Duration

	seq atomic.Int64

	mu        sync.Mutex
	cfg       *core.PlatformClock
	cancel    context.CancelFunc
	done      chan struct{}
	platform  PlatformAPI
	poller    Poller
	enclaves  map[string]Enclave
	listedAt  time.Time
	cycle     CycleStatus
	timeLost  bool
	creds     credCache
	locks     map[string]*sync.Mutex
	lastPoll  map[string]time.Time
	seqLoaded bool
}

type credCache struct {
	server, token string
	until         time.Time
}

// NewService builds the service. It does nothing until Apply is given a
// configuration that turns it on.
func NewService(mon *core.Monitor, signer *Signer, clock Clock, factory Factory, log *slog.Logger) *Service {
	return &Service{
		mon: mon, signer: signer, clock: clock, factory: factory, log: log,
		Interval: DefaultInterval,
		enclaves: map[string]Enclave{}, locks: map[string]*sync.Mutex{},
		lastPoll: map[string]time.Time{},
	}
}

// Signer returns the clock key.
func (s *Service) Signer() *Signer { return s.signer }

// Enabled reports whether the platform clock is running.
func (s *Service) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg != nil
}

// Apply starts, reconfigures or stops the service to match cfg.
func (s *Service) Apply(cfg *core.PlatformClock) {
	s.mu.Lock()
	if cfg != nil && s.cfg != nil && *cfg == *s.cfg {
		s.mu.Unlock()
		return
	}
	cancel := s.cancel
	s.cancel, s.done, s.cfg = nil, nil, nil
	s.mu.Unlock()
	// The previous round is told to stop and not waited for: a configure
	// call should not hang behind a poll of an unreachable enclave. Polls
	// of one enclave never overlap, whichever round they belong to.
	if cancel != nil {
		cancel()
	}
	if cfg == nil || !cfg.Enabled {
		return
	}

	c := *cfg
	platform, poller := s.factory(c, s.challengeTime, s.credentials)
	ctx, cancelRun := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cfg, s.platform, s.poller = &c, platform, poller
	s.cancel, s.done = cancelRun, make(chan struct{})
	s.creds = credCache{}
	done := s.done
	s.mu.Unlock()

	s.loadHighWater()
	s.log.Info("the platform clock is on", "management_url", c.ManagementURL, "key_id", s.signer.KeyID())
	go func() {
		defer close(done)
		s.run(ctx)
	}()
}

// Stop halts the service, waiting a bounded time for a round in flight
// to finish recording.
func (s *Service) Stop() {
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	s.Apply(nil)
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

// loadHighWater restores the sequence counter and the time floor from
// the record, so a restart never reuses a sequence number and never
// believes a time earlier than one it already signed.
func (s *Service) loadHighWater() {
	s.mu.Lock()
	loaded := s.seqLoaded
	s.seqLoaded = true
	s.mu.Unlock()
	if loaded {
		return
	}
	seq, monitorMs, err := s.mon.ClockHighWater()
	if err != nil {
		s.log.Error("could not read the clock's high-water mark", "error", err)
		return
	}
	if seq > s.seq.Load() {
		s.seq.Store(seq)
	}
	if monitorMs > 0 {
		s.clock.SetFloor(time.UnixMilli(monitorMs))
	}
}

func (s *Service) run(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	s.Cycle(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Cycle(ctx)
		}
	}
}

// challengeTime is the time the control-plane challenge carries: the
// trusted time when there is one, since the control plane refuses a
// challenge far from its own clock.
func (s *Service) challengeTime() time.Time {
	if t, ok := s.clock.Now(); ok {
		return t
	}
	return time.Now()
}

// credentials returns the attestation server and a token, from the
// control plane, cached until shortly before the token expires.
func (s *Service) credentials(ctx context.Context) (string, string, error) {
	s.mu.Lock()
	cached, platform := s.creds, s.platform
	s.mu.Unlock()
	if cached.token != "" && time.Now().Before(cached.until) {
		return cached.server, cached.token, nil
	}
	if platform == nil {
		return "", "", errors.New("clock: the platform clock is off")
	}
	server, token, expires, err := platform.AttestationCredentials(ctx)
	if err != nil {
		return "", "", err
	}
	until := time.Now().Add(5 * time.Minute)
	if !expires.IsZero() {
		if left := time.Until(expires) - time.Minute; left < 5*time.Minute {
			until = time.Now().Add(left)
		}
	}
	s.mu.Lock()
	s.creds = credCache{server: server, token: token, until: until}
	s.mu.Unlock()
	return server, token, nil
}

// Cycle is one round: refresh the monitor's own time from NTS, list the
// fleet, poll every enclave.
func (s *Service) Cycle(ctx context.Context) {
	started := time.Now()
	status := CycleStatus{StartedMs: s.challengeTime().UnixMilli()}
	defer func() {
		status.FinishedMs = s.challengeTime().UnixMilli()
		s.mu.Lock()
		s.cycle = status
		s.mu.Unlock()
		s.log.Info("platform clock round", "enclaves", status.Enclaves, "answered", status.Answered,
			"duration_ms", time.Since(started).Milliseconds(), "error", status.Error)
	}()

	if _, err := s.clock.Refresh(ctx); err != nil {
		s.log.Error("could not refresh the trusted time", "error", err)
	}
	if !s.checkTrustedTime() {
		status.Error = "the monitor has no trusted time; no floor was sent"
		return
	}

	s.mu.Lock()
	platform := s.platform
	s.mu.Unlock()
	if platform == nil {
		return
	}
	listed, err := platform.Enclaves(ctx)
	if err != nil {
		status.Error = "listing the enclaves: " + err.Error()
		s.log.Error("could not list the enclaves; polling the last known list", "error", err)
	} else {
		s.mu.Lock()
		s.enclaves = make(map[string]Enclave, len(listed))
		for _, e := range listed {
			s.enclaves[e.ID] = e
		}
		s.listedAt = time.Now()
		s.mu.Unlock()
	}

	s.mu.Lock()
	fleet := make([]Enclave, 0, len(s.enclaves))
	for _, e := range s.enclaves {
		fleet = append(fleet, e)
	}
	s.mu.Unlock()
	status.Enclaves = len(fleet)

	var answered atomic.Int64
	slots := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, e := range fleet {
		wg.Add(1)
		slots <- struct{}{}
		go func(e Enclave) {
			defer wg.Done()
			defer func() { <-slots }()
			r, err := s.Poll(ctx, e, model.ClockCauseScheduled, "")
			if err != nil {
				s.log.Error("could not poll an enclave", "enclave", e.Name, "error", err)
				return
			}
			if r.Outcome == model.ClockOutcomeOK {
				answered.Add(1)
			}
		}(e)
	}
	wg.Wait()
	status.Answered = int(answered.Load())
}

// checkTrustedTime reports whether the monitor has a trusted time, and
// raises an alert the first time it does not.
func (s *Service) checkTrustedTime() bool {
	_, ok := s.clock.Now()
	s.mu.Lock()
	wasLost := s.timeLost
	s.timeLost = !ok
	s.mu.Unlock()
	if ok {
		if wasLost {
			s.log.Info("the trusted time is back")
		}
		return true
	}
	if !wasLost {
		st := s.clock.Status()
		if err := s.mon.RaiseClockAlert(core.EventClockTrustedTimeLost, "monitor",
			"Report that the platform clock lost its trusted time",
			map[string]any{"last_error": st.LastError, "last_fetch_ms": st.LastFetchMs}); err != nil {
			s.log.Error("could not record the loss of trusted time", "error", err)
		}
	}
	return false
}

func (s *Service) lockFor(enclaveID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.locks[enclaveID]
	if !ok {
		l = &sync.Mutex{}
		s.locks[enclaveID] = l
	}
	return l
}

// ErrNoTrustedTime means the monitor has no time to sign.
var ErrNoTrustedTime = errors.New("clock: the monitor has no trusted time")

// Poll sends one floor to one enclave, records the answer, and acts on
// it. Polls of the same enclave never overlap.
func (s *Service) Poll(ctx context.Context, e Enclave, cause, incidentID string) (*model.ClockReading, error) {
	lock := s.lockFor(e.ID)
	lock.Lock()
	defer lock.Unlock()

	s.mu.Lock()
	poller := s.poller
	s.lastPoll[e.ID] = time.Now()
	s.mu.Unlock()
	if poller == nil {
		return nil, errors.New("clock: the platform clock is off")
	}

	sent, ok := s.clock.Now()
	if !ok {
		return nil, ErrNoTrustedTime
	}
	prev := model.ClockEnclave{EnclaveID: e.ID}
	if st, err := s.mon.ClockEnclave(e.ID); err != nil {
		return nil, err
	} else if st != nil {
		prev = *st
	}

	req := s.signer.Floor(e.ID, sent.UnixMilli(), s.seq.Add(1))
	pollCtx, cancel := context.WithTimeout(ctx, PollTimeout+10*time.Second)
	res, err := poller.Poll(pollCtx, e, req)
	cancel()
	received, ok := s.clock.Now()
	if !ok {
		received = sent
	}

	id, idErr := core.NewID("clk")
	if idErr != nil {
		return nil, idErr
	}
	r := model.ClockReading{
		ID: id, EnclaveID: e.ID, EnclaveName: e.Name, TeeType: e.TeeType,
		Cause: cause, IncidentID: incidentID, Seq: req.Seq, SentMs: req.TMs,
		MonitorMs: received.UnixMilli(),
	}
	switch {
	case errors.Is(err, ErrUnreachable):
		r.Outcome, r.Error = model.ClockOutcomeUnreachable, err.Error()
	case errors.Is(err, ErrUnverified):
		r.Outcome, r.Error = model.ClockOutcomeUnverified, err.Error()
	case err != nil:
		// The monitor's own side failed (no verifier, no identity). That is
		// not something the enclave did, and it is not recorded as if it
		// were.
		return nil, err
	default:
		r.RTTMs = res.RTT.Milliseconds()
		r.HTTPStatus = res.HTTPStatus
		r.PlatformID = res.PlatformID
		switch {
		case res.HTTPStatus != 200:
			r.Outcome, r.Error = model.ClockOutcomeRefused, res.Body
		case res.Reply == nil:
			r.Outcome, r.Error = model.ClockOutcomeInvalid, "the answer did not parse: "+res.Body
		case res.Reply.EnclaveID != e.ID:
			r.Outcome = model.ClockOutcomeInvalid
			r.Error = fmt.Sprintf("the answer is about enclave %q", res.Reply.EnclaveID)
		default:
			rep := res.Reply
			r.Outcome = model.ClockOutcomeOK
			r.Runtime, r.HostMs, r.TrustedMs, r.FloorMs = rep.Runtime, rep.HostTimeMs, rep.TrustedTimeMs, rep.FloorMs
			r.Flagged, r.Reason, r.Verdict = rep.Flagged, rep.Reason, rep.Verdict
			r.NTSMs, r.NTSServers, r.ConfigKeyID = rep.NTS.TimeMs, rep.NTS.Servers, rep.ConfigKeyID
			r.DriftMs = Drift(rep.HostTimeMs, r.SentMs, r.MonitorMs)
		}
	}

	platformQuarantined := false
	s.mu.Lock()
	if known, ok := s.enclaves[e.ID]; ok {
		platformQuarantined = known.Quarantined
	}
	s.mu.Unlock()

	next := advance(prev, e, r, s.signer.KeyID(), platformQuarantined)
	if _, err := s.mon.RecordClockReadings([]model.ClockReading{r}, []model.ClockEnclave{next},
		readingMessage(e, r)); err != nil {
		return &r, fmt.Errorf("clock: recording the reading: %w", err)
	}

	s.alertOnReading(prev, next, r)
	// Whether the quarantine is ours is as of now: one lifted by someone
	// else is no longer ours to keep.
	before := prev
	before.Quarantined = next.Quarantined
	if d := Decide(before, r, platformQuarantined, s.signer.KeyID()); d.Op != "" {
		s.act(ctx, e, next, r, d)
	}
	return &r, nil
}

// advance computes the enclave's position after a reading.
func advance(prev model.ClockEnclave, e Enclave, r model.ClockReading, keyID string, platformQuarantined bool) model.ClockEnclave {
	next := prev
	next.EnclaveID, next.Name, next.TeeType, next.MgrHostname = e.ID, e.Name, e.TeeType, e.MgrHostname
	next.LastReadingID, next.LastOutcome, next.LastMs, next.UpdatedMs = r.ID, r.Outcome, r.MonitorMs, r.MonitorMs
	if r.Outcome == model.ClockOutcomeOK {
		next.LastOKMs, next.LastVerdict, next.LastFlagged, next.LastReason = r.MonitorMs, r.Verdict, r.Flagged, r.Reason
		next.LastDriftMs, next.LastHostMs, next.LastConfigKey = r.DriftMs, r.HostMs, r.ConfigKeyID
	}
	switch r.Outcome {
	case model.ClockOutcomeOK, model.ClockOutcomeRefused:
		next.ConfigMissing = configMissing(r, keyID)
	}
	if r.Outcome == model.ClockOutcomeUnreachable {
		next.FailedPolls = prev.FailedPolls + 1
	} else {
		next.FailedPolls = 0
	}
	// A quarantine of ours that the platform no longer shows was lifted
	// by someone else. It is not ours to keep tracking.
	if next.Quarantined && !platformQuarantined {
		next.Quarantined, next.QuarantinedMs, next.QuarantineReason = false, 0, ""
	}
	return next
}

func readingMessage(e Enclave, r model.ClockReading) string {
	name := e.Name
	if name == "" {
		name = e.ID
	}
	if r.Outcome == model.ClockOutcomeOK {
		return "Record the clock of " + name + ": " + r.Verdict
	}
	return "Record the clock of " + name + ": " + r.Outcome
}

// alertOnReading raises the alerts a reading calls for by itself: the
// monitor found to be the wrong one, and a runtime that does not hold
// this monitor's key. Both are raised on the transition, not on every
// reading.
func (s *Service) alertOnReading(prev, next model.ClockEnclave, r model.ClockReading) {
	if r.Outcome == model.ClockOutcomeOK && r.Verdict == VerdictMonitorWrong {
		if err := s.mon.RaiseClockAlert(core.EventClockMonitorWrong, r.EnclaveID,
			"Report that a runtime found the monitor's clock wrong", map[string]any{
				"enclave_id": r.EnclaveID, "enclave_name": r.EnclaveName, "reading_id": r.ID,
				"host_ms": r.HostMs, "nts_ms": r.NTSMs, "nts_servers": r.NTSServers,
				"monitor_sent_ms": r.SentMs, "drift_ms": r.DriftMs,
			}); err != nil {
			s.log.Error("could not raise the monitor-clock alert", "error", err)
		}
	}
	if next.ConfigMissing && !prev.ConfigMissing {
		if err := s.mon.RaiseClockAlert(core.EventClockConfigMissing, r.EnclaveID,
			"Report a runtime missing the clock monitor's key", map[string]any{
				"enclave_id": r.EnclaveID, "enclave_name": r.EnclaveName, "reading_id": r.ID,
				"outcome": r.Outcome, "http_status": r.HTTPStatus,
				"runtime_key_id": r.ConfigKeyID, "monitor_key_id": s.signer.KeyID(),
				"remedy": "push the clock monitor configuration to the runtimes again",
			}); err != nil {
			s.log.Error("could not raise the missing-config alert", "error", err)
		}
	}
}

// act asks the platform for a quarantine or a release, and records the
// request and its answer whatever it was.
func (s *Service) act(ctx context.Context, e Enclave, st model.ClockEnclave, r model.ClockReading, d Decision) {
	s.mu.Lock()
	platform := s.platform
	s.mu.Unlock()
	if platform == nil {
		return
	}
	evidence := evidenceOf(r, s.signer.KeyID())
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	var status int
	var err error
	if d.Op == model.ClockOpQuarantine {
		status, err = platform.Quarantine(callCtx, e.ID, d.Reason, evidence)
	} else {
		status, err = platform.Release(callCtx, e.ID, d.Reason, evidence)
	}
	cancel()

	id, idErr := core.NewID("cka")
	if idErr != nil {
		s.log.Error("could not name a clock action", "error", idErr)
		return
	}
	at, ok := s.clock.Now()
	if !ok {
		at = time.UnixMilli(r.MonitorMs)
	}
	a := model.ClockAction{
		ID: id, EnclaveID: e.ID, Op: d.Op, Reason: d.Reason, ReadingID: r.ID,
		Evidence: evidence, Applied: err == nil, HTTPStatus: status, AtMs: at.UnixMilli(),
	}
	event := core.EventClockActionFailed
	if err != nil {
		a.Error = err.Error()
		s.log.Error("the platform refused a clock action", "op", d.Op, "enclave", e.Name, "error", err)
	} else if d.Op == model.ClockOpQuarantine {
		event = core.EventClockQuarantined
		st.Quarantined, st.QuarantinedMs, st.QuarantineReason = true, a.AtMs, d.Reason
		s.setPlatformQuarantined(e.ID, true, d.Reason)
		s.log.Warn("quarantined an enclave", "enclave", e.Name, "reason", d.Reason)
	} else {
		event = core.EventClockReleased
		st.Quarantined, st.QuarantinedMs, st.QuarantineReason = false, 0, ""
		s.setPlatformQuarantined(e.ID, false, "")
		s.log.Info("released an enclave", "enclave", e.Name, "reason", d.Reason)
	}
	st.UpdatedMs = a.AtMs
	payload := map[string]any{
		"enclave_id": e.ID, "enclave_name": e.Name, "op": d.Op, "reason": d.Reason,
		"applied": a.Applied, "reading_id": r.ID, "evidence": evidence,
	}
	if a.Error != "" {
		payload["error"] = a.Error
	}
	if _, err := s.mon.RecordClockAction(a, st, event, payload); err != nil {
		s.log.Error("could not record a clock action", "error", err)
	}
}

func (s *Service) setPlatformQuarantined(enclaveID string, q bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.enclaves[enclaveID]; ok {
		e.Quarantined, e.QuarantineReason = q, reason
		s.enclaves[enclaveID] = e
	}
}

// evidenceOf is the document a quarantine or a release carries: the
// reading that caused it, in full, and where it sits in the record.
func evidenceOf(r model.ClockReading, keyID string) map[string]any {
	return map[string]any{
		"reading_id": r.ID, "outcome": r.Outcome, "cause": r.Cause,
		"incident_id": r.IncidentID, "seq": r.Seq,
		"monitor_sent_ms": r.SentMs, "monitor_received_ms": r.MonitorMs, "rtt_ms": r.RTTMs,
		"host_ms": r.HostMs, "trusted_ms": r.TrustedMs, "floor_ms": r.FloorMs,
		"flagged": r.Flagged, "reason": r.Reason, "verdict": r.Verdict,
		"nts_ms": r.NTSMs, "nts_servers": r.NTSServers, "drift_ms": r.DriftMs,
		"error": r.Error, "http_status": r.HTTPStatus, "platform_id": r.PlatformID,
		"runtime_key_id": r.ConfigKeyID, "monitor_key_id": keyID,
	}
}

// -- incidents ---------------------------------------------------------------

// receiptBudget is how long an incident waits for its record before the
// receipt goes out anyway. The runtime waits at most five seconds for a
// receipt and fails closed without one, so the receipt never waits on
// the ledger for long.
const receiptBudget = 700 * time.Millisecond

// incidentPollGap is the shortest gap between two polls of an enclave
// that incident reports can cause. A burst of reports, genuine or not,
// costs one poll.
const incidentPollGap = 10 * time.Second

// Incident receives a report, answers it with a signed receipt, records
// it, and polls the enclave it names. The receipt is returned within
// receiptBudget whatever the record is doing.
func (s *Service) Incident(ctx context.Context, report IncidentReport, remoteAddr string) (Receipt, error) {
	if !s.Enabled() {
		return Receipt{}, errors.New("clock: the platform clock is off")
	}
	if err := report.Validate(); err != nil {
		return Receipt{}, err
	}
	id, err := core.NewID("cki")
	if err != nil {
		return Receipt{}, err
	}
	receipt := s.signer.Receipt(report.EnclaveID, report.Nonce, id)

	s.mu.Lock()
	e, known := s.enclaves[report.EnclaveID]
	s.mu.Unlock()
	received := s.challengeTime()
	rec := model.ClockIncident{
		ID: id, EnclaveID: report.EnclaveID, Reason: report.Reason,
		HostMs: report.HostTimeMs, FloorMs: report.FloorMs, NTSMs: report.NTSTimeMs,
		Nonce: report.Nonce, ReceivedMs: received.UnixMilli(), KnownFleet: known,
		RemoteAddr: remoteAddr,
	}
	s.log.Warn("clock incident reported", "enclave", report.EnclaveID, "reason", report.Reason, "known", known)

	recorded := make(chan struct{})
	go func() {
		if _, err := s.mon.RecordClockIncident(rec); err != nil {
			s.log.Error("could not record a clock incident", "incident", id, "error", err)
		}
		close(recorded)
		s.pollAfterIncident(e, known, report.EnclaveID, id)
	}()
	select {
	case <-recorded:
	case <-time.After(receiptBudget):
	case <-ctx.Done():
	}
	return receipt, nil
}

// pollAfterIncident polls the enclave a report names, at once. The
// report itself decides nothing: the poll's answer does.
func (s *Service) pollAfterIncident(e Enclave, known bool, enclaveID, incidentID string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if !known {
		e, known = s.refreshFor(ctx, enclaveID)
		if !known {
			s.log.Warn("an incident names an enclave the platform does not list", "enclave", enclaveID)
			return
		}
	}
	s.mu.Lock()
	last := s.lastPoll[enclaveID]
	s.mu.Unlock()
	if time.Since(last) < incidentPollGap {
		return
	}
	if _, err := s.Poll(ctx, e, model.ClockCauseIncident, incidentID); err != nil {
		s.log.Error("could not poll after an incident", "enclave", enclaveID, "error", err)
	}
}

// refreshFor relists the fleet when a report names an enclave the last
// list did not have, at most every thirty seconds.
func (s *Service) refreshFor(ctx context.Context, enclaveID string) (Enclave, bool) {
	s.mu.Lock()
	platform, listedAt := s.platform, s.listedAt
	s.mu.Unlock()
	if platform == nil || time.Since(listedAt) < 30*time.Second {
		return Enclave{}, false
	}
	listed, err := platform.Enclaves(ctx)
	if err != nil {
		return Enclave{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enclaves = make(map[string]Enclave, len(listed))
	for _, e := range listed {
		s.enclaves[e.ID] = e
	}
	s.listedAt = time.Now()
	e, ok := s.enclaves[enclaveID]
	return e, ok
}

// PollNow polls one enclave on request.
func (s *Service) PollNow(ctx context.Context, enclaveID string) (*model.ClockReading, error) {
	if !s.Enabled() {
		return nil, errors.New("clock: the platform clock is off")
	}
	s.mu.Lock()
	e, ok := s.enclaves[enclaveID]
	s.mu.Unlock()
	if !ok {
		if e, ok = s.refreshFor(ctx, enclaveID); !ok {
			return nil, fmt.Errorf("no enclave %s in the fleet", enclaveID)
		}
	}
	return s.Poll(ctx, e, model.ClockCauseManual, "")
}

// -- the fleet view ------------------------------------------------------------

// FleetEnclave is one row of the fleet view.
type FleetEnclave struct {
	model.ClockEnclave
	// Listed is false for an enclave the platform no longer lists.
	Listed bool `json:"listed"`
	// PlatformQuarantined is the platform's own state, whoever placed it.
	PlatformQuarantined bool   `json:"platform_quarantined"`
	PlatformReason      string `json:"platform_quarantine_reason,omitempty"`
}

// Fleet is the fleet view.
type Fleet struct {
	Enabled         bool              `json:"enabled"`
	KeyID           string            `json:"key_id"`
	PublicKey       string            `json:"public_key"`
	IntervalSeconds int64             `json:"interval_seconds"`
	ToleranceMs     int64             `json:"tolerance_ms"`
	TrustedTime     timesource.Status `json:"trusted_time"`
	LastRound       CycleStatus       `json:"last_round"`
	Enclaves        []FleetEnclave    `json:"enclaves"`
}

// Fleet returns the latest position on every enclave, listed or known.
func (s *Service) Fleet() (*Fleet, error) {
	states, err := s.mon.ClockEnclaves()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	listed := make(map[string]Enclave, len(s.enclaves))
	for id, e := range s.enclaves {
		listed[id] = e
	}
	out := &Fleet{
		Enabled: s.cfg != nil, KeyID: s.signer.KeyID(), PublicKey: s.signer.EncodedPublicKey(),
		IntervalSeconds: int64(s.Interval / time.Second), ToleranceMs: Tolerance,
		LastRound: s.cycle,
	}
	s.mu.Unlock()
	out.TrustedTime = s.clock.Status()

	seen := map[string]bool{}
	for _, st := range states {
		row := FleetEnclave{ClockEnclave: st}
		if e, ok := listed[st.EnclaveID]; ok {
			row.Listed, row.PlatformQuarantined, row.PlatformReason = true, e.Quarantined, e.QuarantineReason
		}
		seen[st.EnclaveID] = true
		out.Enclaves = append(out.Enclaves, row)
	}
	for id, e := range listed {
		if seen[id] {
			continue
		}
		out.Enclaves = append(out.Enclaves, FleetEnclave{
			ClockEnclave: model.ClockEnclave{EnclaveID: id, Name: e.Name, TeeType: e.TeeType, MgrHostname: e.MgrHostname},
			Listed:       true, PlatformQuarantined: e.Quarantined, PlatformReason: e.QuarantineReason,
		})
	}
	if out.Enclaves == nil {
		out.Enclaves = []FleetEnclave{}
	}
	return out, nil
}
