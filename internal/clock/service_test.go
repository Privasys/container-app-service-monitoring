// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/clock/timesource"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/keys"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// fakeClock is a trusted clock the test sets.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	ok    bool
	floor time.Time
	// gate, when set, holds Refresh until it is closed.
	gate chan struct{}
}

func (c *fakeClock) Now() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now, c.ok
}
func (c *fakeClock) Floor() time.Time { return c.now }
func (c *fakeClock) SetFloor(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.floor = t
}
func (c *fakeClock) Refresh(ctx context.Context) ([]timesource.Sample, error) {
	c.mu.Lock()
	gate := c.gate
	c.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
		}
	}
	return nil, nil
}
func (c *fakeClock) Status() timesource.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return timesource.Status{Synced: c.ok}
}

// fakePlatform records what the monitor asked of the control plane.
type fakePlatform struct {
	mu          sync.Mutex
	enclaves    []Enclave
	quarantined map[string]string
	calls       []string
	lists       int
}

func (p *fakePlatform) Enclaves(context.Context) ([]Enclave, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lists++
	out := make([]Enclave, len(p.enclaves))
	for i, e := range p.enclaves {
		reason, q := p.quarantined[e.ID]
		e.Quarantined, e.QuarantineReason = q, reason
		out[i] = e
	}
	return out, nil
}

func (p *fakePlatform) Quarantine(_ context.Context, id, reason string, evidence map[string]any) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if evidence["reading_id"] == "" || evidence["monitor_key_id"] == "" {
		panic("a quarantine went out without its evidence")
	}
	p.quarantined[id] = reason
	p.calls = append(p.calls, "quarantine:"+id)
	return 200, nil
}

func (p *fakePlatform) Release(_ context.Context, id, _ string, _ map[string]any) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.quarantined, id)
	p.calls = append(p.calls, "release:"+id)
	return 200, nil
}

func (p *fakePlatform) AttestationCredentials(context.Context) (string, string, time.Time, error) {
	return "https://attestation.invalid/verify", "token", time.Now().Add(time.Hour), nil
}

func (p *fakePlatform) Calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

// fakePoller answers floors the way a runtime would, from a scripted
// host clock.
type fakePoller struct {
	mu     sync.Mutex
	signer *Signer
	answer func(req PollRequest) (*PollResult, error)
	floors []PollRequest
	polled chan string
	// hold, when set, runs before the answer, with the poll's context.
	hold func(ctx context.Context)
}

func (f *fakePoller) Poll(ctx context.Context, e Enclave, req PollRequest) (*PollResult, error) {
	if err := VerifyFloor(f.signer.PublicKey(), req); err != nil {
		panic("the service sent a floor that does not verify: " + err.Error())
	}
	f.mu.Lock()
	f.floors = append(f.floors, req)
	answer, hold := f.answer, f.hold
	f.mu.Unlock()
	if f.polled != nil {
		select {
		case f.polled <- e.ID:
		default:
		}
	}
	if hold != nil {
		hold(ctx)
	}
	return answer(req)
}

func (f *fakePoller) set(answer func(req PollRequest) (*PollResult, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

// reply builds a runtime's answer with the host clock offByMs from the
// floor.
func reply(req PollRequest, keyID string, offByMs int64, verdict string, flagged bool) (*PollResult, error) {
	return &PollResult{HTTPStatus: 200, RTT: 20 * time.Millisecond, Reply: &PollReply{
		EnclaveID: req.EnclaveID, Runtime: "virtual",
		HostTimeMs: req.TMs + offByMs, TrustedTimeMs: req.TMs, FloorMs: req.TMs,
		Flagged: flagged, Verdict: verdict, ConfigKeyID: keyID,
	}}, nil
}

type rig struct {
	t        *testing.T
	mon      *core.Monitor
	svc      *Service
	clock    *fakeClock
	platform *fakePlatform
	poller   *fakePoller
	alerts   chan core.Alert
	enclave  Enclave
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	material, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.Open(filepath.Join(dir, "secrets"), material.Master)
	if err != nil {
		t.Fatal(err)
	}
	ck, source, err := material.CommitmentKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "record"), ck)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	egress := journey.NewAllowlist()
	egress.Open()
	mon := core.New(st, material, vault, egress, core.Options{
		Name: "clock", Tenant: "platform", CommitmentSource: source,
	})
	if _, err := mon.Configure(auth.System("platform"), core.ConfigureRequest{
		Tenant: "platform", CallbackURL: "https://ops.example/hooks",
		PlatformClock: &core.PlatformClock{Enabled: true, ManagementURL: "https://api.example"},
	}, ""); err != nil {
		t.Fatal(err)
	}

	r := &rig{
		t: t, mon: mon,
		clock:    &fakeClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), ok: true},
		platform: &fakePlatform{quarantined: map[string]string{}},
		alerts:   make(chan core.Alert, 64),
		enclave:  Enclave{ID: "11111111-2222-3333-4444-555555555555", Name: "m6-dev", TeeType: "tdx", MgrHostname: "m6-dev-mgr.apps.example"},
	}
	mon.SetHooks(core.Hooks{OnAlert: func(a core.Alert) { r.alerts <- a }})
	r.platform.enclaves = []Enclave{r.enclave}

	key, err := material.ClockKey()
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(key)
	r.poller = &fakePoller{signer: signer, polled: make(chan string, 16)}
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, signer.KeyID(), 0, VerdictInSync, false)
	})
	factory := func(core.PlatformClock, func() time.Time, CredentialSource) (PlatformAPI, Poller) {
		return r.platform, r.poller
	}
	r.svc = NewService(mon, signer, r.clock, factory, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.svc.Interval = time.Hour // the test drives the rounds itself
	r.svc.Apply(mon.PlatformClockConfig())
	t.Cleanup(r.svc.Stop)
	// Wait for the first round Apply starts.
	r.waitPolled()
	r.waitIdle()
	return r
}

func (r *rig) waitPolled() {
	r.t.Helper()
	select {
	case <-r.poller.polled:
	case <-time.After(5 * time.Second):
		r.t.Fatal("the enclave was never polled")
	}
}

// waitIdle waits until the enclave's poll has finished and been
// recorded.
func (r *rig) waitIdle() {
	l := r.svc.lockFor(r.enclave.ID)
	l.Lock()
	l.Unlock()
}

func (r *rig) poll() *model.ClockReading {
	r.t.Helper()
	reading, err := r.svc.PollNow(context.Background(), r.enclave.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return reading
}

func (r *rig) state() model.ClockEnclave {
	r.t.Helper()
	st, err := r.mon.ClockEnclave(r.enclave.ID)
	if err != nil || st == nil {
		r.t.Fatalf("no position recorded: %v", err)
	}
	return *st
}

func (r *rig) expectAlert(event string) core.Alert {
	r.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case a := <-r.alerts:
			if a.Event == event {
				if a.ServiceID != core.ClockServiceID || a.LedgerVersion == 0 {
					r.t.Fatalf("alert %s lacks its subject or ledger coordinates: %+v", event, a)
				}
				return a
			}
		case <-deadline:
			r.t.Fatalf("no %s alert was raised", event)
		}
	}
}

func (r *rig) noAlert(event string) {
	r.t.Helper()
	for {
		select {
		case a := <-r.alerts:
			if a.Event == event {
				r.t.Fatalf("an unexpected %s alert was raised", event)
			}
		default:
			return
		}
	}
}

func TestAWrongHostIsQuarantinedAndReleasedOnceFixed(t *testing.T) {
	r := newRig(t)
	if st := r.state(); st.LastVerdict != VerdictInSync || st.Quarantined {
		t.Fatalf("a clean first round left %+v", st)
	}

	// The host rolls its clock back an hour. The runtime asks NTS, finds
	// the host wrong, and freezes its time.
	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, -3_600_000, VerdictHostWrong, true)
	})
	reading := r.poll()
	if reading.Verdict != VerdictHostWrong || reading.DriftMs > -3_599_000 {
		t.Fatalf("reading %+v", reading)
	}
	if calls := r.platform.Calls(); len(calls) != 1 || calls[0] != "quarantine:"+r.enclave.ID {
		t.Fatalf("platform calls %v, want one quarantine", calls)
	}
	r.expectAlert(core.EventClockQuarantined)
	if st := r.state(); !st.Quarantined || st.QuarantineReason == "" {
		t.Fatalf("the quarantine is not in the record: %+v", st)
	}

	// Still wrong: no second request.
	r.poll()
	if calls := r.platform.Calls(); len(calls) != 1 {
		t.Fatalf("a quarantined enclave was quarantined again: %v", calls)
	}

	// The host is fixed.
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 150, VerdictInSync, false)
	})
	r.poll()
	if calls := r.platform.Calls(); len(calls) != 2 || calls[1] != "release:"+r.enclave.ID {
		t.Fatalf("platform calls %v, want a release", calls)
	}
	r.expectAlert(core.EventClockReleased)
	if st := r.state(); st.Quarantined {
		t.Fatalf("the release is not in the record: %+v", st)
	}

	actions, err := r.mon.ClockActions(10)
	if err != nil || len(actions) != 2 {
		t.Fatalf("actions %+v, %v", actions, err)
	}
	for _, a := range actions {
		if !a.Applied || a.ReadingID == "" {
			t.Fatalf("action %+v", a)
		}
		// The quarantine carries the reading that caused it.
		if a.Op == model.ClockOpQuarantine && a.Evidence["verdict"] != VerdictHostWrong {
			t.Fatalf("the quarantine's evidence is %+v", a.Evidence)
		}
	}
}

func TestAWrongMonitorIsReportedAndNothingIsQuarantined(t *testing.T) {
	r := newRig(t)
	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 120_000, VerdictMonitorWrong, false)
	})
	r.poll()
	r.expectAlert(core.EventClockMonitorWrong)
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("a monitor that is wrong quarantined an enclave: %v", calls)
	}
}

func TestARuntimeWithoutTheKeyIsReportedOnceAndNotQuarantined(t *testing.T) {
	r := newRig(t)
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return &PollResult{HTTPStatus: 409, Body: `{"error":"no clock monitor configured"}`}, nil
	})
	r.poll()
	r.expectAlert(core.EventClockConfigMissing)
	r.poll()
	r.noAlert(core.EventClockConfigMissing)
	if !r.state().ConfigMissing {
		t.Fatal("the missing configuration is not in the fleet view")
	}
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("a missing configuration caused %v", calls)
	}

	// An answer naming another key is the same problem.
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, "ffffffffffffffff", 0, VerdictInSync, false)
	})
	r.poll()
	if !r.state().ConfigMissing {
		t.Fatal("an answer under another key was taken as configured")
	}
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, r.svc.Signer().KeyID(), 0, VerdictInSync, false)
	})
	r.poll()
	if r.state().ConfigMissing {
		t.Fatal("the configuration came back and the fleet view did not notice")
	}
}

func TestTwoSilentPollsQuarantineAnEnclaveThatWasNeverFlagged(t *testing.T) {
	r := newRig(t)
	r.poller.set(func(PollRequest) (*PollResult, error) {
		return nil, ErrUnreachable
	})
	r.poll()
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("one silent poll caused %v", calls)
	}
	if st := r.state(); st.FailedPolls != 1 {
		t.Fatalf("failed polls %d, want 1", st.FailedPolls)
	}
	r.poll()
	if calls := r.platform.Calls(); len(calls) != 1 || calls[0] != "quarantine:"+r.enclave.ID {
		t.Fatalf("platform calls %v, want a quarantine on the second silent poll", calls)
	}
	st := r.state()
	if !st.Quarantined || !strings.HasPrefix(st.QuarantineReason, "unreachable") {
		t.Fatalf("position %+v", st)
	}

	// Answering again, but not yet clean: still quarantined, and the count
	// starts over.
	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 0, VerdictIgnoredStale, false)
	})
	r.poll()
	if st := r.state(); !st.Quarantined || st.FailedPolls != 0 {
		t.Fatalf("position %+v", st)
	}
	// A clean in_sync answer releases it.
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 0, VerdictInSync, false)
	})
	r.poll()
	if calls := r.platform.Calls(); len(calls) != 2 || calls[1] != "release:"+r.enclave.ID {
		t.Fatalf("platform calls %v, want a release", calls)
	}
}

func TestSilenceAfterAFlagIsQuarantined(t *testing.T) {
	r := newRig(t)
	key := r.svc.Signer().KeyID()
	// Flagged, but the monitor's floor was stale to it: no host_clock_wrong
	// verdict, yet the enclave is serving a frozen time.
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 0, VerdictIgnoredStale, true)
	})
	r.poll()
	r.expectAlert(core.EventClockQuarantined)

	// Released by an operator while still flagged, then the host goes
	// quiet: quarantined again on silence.
	r.platform.mu.Lock()
	delete(r.platform.quarantined, r.enclave.ID)
	r.platform.mu.Unlock()
	r.svc.setPlatformQuarantined(r.enclave.ID, false, "")
	r.poller.set(func(PollRequest) (*PollResult, error) {
		return nil, ErrUnreachable
	})
	reading := r.poll()
	if reading.Outcome != model.ClockOutcomeUnreachable {
		t.Fatalf("outcome %q", reading.Outcome)
	}
	if calls := r.platform.Calls(); len(calls) != 2 {
		t.Fatalf("platform calls %v, want a second quarantine on silence", calls)
	}
}

func TestAnIncidentGetsAReceiptAndCausesAPoll(t *testing.T) {
	r := newRig(t)
	report := newReport(r.enclave.ID)
	started := time.Now()
	receipt, err := r.svc.Incident(context.Background(), report, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the receipt took %s", elapsed)
	}
	if err := VerifyReceipt(r.svc.Signer().PublicKey(), r.enclave.ID, receipt); err != nil {
		t.Fatalf("the receipt does not verify: %v", err)
	}
	if receipt.Nonce != report.Nonce {
		t.Fatal("the receipt does not echo the nonce")
	}

	r.waitPolled()
	deadline := time.Now().Add(5 * time.Second)
	for {
		readings, err := r.mon.ClockReadings(r.enclave.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(readings) > 0 && readings[0].Cause == model.ClockCauseIncident {
			if readings[0].IncidentID != receipt.IncidentID {
				t.Fatalf("the poll names incident %q, not %q", readings[0].IncidentID, receipt.IncidentID)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the incident did not cause a poll")
		}
		time.Sleep(20 * time.Millisecond)
	}
	incidents, err := r.mon.ClockIncidents(10)
	if err != nil || len(incidents) != 1 || !incidents[0].KnownFleet {
		t.Fatalf("incidents %+v, %v", incidents, err)
	}
	// The report alone decided nothing: the poll was in sync.
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("a report quarantined an enclave on its own: %v", calls)
	}
}

func TestSequenceNumbersSurviveARestart(t *testing.T) {
	r := newRig(t)
	r.poll()
	r.svc.Stop()
	last := r.poller.floors[len(r.poller.floors)-1].Seq
	for drained := false; !drained; {
		select {
		case <-r.poller.polled:
		default:
			drained = true
		}
	}

	restarted := NewService(r.mon, r.svc.Signer(), r.clock, func(core.PlatformClock, func() time.Time, CredentialSource) (PlatformAPI, Poller) {
		return r.platform, r.poller
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	restarted.Interval = time.Hour
	restarted.Apply(r.mon.PlatformClockConfig())
	defer restarted.Stop()
	r.waitPolled()
	l := restarted.lockFor(r.enclave.ID)
	l.Lock()
	l.Unlock()
	r.poller.mu.Lock()
	next := r.poller.floors[len(r.poller.floors)-1].Seq
	r.poller.mu.Unlock()
	if next <= last {
		t.Fatalf("sequence went from %d to %d across a restart", last, next)
	}
}

func TestNoFloorIsSentWithoutTrustedTime(t *testing.T) {
	r := newRig(t)
	r.clock.mu.Lock()
	r.clock.ok = false
	r.clock.mu.Unlock()
	before := len(r.poller.floors)
	r.svc.Cycle(context.Background())
	r.expectAlert(core.EventClockTrustedTimeLost)
	if len(r.poller.floors) != before {
		t.Fatal("a floor was sent without a trusted time")
	}
	fleet, err := r.svc.Fleet()
	if err != nil || fleet.LastRound.Error == "" || len(fleet.Enclaves) != 1 {
		t.Fatalf("fleet %+v, %v", fleet, err)
	}
}

func newReport(enclaveID string) IncidentReport {
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	return IncidentReport{
		EnclaveID: enclaveID, Reason: ReasonHostBehindFloor,
		HostTimeMs: 1, FloorMs: 2, Nonce: base64.RawURLEncoding.EncodeToString(nonce),
	}
}

func (r *rig) incidentPolls() int {
	r.t.Helper()
	readings, err := r.mon.ClockReadings(r.enclave.ID, 100)
	if err != nil {
		r.t.Fatal(err)
	}
	n := 0
	for _, reading := range readings {
		if reading.Cause == model.ClockCauseIncident {
			n++
		}
	}
	return n
}

func TestReportsCauseAtMostOnePollAMinute(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 3; i++ {
		if _, err := r.svc.Incident(context.Background(), newReport(r.enclave.ID), "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	r.waitPolled()
	deadline := time.Now().Add(5 * time.Second)
	for r.incidentPolls() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("no poll followed the reports")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Give any further poll the time to happen, then count.
	time.Sleep(200 * time.Millisecond)
	r.waitIdle()
	if n := r.incidentPolls(); n != 1 {
		t.Fatalf("three reports caused %d polls, want 1", n)
	}
	incidents, err := r.mon.ClockIncidents(10)
	if err != nil || len(incidents) != 3 {
		t.Fatalf("incidents %d, %v; every report taken is still recorded", len(incidents), err)
	}

	// A minute later a report may cause a poll again.
	r.svc.mu.Lock()
	r.svc.lastIncidentPoll[r.enclave.ID] = time.Now().Add(-incidentPollGap)
	r.svc.mu.Unlock()
	if _, err := r.svc.Incident(context.Background(), newReport(r.enclave.ID), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for r.incidentPolls() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("a report a minute later caused no poll")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAReportForAnUnlistedEnclaveGetsNoReceipt(t *testing.T) {
	r := newRig(t)
	_, err := r.svc.Incident(context.Background(), newReport("99999999-0000-0000-0000-000000000000"), "192.0.2.1")
	if !errors.Is(err, ErrUnknownEnclave) {
		t.Fatalf("got %v, want the unknown-enclave refusal", err)
	}
	if incidents, _ := r.mon.ClockIncidents(10); len(incidents) != 0 {
		t.Fatalf("a refused report was recorded: %+v", incidents)
	}
}

func TestReportsAreRateLimited(t *testing.T) {
	r := newRig(t)
	taken := 0
	for i := 0; i < incidentsPerEnclave+3; i++ {
		_, err := r.svc.Incident(context.Background(), newReport(r.enclave.ID), "192.0.2.1")
		switch {
		case err == nil:
			taken++
		case errors.Is(err, ErrTooManyIncidents):
		default:
			t.Fatal(err)
		}
	}
	if taken != incidentsPerEnclave {
		t.Fatalf("%d reports taken in a burst, want %d", taken, incidentsPerEnclave)
	}
	time.Sleep(200 * time.Millisecond)
	r.waitIdle()
	if incidents, _ := r.mon.ClockIncidents(100); len(incidents) != incidentsPerEnclave {
		t.Fatalf("%d incidents recorded, want %d", len(incidents), incidentsPerEnclave)
	}
}

func TestTheRateLimitIsPerEnclaveAndGlobal(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	l := newRateLimit(6, 10)
	for i := 0; i < 6; i++ {
		if !l.allow("a", now) {
			t.Fatalf("report %d for a refused", i)
		}
	}
	if l.allow("a", now) {
		t.Fatal("a seventh report for one enclave in the same instant was taken")
	}
	for i := 0; i < 4; i++ {
		if !l.allow("b", now) {
			t.Fatalf("report %d for b refused", i)
		}
	}
	if l.allow("c", now) {
		t.Fatal("the global limit did not hold")
	}
	// Ten seconds refill one report per enclave (6 a minute) and more
	// than one globally.
	later := now.Add(10 * time.Second)
	if !l.allow("a", later) {
		t.Fatal("the per-enclave bucket did not refill")
	}
	if l.allow("a", later) {
		t.Fatal("the per-enclave bucket refilled too much")
	}
}

func (p *fakePlatform) listCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lists
}

func TestANewlyRegisteredEnclaveIsFoundOnceAMinute(t *testing.T) {
	r := newRig(t)
	// The start and the first round have listed; let a minute pass.
	r.svc.mu.Lock()
	r.svc.listTried = time.Now().Add(-listRefreshGap)
	r.svc.mu.Unlock()
	before := r.platform.listCalls()

	// An enclave registers after the last list, and reports straight away.
	fresh := Enclave{ID: "22222222-3333-4444-5555-666666666666", Name: "m7-dev", TeeType: "tdx",
		MgrHostname: "m7-dev-mgr.apps.example"}
	r.platform.mu.Lock()
	r.platform.enclaves = append(r.platform.enclaves, fresh)
	r.platform.mu.Unlock()
	if _, err := r.svc.Incident(context.Background(), newReport(fresh.ID), "192.0.2.1"); err != nil {
		t.Fatalf("a report from a newly listed enclave was refused: %v", err)
	}
	if got := r.platform.listCalls() - before; got != 1 {
		t.Fatalf("%d list calls, want 1", got)
	}
	// The report causes a poll of the new enclave; let it finish.
	deadline := time.Now().Add(5 * time.Second)
	for {
		readings, err := r.mon.ClockReadings(fresh.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(readings) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the new enclave was never polled")
		}
		time.Sleep(20 * time.Millisecond)
	}
	l := r.svc.lockFor(fresh.ID)
	l.Lock()
	l.Unlock()

	// Made-up ids, many at once: no further list call within the minute,
	// and every one refused.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("99999999-0000-0000-0000-%012d", i)
			if _, err := r.svc.Incident(context.Background(), newReport(id), "192.0.2.1"); !errors.Is(err, ErrUnknownEnclave) {
				t.Errorf("an unknown enclave got %v", err)
			}
		}(i)
	}
	wg.Wait()
	if got := r.platform.listCalls() - before; got != 1 {
		t.Fatalf("unknown ids drove %d list calls in a minute, want 1", got)
	}
}

func TestConcurrentRefreshesShareOneCall(t *testing.T) {
	r := newRig(t)
	r.svc.mu.Lock()
	r.svc.listTried = time.Time{}
	r.svc.mu.Unlock()
	before := r.platform.listCalls()
	r.platform.mu.Lock() // hold the fetch so the callers pile up on it
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.svc.refreshList(context.Background(), false)
		}()
	}
	time.Sleep(100 * time.Millisecond)
	r.platform.mu.Unlock()
	wg.Wait()
	if got := r.platform.listCalls() - before; got != 1 {
		t.Fatalf("%d concurrent callers made %d list calls, want 1", 10, got)
	}
}

func TestTheListIsFetchedBeforeTheFirstNTSRefresh(t *testing.T) {
	r := newRig(t)
	r.svc.Stop()

	// Restart with the NTS refresh held: reports must be taken anyway,
	// because the list comes first.
	gate := make(chan struct{})
	r.clock.mu.Lock()
	r.clock.gate = gate
	r.clock.mu.Unlock()
	defer close(gate)
	svc := NewService(r.mon, r.svc.Signer(), r.clock, func(core.PlatformClock, func() time.Time, CredentialSource) (PlatformAPI, Poller) {
		return r.platform, r.poller
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.Interval = time.Hour
	svc.Apply(r.mon.PlatformClockConfig())
	defer svc.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := svc.lookup(r.enclave.ID); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the list was not fetched while the NTS refresh was held")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := svc.Incident(context.Background(), newReport(r.enclave.ID), "192.0.2.1"); err != nil {
		t.Fatalf("a report at start was refused: %v", err)
	}
	// Let the poll the report causes finish before the store closes.
	deadline = time.Now().Add(5 * time.Second)
	for r.incidentPolls() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the report caused no poll")
		}
		time.Sleep(20 * time.Millisecond)
	}
	l := svc.lockFor(r.enclave.ID)
	l.Lock()
	l.Unlock()
}

// drainPolled empties the rig's poll notifications.
func (r *rig) drainPolled() {
	for {
		select {
		case <-r.poller.polled:
		default:
			return
		}
	}
}

func TestShutdownCancelsAndWaitsForAnIncidentPoll(t *testing.T) {
	r := newRig(t)
	r.drainPolled()
	r.poller.mu.Lock()
	r.poller.hold = func(ctx context.Context) { <-ctx.Done() }
	r.poller.mu.Unlock()

	if _, err := r.svc.Incident(context.Background(), newReport(r.enclave.ID), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	r.waitPolled() // the incident's poll is now in flight, held

	started := time.Now()
	r.svc.Shutdown()
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %s; the poll's context was not cancelled", elapsed)
	}
	// A poll cut short by shutdown is not a silent poll of the enclave.
	if n := r.incidentPolls(); n != 0 {
		t.Fatalf("a poll cancelled by shutdown was recorded (%d)", n)
	}
	if st := r.state(); st.FailedPolls != 0 {
		t.Fatalf("a cancelled poll counted as a failure: %+v", st)
	}
	// Nothing new starts once shutdown has begun.
	if _, err := r.svc.Incident(context.Background(), newReport(r.enclave.ID), "192.0.2.1"); !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("a report after shutdown got %v", err)
	}
	r.svc.Apply(r.mon.PlatformClockConfig())
	if r.svc.Enabled() {
		t.Fatal("the clock started again after shutdown")
	}
}

func TestWorkThatOutlivesShutdownWritesNothing(t *testing.T) {
	r := newRig(t)
	r.drainPolled()
	previous := shutdownWait
	shutdownWait = 100 * time.Millisecond
	defer func() { shutdownWait = previous }()

	// A poll that ignores its context, and so outlives the wait.
	release := make(chan struct{})
	r.poller.mu.Lock()
	r.poller.hold = func(context.Context) { <-release }
	r.poller.mu.Unlock()
	if _, err := r.svc.Incident(context.Background(), newReport(r.enclave.ID), "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	r.waitPolled()
	incidents, _ := r.mon.ClockIncidents(10)

	started := time.Now()
	r.svc.Shutdown()
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("shutdown waited %s, past its bound", elapsed)
	}
	readings, _ := r.mon.ClockReadings("", 100)

	close(release)
	r.svc.life.bg.Wait() // the straggler finishes, after shutdown

	// The record is untouched by it: the store could have been closed.
	after, _ := r.mon.ClockReadings("", 100)
	afterIncidents, _ := r.mon.ClockIncidents(10)
	if len(after) != len(readings) || len(afterIncidents) != len(incidents) {
		t.Fatalf("work that outlived shutdown wrote to the record: readings %d -> %d",
			len(readings), len(after))
	}
}
