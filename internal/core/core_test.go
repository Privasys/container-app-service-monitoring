// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/availability"
	"github.com/Privasys/container-app-service-monitoring/internal/checkpoint"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/keys"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// A harness with a clock the test drives, so a month of readings takes
// no longer than a month of arithmetic.
type harness struct {
	t       *testing.T
	mon     *core.Monitor
	now     int64
	service *model.Service
	api     *model.Component
	monitor *model.Monitor
	owner   *auth.Principal
}

func newHarness(t *testing.T) *harness {
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

	h := &harness{t: t, now: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Unix()}
	egress := journey.NewAllowlist()
	egress.Open()
	h.mon = core.New(st, material, vault, egress, core.Options{
		Name: "test", Vantage: "test", Tenant: "tenant", CommitmentSource: source,
		Now: func() time.Time { return time.Unix(h.now, 0) },
	})

	h.owner = auth.System("tenant")
	h.owner.Grant(auth.PermModel, auth.PermSecrets, auth.PermMaintenance)

	svc, _, err := h.mon.UpsertService(h.owner, model.Service{
		Name: "Example", Timezone: "UTC", Visibility: model.VisibilityPublic,
		CoverageFloorPPM: 990_000,
	}, "Create the service under test")
	if err != nil {
		t.Fatal(err)
	}
	h.service = svc

	component, _, err := h.mon.UpsertComponent(h.owner, model.Component{
		ServiceID: svc.ID, Name: "API", UserWeight: 1000, Rollup: model.RollupAny,
	}, "Add the API component")
	if err != nil {
		t.Fatal(err)
	}
	h.api = component

	mon, _, err := h.mon.UpsertMonitor(h.owner, model.Monitor{
		ComponentID: component.ID, Name: "order journey",
		IntervalSeconds: 60, TimeoutSeconds: 30,
		FailureThreshold: 2, RecoveryThreshold: 2,
		Steps: []model.Step{{
			Name: "call", Kind: model.StepHTTP, Method: "GET",
			URL: "https://api.example.com/health", ExpectStatus: []int{200},
		}},
	}, "Add the order journey")
	if err != nil {
		t.Fatal(err)
	}
	h.monitor = mon
	return h
}

// record writes one reading a minute for the given number of minutes.
func (h *harness) record(minutes int, verdict string) {
	h.t.Helper()
	for i := 0; i < minutes; i++ {
		_, _, err := h.mon.RecordSamples([]model.Sample{{
			MonitorID: h.monitor.ID, MonitorVersion: h.monitor.Version,
			ComponentID: h.api.ID, ServiceID: h.service.ID, Vantage: "test",
			StartedAt: h.now, DurationMs: 40, Verdict: verdict,
		}})
		if err != nil {
			h.t.Fatal(err)
		}
		h.now += 60
	}
}

func (h *harness) fold() {
	h.t.Helper()
	if _, err := h.mon.Fold(h.now); err != nil {
		h.t.Fatal(err)
	}
}

// The whole chain: readings, folding, an outage, a report, and the
// report recomputed from its own evidence exactly as the shipped
// verifier does it.
func TestAReportRecomputesFromItsOwnEvidence(t *testing.T) {
	h := newHarness(t)
	start := h.now

	h.record(60, model.VerdictUp)
	h.record(10, model.VerdictDown)
	h.record(50, model.VerdictUp)
	h.fold()

	report, err := h.mon.GenerateReport(h.owner, core.ReportRequest{
		ServiceID: h.service.ID, From: start, To: h.now, IncludeProofs: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if report.AST.Net != 7200 {
		t.Fatalf("agreed service time = %d, want 7200", report.AST.Net)
	}
	if report.Downtime.Seconds != 600 {
		t.Fatalf("downtime = %d, want 600", report.Downtime.Seconds)
	}
	if want := availability.Availability(7200, 600); report.Results.AvailabilityPPM != want {
		t.Fatalf("availability = %d, want %d", report.Results.AvailabilityPPM, want)
	}
	if report.Results.CoveragePPM != 1_000_000 {
		t.Fatalf("coverage = %d, want complete", report.Results.CoveragePPM)
	}

	// The signature covers the whole document, evidence included.
	if err := core.VerifyReportSignature(h.mon.PublicKey(), report); err != nil {
		t.Fatalf("the report does not verify: %v", err)
	}
	// The evidence hashes to what the row committed to.
	if got := core.EvidenceHash(report.Evidence.Buckets); got != report.Evidence.EvidenceHash {
		t.Fatal("the evidence does not hash to the committed value")
	}
	// And the arithmetic is reproducible from that evidence alone.
	recomputed := recompute(t, report)
	if recomputed.Results.AvailabilityPPM != report.Results.AvailabilityPPM {
		t.Fatalf("recomputed availability %d, the report says %d",
			recomputed.Results.AvailabilityPPM, report.Results.AvailabilityPPM)
	}
	if recomputed.Downtime.Seconds != report.Downtime.Seconds {
		t.Fatalf("recomputed downtime %d, the report says %d",
			recomputed.Downtime.Seconds, report.Downtime.Seconds)
	}

	// The row is provable and anchored.
	found := false
	for _, bundle := range report.Evidence.Proofs {
		if bundle.Table != "reports" {
			continue
		}
		found = true
		if err := checkpoint.VerifyBundleProof(&bundle); err != nil {
			t.Fatalf("the report row's proof does not hold: %v", err)
		}
		if err := checkpoint.VerifyBundleSignature(h.mon.PublicKey(), &bundle); err != nil {
			t.Fatalf("the report row's bundle is not signed: %v", err)
		}
	}
	if !found {
		t.Fatal("the report carries no proof of its own row")
	}
}

// A report that hid an outage has to fail against its own evidence.
func TestEvidenceContradictsAnEditedReport(t *testing.T) {
	h := newHarness(t)
	start := h.now
	h.record(30, model.VerdictUp)
	h.record(5, model.VerdictDown)
	h.record(25, model.VerdictUp)
	h.fold()

	report, err := h.mon.GenerateReport(h.owner, core.ReportRequest{
		ServiceID: h.service.ID, From: start, To: h.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	edited := *report
	edited.Downtime.Seconds = 0
	edited.Outages = nil
	edited.Results.AvailabilityPPM = 1_000_000

	out := recompute(t, &edited)
	if out.Downtime.Seconds != 300 {
		t.Fatalf("the evidence should still show 300 seconds down, got %d", out.Downtime.Seconds)
	}
	if out.Results.AvailabilityPPM == edited.Results.AvailabilityPPM {
		t.Fatal("the edited figure survived recomputation")
	}
}

// Detection: one failure is not an outage, two consecutive ones are,
// and the recovery threshold works the same way in reverse.
func TestDetectionNeedsConsecutiveFailures(t *testing.T) {
	h := newHarness(t)

	h.record(5, model.VerdictUp)
	states, _ := h.mon.States()
	if states[h.api.ID].Verdict == model.VerdictDown {
		t.Fatal("the component is down before anything failed")
	}

	h.record(1, model.VerdictDown)
	states, _ = h.mon.States()
	if states[h.monitor.ID].Verdict == model.VerdictDown {
		t.Fatal("one failure declared the monitor down; the threshold is two")
	}

	h.record(1, model.VerdictDown)
	states, _ = h.mon.States()
	if states[h.monitor.ID].Verdict != model.VerdictDown {
		t.Fatal("two consecutive failures did not declare the monitor down")
	}
	if states[h.api.ID].Verdict != model.VerdictDown {
		t.Fatal("the component did not follow its monitor down")
	}

	incidents, err := h.mon.OpenIncidents(h.service.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || !incidents[0].Auto {
		t.Fatalf("expected one automatically opened incident, got %d", len(incidents))
	}

	h.record(2, model.VerdictUp)
	states, _ = h.mon.States()
	if states[h.api.ID].Verdict != model.VerdictUp {
		t.Fatal("the component did not recover")
	}
	incidents, _ = h.mon.OpenIncidents(h.service.ID)
	if len(incidents) != 0 {
		t.Fatal("the incident the monitor opened was not resolved when the readings recovered")
	}
}

// An error is not downtime. It is a reading the monitor could not take,
// and it costs coverage instead.
func TestAnErrorDoesNotDeclareAnOutage(t *testing.T) {
	h := newHarness(t)
	h.record(5, model.VerdictUp)
	h.record(5, model.VerdictError)
	states, _ := h.mon.States()
	if states[h.api.ID].Verdict == model.VerdictDown {
		t.Fatal("readings the monitor could not take declared the service down")
	}
}

// The property a dispute turns on.
func TestALateMaintenanceWindowIsRecordedButNotApplied(t *testing.T) {
	h := newHarness(t)
	start := h.now
	h.record(60, model.VerdictUp)
	h.record(10, model.VerdictDown)
	h.record(50, model.VerdictUp)
	h.fold()

	// Declared now, over an interval that has already passed.
	_, _, err := h.mon.DeclareMaintenance(h.owner, model.MaintenanceWindow{
		ServiceID: h.service.ID, Title: "Retrospective window",
		Class:    model.ClassPlannedMaintenance,
		StartsAt: start + 3600, EndsAt: start + 4200,
	}, "Declare a window over an outage that already happened")
	if err != nil {
		t.Fatal(err)
	}

	report, err := h.mon.GenerateReport(h.owner, core.ReportRequest{
		ServiceID: h.service.ID, From: start, To: h.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Exclusions) != 1 {
		t.Fatalf("the window is missing from the report: %v", report.Exclusions)
	}
	ex := report.Exclusions[0]
	if ex.Applied {
		t.Fatal("a window declared after the event was excluded from the agreed service time")
	}
	if ex.LeadTime >= 0 {
		t.Fatalf("the lead time should be negative, got %d", ex.LeadTime)
	}
	if report.Downtime.Seconds != 600 {
		t.Fatalf("the outage was hidden: downtime = %d", report.Downtime.Seconds)
	}

	// The same window, declared with notice, does leave the denominator.
	future := h.now + 7*86400
	window, _, err := h.mon.DeclareMaintenance(h.owner, model.MaintenanceWindow{
		ServiceID: h.service.ID, Title: "Planned upgrade",
		Class:    model.ClassPlannedMaintenance,
		StartsAt: future, EndsAt: future + 3600,
	}, "Declare next week's upgrade window")
	if err != nil {
		t.Fatal(err)
	}
	if !window.Excluded {
		t.Fatal("a window declared a week ahead was not excluded")
	}
}

// A restart is a visible event, because a gap in the readings would
// otherwise look like a quiet period.
func TestACoverageGapIsReportedRatherThanAssumedGood(t *testing.T) {
	h := newHarness(t)
	start := h.now
	h.record(30, model.VerdictUp)
	// Half an hour when nothing was watching.
	h.now += 1800
	h.record(30, model.VerdictUp)
	h.fold()

	report, err := h.mon.GenerateReport(h.owner, core.ReportRequest{
		ServiceID: h.service.ID, From: start, To: h.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Gaps) != 1 || report.Gaps[0].Seconds != 1800 {
		t.Fatalf("gaps = %v, want one of 1800 seconds", report.Gaps)
	}
	if report.Results.CoveragePPM >= 1_000_000 {
		t.Fatalf("coverage = %d, want less than complete", report.Results.CoveragePPM)
	}
	if report.Results.AvailabilityPPM != 1_000_000 {
		t.Fatalf("availability = %d: an unobserved interval is not downtime",
			report.Results.AvailabilityPPM)
	}
}

func TestCheckpointsChainAndAnchorTheLineage(t *testing.T) {
	h := newHarness(t)
	h.record(5, model.VerdictUp)
	first, err := h.mon.IssueCheckpoint(core.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	h.record(5, model.VerdictUp)
	second, err := h.mon.IssueCheckpoint(core.ReasonManual)
	if err != nil {
		t.Fatal(err)
	}
	if second.Checkpoint.Previous == nil ||
		second.Checkpoint.Previous.Version != first.Checkpoint.Version {
		t.Fatal("the second checkpoint does not name the first")
	}
	if err := checkpoint.VerifyCheckpoint(h.mon.PublicKey(), second); err != nil {
		t.Fatalf("the checkpoint does not verify: %v", err)
	}
	if second.Checkpoint.Head == "" {
		t.Fatal("the checkpoint carries no lineage head")
	}

	lineage, err := h.mon.Lineage(h.owner)
	if err != nil {
		t.Fatal(err)
	}
	if !lineage.Enabled {
		t.Fatal("a record created now should maintain the lineage chain")
	}
}

// Credentials are recorded without their values, and destroying one is
// visible in the record.
func TestTheRecordHoldsCredentialsWithoutTheirValues(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.mon.PutSecret(h.owner, "api_key", "the-actual-value",
		[]string{"api.example.com"}, "the test account", "Store the account")
	if err != nil {
		t.Fatal(err)
	}
	list, err := h.mon.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Fingerprint == "" {
		t.Fatalf("secrets = %v", list)
	}
	entries, err := h.mon.Log(h.owner, model.KindSecretPut, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		for _, op := range entry.WriteSet {
			for _, v := range op.Values {
				if s, ok := v.(string); ok && s == "the-actual-value" {
					t.Fatal("the credential value reached the record")
				}
			}
		}
	}
	if _, err := h.mon.DestroySecret(h.owner, "api_key", "Destroy the account"); err != nil {
		t.Fatal(err)
	}
	if h.mon.Vault().Has("api_key") {
		t.Fatal("the credential survived its destruction")
	}
}

// recompute runs the calculation from the report's own evidence, the
// way the offline verifier does.
func recompute(t *testing.T, report *model.Report) availability.Output {
	t.Helper()
	byComponent := map[string][]model.Bucket{}
	for _, b := range report.Evidence.Buckets {
		byComponent[b.ComponentID] = append(byComponent[b.ComponentID], b)
	}
	in := availability.Input{
		Period: report.Period, Scheduled: report.AST.Intervals,
		Exclusions: report.Exclusions,
	}
	for _, c := range report.Components {
		in.Components = append(in.Components, availability.ComponentInput{
			ID: c.ComponentID, Name: c.Name, UserWeight: c.UserWeight,
			Rollup: c.Rollup, Buckets: byComponent[c.ComponentID],
		})
	}
	out, err := availability.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The first boot happens before anyone has said which customer this
// monitor serves. It still has to be recorded: the coverage figure is
// only honest if the monitor's own absences are in the record, and the
// first of them is the one before it was configured.
func TestTheFirstBootIsRecordedBeforeConfiguration(t *testing.T) {
	dir := t.TempDir()
	material, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.Open(filepath.Join(dir, "secrets"), material.Master)
	if err != nil {
		t.Fatal(err)
	}
	ck, _, err := material.CommitmentKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "record"), ck)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}

	// No tenant: this instance has not been configured.
	egress := journey.NewAllowlist()
	egress.Open()
	mon := core.New(st, material, vault, egress, core.Options{Name: "test"})

	if err := mon.RecordRuntimeEvent(model.EventBoot, "the monitor started"); err != nil {
		t.Fatalf("the first boot was not recorded: %v", err)
	}
	events, err := mon.RuntimeEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != model.EventBoot {
		t.Fatalf("events = %v, want one boot", events)
	}
	last, err := mon.LastBoot()
	if err != nil || last == nil {
		t.Fatalf("LastBoot = %v, %v", last, err)
	}
}
