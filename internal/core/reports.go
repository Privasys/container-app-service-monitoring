// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/availability"
	"github.com/Privasys/container-app-service-monitoring/internal/canon"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// The SLA report.
//
// A report is a transaction, not a rendering. The monitor writes a
// report row whose columns carry the headline figures, a hash over the
// exact evidence the arithmetic used, and the document itself; then it
// anchors the state and attaches the inclusion proof for that row. What
// the customer receives is therefore checkable in one pass and without
// the monitor's help: recompute the arithmetic from the bundled
// readings, confirm the readings hash to what the row committed to, and
// confirm the row is in a state a signed checkpoint attests.
//
// The signature is applied last and covers everything, so the evidence
// cannot be swapped for a friendlier set after the fact.

// ReportRequest asks for a report.
type ReportRequest struct {
	ServiceID string
	// Window is a named reporting period (calendar_month, calendar_week,
	// calendar_quarter, rolling_30d).
	Window string
	// Previous asks for the period before the current one, which is what
	// "last month's report" means.
	Previous bool
	// From and To override the named period entirely.
	From, To int64
	// IncludeProofs attaches inclusion proofs for the folded intervals
	// inside declared outages: the minutes an argument is actually
	// about.
	IncludeProofs bool
}

// GenerateReport produces and records a signed report.
func (m *Monitor) GenerateReport(p *auth.Principal, req ReportRequest) (*model.Report, error) {
	if !p.Can(auth.PermReports) {
		return nil, fmt.Errorf("%s may not issue reports", p.Acting)
	}

	var report *model.Report
	err := m.st.Do(func(tx *store.Tx) error {
		svc, err := readService(tx, req.ServiceID)
		if err != nil {
			return err
		}
		if svc == nil {
			return fmt.Errorf("no service %s", req.ServiceID)
		}
		period, err := resolvePeriod(req, svc)
		if err != nil {
			return err
		}
		built, evidenceBuckets, err := m.buildReport(tx, svc, period, req)
		if err != nil {
			return err
		}
		report = built

		// The row carries both the document and the readings it rests on,
		// so retrieving a report months later returns the same evidence it
		// was issued with rather than whatever has been folded since.
		id, err := NewID("rep")
		if err != nil {
			return err
		}
		built.ID = id
		body, err := canon.Marshal(reportCore(built))
		if err != nil {
			return err
		}
		evidenceBody, err := canon.Marshal(evidenceBuckets)
		if err != nil {
			return err
		}
		evidenceHash := hashBuckets(evidenceBuckets)

		if _, err := m.commit(tx, model.Envelope{
			Kind: model.KindReportIssue, Service: svc.ID, ObjectIDs: []string{id},
			Author: p.Author(), Timestamp: m.Now(),
			Message: fmt.Sprintf("Report %s availability for %s", svc.Name, period.Label),
		}, []model.WriteOp{{
			Table: "reports", Key: map[string]any{"id": id},
			Values: map[string]any{
				"service_id": svc.ID, "period_from": period.From, "period_to": period.To,
				"label":                 period.Label,
				"availability_ppm":      built.Results.AvailabilityPPM,
				"user_availability_ppm": built.Results.UserAvailabilityPPM,
				"coverage_ppm":          built.Results.CoveragePPM,
				"downtime_seconds":      built.Downtime.Seconds,
				"outages":               built.Downtime.Outages,
				"evidence_hash":         evidenceHash,
				"evidence":              model.Binary(evidenceBody),
				"document":              model.Binary(body),
				"generated_at":          built.GeneratedAt,
				"txid":                  model.TxIDPlaceholder,
			},
		}}); err != nil {
			return err
		}

		// Anchor after the write, so the proof of the report row is taken
		// at the state that contains it.
		anchor, err := m.anchorCurrentState(tx)
		if err != nil {
			return err
		}
		root, version := tx.Root()
		built.Evidence = &model.ReportEvidence{
			Root: root, Version: version, Checkpoint: anchor,
			EvidenceHash: evidenceHash, Buckets: evidenceBuckets,
		}
		rowProof, err := m.evidence(tx, "reports", []any{id},
			"the report "+id+" as it was recorded")
		if err != nil {
			return err
		}
		built.Evidence.Proofs = []model.EvidenceBundle{*rowProof}

		if req.IncludeProofs {
			proofs, err := m.outageProofs(tx, built)
			if err != nil {
				return err
			}
			built.Evidence.Proofs = append(built.Evidence.Proofs, proofs...)
		}

		return SignReport(m.mat.Signer, m.mat.KeyID, built)
	})
	if err != nil {
		return nil, err
	}
	return report, nil
}

// buildReport does the reading and the arithmetic.
func (m *Monitor) buildReport(tx *store.Tx, svc *model.Service, period model.Period,
	req ReportRequest) (*model.Report, []model.Bucket, error) {

	schedule, err := readSchedule(tx, svc.ScheduleID)
	if err != nil {
		return nil, nil, err
	}
	if schedule == nil {
		return nil, nil, fmt.Errorf("service %s has no agreed service time", svc.ID)
	}
	scheduled, err := availability.Expand(*schedule, period.From, period.To)
	if err != nil {
		return nil, nil, err
	}

	components, err := listComponents(tx, svc.ID)
	if err != nil {
		return nil, nil, err
	}
	monitors, err := listMonitors(tx, svc.ID)
	if err != nil {
		return nil, nil, err
	}
	objectives, err := listObjectives(tx, svc.ID)
	if err != nil {
		return nil, nil, err
	}

	// Exclusions. The decision was taken when each window was declared;
	// the report repeats it and shows the notice that was given.
	windows, err := maintenanceBetween(tx, svc.ID, period.From, period.To)
	if err != nil {
		return nil, nil, err
	}
	exclusions := make([]model.Exclusion, 0, len(windows))
	for _, w := range windows {
		exclusions = append(exclusions, model.Exclusion{
			WindowID: w.ID, Class: w.Class, Title: w.Title,
			DeclaredAt: w.DeclaredAt, LeadTime: w.LeadTime,
			From: w.StartsAt, To: w.EndsAt, Applied: w.Excluded,
			Reason: exclusionReason(w, svc), TxID: w.TxID,
		})
	}

	buckets, err := m.evidenceBuckets(tx, svc.ID, period.From, period.To)
	if err != nil {
		return nil, nil, err
	}

	byComponent := map[string][]model.Bucket{}
	for _, b := range buckets {
		byComponent[b.ComponentID] = append(byComponent[b.ComponentID], b)
	}
	monitorRefs := make([]model.MonitorRef, 0, len(monitors))
	refsByComponent := map[string][]model.MonitorRef{}
	for _, mon := range monitors {
		ref := model.MonitorRef{
			ID: mon.ID, Name: mon.Name, Version: mon.Version,
			ComponentID: mon.ComponentID, IntervalSec: mon.IntervalSeconds,
		}
		monitorRefs = append(monitorRefs, ref)
		refsByComponent[mon.ComponentID] = append(refsByComponent[mon.ComponentID], ref)
	}

	in := availability.Input{
		Period: period, Scheduled: scheduled, Exclusions: exclusions,
		CoverageFloorPPM: svc.CoverageFloorPPM, Objectives: objectives,
	}
	for _, c := range components {
		in.Components = append(in.Components, availability.ComponentInput{
			ID: c.ID, Name: c.Name, UserWeight: c.UserWeight, Rollup: c.Rollup,
			Buckets: byComponent[c.ID], Monitors: refsByComponent[c.ID],
		})
	}

	out, err := availability.Compute(in)
	if err != nil {
		return nil, nil, err
	}
	// The rollup rule travels with the result: a verifier that does not
	// know it cannot reach the same answer.
	rollups := map[string]string{}
	for _, c := range components {
		rollups[c.ID] = c.Rollup
	}
	for i := range out.Components {
		out.Components[i].Rollup = rollups[out.Components[i].ComponentID]
	}

	incidents, err := incidentsBetween(tx, svc.ID, period.From, period.To)
	if err != nil {
		return nil, nil, err
	}
	attachIncidents(out.Outages, incidents)

	report := &model.Report{
		Instance: m.opts.Name, Tenant: svc.Tenant,
		ServiceID: svc.ID, ServiceName: svc.Name, Period: period,
		GeneratedAt: m.Now(), ImageDigest: m.opts.ImageDigest,
		ScheduleID: schedule.ID, ScheduleVersion: schedule.Version,
		Monitors: monitorRefs,
		AST:      out.AST, Downtime: out.Downtime, Results: out.Results,
		Components: out.Components, Outages: out.Outages,
		Exclusions: out.Exclusions, Gaps: out.Gaps,
		Incidents: incidents, Objectives: out.Objectives,
		Alternates: worstSubPeriods(in, out, period),
	}
	return report, buckets, nil
}

// evidenceBuckets reads the folded intervals a report rests on.
//
// Hours everywhere, minutes where it matters. A month of hour buckets
// is a few hundred rows per monitor; a month of minutes is forty
// thousand. So the report reads the hours, and then reads the minutes
// of every hour that was not uniformly up, plus the hour the period
// ends in, which may not be folded yet. The finest reading wins in the
// arithmetic, so the result is exactly what a minute-by-minute
// computation would give, over evidence a person can actually be handed.
func (m *Monitor) evidenceBuckets(tx *store.Tx, serviceID string, from, to int64) ([]model.Bucket, error) {
	hourFrom := (from / WidthHour) * WidthHour
	rows, err := tx.Query("SELECT * FROM `buckets` WHERE service_id = " + store.Lit(serviceID) +
		" AND width_seconds = " + store.Lit(WidthHour) +
		" AND bucket_start >= " + store.Lit(hourFrom) +
		" AND bucket_start < " + store.Lit(to) + " ORDER BY bucket_start")
	if err != nil {
		return nil, err
	}

	var out []model.Bucket
	// Hours that need their minutes: the ones that were not uniformly
	// up, and the ones with no hour bucket at all.
	interesting := map[int64]bool{}
	present := map[string]bool{}
	for _, row := range rows {
		b := bucketFromRow(row)
		out = append(out, b)
		present[fmt.Sprintf("%s|%d", b.MonitorID, b.Start)] = true
		if b.Verdict != model.VerdictUp || b.Errors > 0 {
			interesting[b.Start] = true
		}
	}
	// The first and last hours of the period are always read at minute
	// resolution: they are the two that the period boundary cuts, and the
	// last one may not be folded to an hour yet.
	interesting[hourFrom] = true
	interesting[((to-1)/WidthHour)*WidthHour] = true

	starts := make([]int64, 0, len(interesting))
	for h := range interesting {
		starts = append(starts, h)
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })

	for _, h := range starts {
		minutes, err := tx.Query("SELECT * FROM `buckets` WHERE service_id = " + store.Lit(serviceID) +
			" AND width_seconds = " + store.Lit(WidthMinute) +
			" AND bucket_start >= " + store.Lit(h) +
			" AND bucket_start < " + store.Lit(h+WidthHour) + " ORDER BY bucket_start")
		if err != nil {
			return nil, err
		}
		for _, row := range minutes {
			out = append(out, bucketFromRow(row))
		}
	}

	// Hours with unfolded minutes at the end of the period are covered
	// by the minute pass above; anything still missing is a coverage gap
	// and is reported as one rather than assumed to have been up.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].MonitorID != out[j].MonitorID {
			return out[i].MonitorID < out[j].MonitorID
		}
		if out[i].Width != out[j].Width {
			return out[i].Width < out[j].Width
		}
		return out[i].Start < out[j].Start
	})
	return out, nil
}

// outageProofs attaches inclusion proofs for the folded intervals
// inside declared outages, bounded so a long outage does not produce an
// unusable document.
func (m *Monitor) outageProofs(tx *store.Tx, r *model.Report) ([]model.EvidenceBundle, error) {
	const maxProofs = 120
	var out []model.EvidenceBundle
	for _, o := range r.Outages {
		for _, b := range r.Evidence.Buckets {
			if b.ComponentID != o.ComponentID || b.Width != WidthMinute {
				continue
			}
			if b.Start < o.From || b.Start >= o.To || b.Verdict != model.VerdictDown {
				continue
			}
			bundle, err := m.evidence(tx, "buckets", []any{b.MonitorID, b.Width, b.Start},
				fmt.Sprintf("the readings folded for %s over the minute beginning %d", b.MonitorID, b.Start))
			if err != nil {
				return nil, err
			}
			out = append(out, *bundle)
			if len(out) >= maxProofs {
				return out, nil
			}
		}
	}
	return out, nil
}

// worstSubPeriods answers the question a reporting period can otherwise
// hide. The same eight hours of downtime is 95.2% on the week and 99.6%
// on the quarter, so a monthly report states the worst day and the
// worst week inside it as well as the month's own figure.
func worstSubPeriods(in availability.Input, out availability.Output, period model.Period) []model.Alternate {
	if period.To-period.From <= 24*3600 {
		return nil
	}
	loc, err := time.LoadLocation(period.Timezone)
	if err != nil {
		loc = time.UTC
	}
	var alternates []model.Alternate
	for _, span := range []struct {
		label string
		size  int64
	}{{"worst day", 24 * 3600}, {"worst week", 7 * 24 * 3600}} {
		if period.To-period.From <= span.size {
			continue
		}
		worst := int64(availability.PPM)
		var wFrom, wTo int64
		for start := period.From; start < period.To; start += 24 * 3600 {
			end := start + span.size
			if end > period.To {
				end = period.To
			}
			window := []model.Interval{{From: start, To: end}}
			ast := availability.Total(availability.Intersect(in.Scheduled, window))
			if ast == 0 {
				continue
			}
			var down int64
			for _, o := range out.Outages {
				down += availability.Total(availability.Intersect(
					[]model.Interval{{From: o.From, To: o.To}}, window))
			}
			if ppm := availability.Availability(ast, down); ppm < worst {
				worst, wFrom, wTo = ppm, start, end
			}
		}
		if wTo > wFrom {
			label := fmt.Sprintf("%s (%s)", span.label, time.Unix(wFrom, 0).In(loc).Format("2 January"))
			alternates = append(alternates, model.Alternate{
				Label: label, From: wFrom, To: wTo, AvailabilityPPM: worst,
			})
		}
	}
	return alternates
}

func exclusionReason(w model.MaintenanceWindow, svc *model.Service) string {
	if w.Excluded {
		return fmt.Sprintf("planned maintenance declared %s in advance", humanDuration(w.LeadTime))
	}
	if w.Class != model.ClassPlannedMaintenance {
		return fmt.Sprintf("recorded as %s; the agreement does not exclude it", w.Class)
	}
	lead := svc.MaintenanceLeadTime
	if w.LeadTime < 0 {
		return fmt.Sprintf("declared %s after it began, so it stays in the agreed service time",
			humanDuration(-w.LeadTime))
	}
	return fmt.Sprintf("declared %s ahead, short of the %s this service requires",
		humanDuration(w.LeadTime), humanDuration(lead))
}

func humanDuration(seconds int64) string {
	switch {
	case seconds >= 86400:
		return fmt.Sprintf("%d days", seconds/86400)
	case seconds >= 3600:
		return fmt.Sprintf("%d hours", seconds/3600)
	case seconds >= 60:
		return fmt.Sprintf("%d minutes", seconds/60)
	default:
		return fmt.Sprintf("%d seconds", seconds)
	}
}

func attachIncidents(outages []model.Outage, incidents []model.Incident) {
	for i := range outages {
		for _, inc := range incidents {
			if inc.OpenedAt <= outages[i].To && (inc.ResolvedAt == 0 || inc.ResolvedAt >= outages[i].From) {
				for _, c := range inc.Components {
					if c == outages[i].ComponentID {
						outages[i].IncidentID = inc.ID
					}
				}
			}
		}
	}
}

func resolvePeriod(req ReportRequest, svc *model.Service) (model.Period, error) {
	if req.From > 0 && req.To > req.From {
		return model.Period{
			Label: fmt.Sprintf("%s to %s",
				time.Unix(req.From, 0).UTC().Format("2006-01-02"),
				time.Unix(req.To, 0).UTC().Format("2006-01-02")),
			From: req.From, To: req.To, Timezone: svc.Timezone,
		}, nil
	}
	window := req.Window
	if window == "" {
		window = model.WindowCalendarMonth
	}
	at := time.Now().Unix()
	period, err := availability.Period(window, at, svc.Timezone)
	if err != nil {
		return period, err
	}
	if req.Previous {
		return availability.Previous(period, window, svc.Timezone)
	}
	return period, nil
}

// reportCore is the document without its evidence and signature: the
// bytes the ledger row commits to.
func reportCore(r *model.Report) model.Report {
	core := *r
	core.Evidence = nil
	core.KeyID = ""
	core.Algorithm = ""
	core.Signature = ""
	return core
}

// hashBuckets is the commitment to the exact readings the arithmetic
// used.
func hashBuckets(buckets []model.Bucket) string {
	body, err := canon.Marshal(buckets)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("privasys-monitor/report-evidence/v1"), body...))
	return hex.EncodeToString(sum[:])
}

// SignReport signs a report in place. The signature covers the whole
// document, evidence included, so a friendlier set of readings cannot
// be substituted afterwards.
func SignReport(signer ed25519.PrivateKey, keyID string, r *model.Report) error {
	r.KeyID = keyID
	r.Algorithm = "ed25519"
	r.Signature = ""
	body, err := canon.Marshal(r)
	if err != nil {
		return err
	}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, body))
	return nil
}

// VerifyReportSignature checks a report against a public key.
func VerifyReportSignature(pub ed25519.PublicKey, r *model.Report) error {
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("report: signature: %w", err)
	}
	unsigned := *r
	unsigned.Signature = ""
	body, err := canon.Marshal(&unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sig) {
		return fmt.Errorf("report: the signature does not verify")
	}
	return nil
}

// ReportCoreBytes renders the bytes a report row commits to, so a
// verifier can compare a document against the row it was recorded in.
func ReportCoreBytes(r *model.Report) ([]byte, error) {
	return canon.Marshal(reportCore(r))
}

// EvidenceHash exposes the commitment over a set of folded readings.
func EvidenceHash(buckets []model.Bucket) string { return hashBuckets(buckets) }

// Reports lists a service's reports, newest first.
func (m *Monitor) Reports(p *auth.Principal, serviceID string, limit int) ([]model.Report, error) {
	if !p.Can(auth.PermReports) && !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read reports", p.Acting)
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	var out []model.Report
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `reports` WHERE service_id = " + store.Lit(serviceID) +
			" ORDER BY period_from DESC LIMIT " + store.Lit(int64(limit)))
		if err != nil {
			return err
		}
		for _, row := range rows {
			var r model.Report
			if raw := row.Bytes("document"); len(raw) > 0 {
				if err := json.Unmarshal(raw, &r); err != nil {
					return err
				}
			}
			out = append(out, r)
		}
		return nil
	})
	return out, err
}

// Report reads one recorded report and re-attaches its evidence.
func (m *Monitor) Report(p *auth.Principal, id string) (*model.Report, error) {
	if !p.Can(auth.PermReports) && !p.Can(auth.PermExplorer) {
		return nil, fmt.Errorf("%s may not read reports", p.Acting)
	}
	var out *model.Report
	err := m.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT * FROM `reports` WHERE id = " + store.Lit(id))
		if err != nil || row == nil {
			return err
		}
		var r model.Report
		if raw := row.Bytes("document"); len(raw) > 0 {
			if err := json.Unmarshal(raw, &r); err != nil {
				return err
			}
		}
		// The readings come back from the row, not from a fresh scan: a
		// report reissued months later has to carry the evidence it was
		// issued with, or its hash stops matching and the document stops
		// being checkable.
		var buckets []model.Bucket
		if raw := row.Bytes("evidence"); len(raw) > 0 {
			if err := json.Unmarshal(raw, &buckets); err != nil {
				return err
			}
		}
		anchor, err := m.anchorCurrentState(tx)
		if err != nil {
			return err
		}
		root, version := tx.Root()
		r.Evidence = &model.ReportEvidence{
			Root: root, Version: version, Checkpoint: anchor,
			EvidenceHash: row.Str("evidence_hash"), Buckets: buckets,
		}
		proof, err := m.evidence(tx, "reports", []any{id}, "the report "+id+" as it was recorded")
		if err != nil {
			return err
		}
		r.Evidence.Proofs = []model.EvidenceBundle{*proof}
		if err := SignReport(m.mat.Signer, m.mat.KeyID, &r); err != nil {
			return err
		}
		out = &r
		return nil
	})
	return out, err
}
