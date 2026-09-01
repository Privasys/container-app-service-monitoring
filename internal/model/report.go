// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package model

// The SLA report.
//
// A report is not a rendering of a number held somewhere else. It is a
// transaction: the monitor writes a report row into the ledger, and the
// row commits to a hash over the exact evidence the arithmetic used. So
// a reader is handed one inclusion proof, one signed checkpoint, and a
// set of folded readings, and can recompute the whole document offline.
// The verifier does exactly that, and it also checks the direction that
// matters in a dispute: every interval the evidence shows as down has
// to appear in the report as downtime.

// Period is the interval a report covers, with the timezone the
// calendar boundaries were taken in.
type Period struct {
	Label    string `json:"label"`
	From     int64  `json:"from"`
	To       int64  `json:"to"`
	Timezone string `json:"timezone"`
}

// Report is the signed SLA document.
type Report struct {
	ID          string `json:"id"`
	Instance    string `json:"instance"`
	Tenant      string `json:"tenant"`
	ServiceID   string `json:"service_id"`
	ServiceName string `json:"service_name"`
	Period      Period `json:"period"`
	GeneratedAt int64  `json:"generated_at"`
	// ImageDigest is the measurement of the build that produced the
	// document. A reader who verified the RA-TLS certificate has already
	// verified a hardware quote over this value.
	ImageDigest string `json:"image_digest,omitempty"`

	// Definitions in force. A report names what it measured, not just
	// what it measured it to be.
	ScheduleID      string       `json:"schedule_id"`
	ScheduleVersion uint64       `json:"schedule_version"`
	Monitors        []MonitorRef `json:"monitors"`

	AST        ASTSummary        `json:"ast"`
	Downtime   DowntimeSummary   `json:"downtime"`
	Results    Results           `json:"results"`
	Components []ComponentResult `json:"components"`
	Outages    []Outage          `json:"outages"`
	Exclusions []Exclusion       `json:"exclusions"`
	Gaps       []Gap             `json:"gaps"`
	Incidents  []Incident        `json:"incidents,omitempty"`
	Objectives []ObjectiveResult `json:"objectives"`
	// Alternates show the same period's outages at other cadences, so a
	// reporting period cannot silently flatter the figure.
	Alternates []Alternate `json:"alternates,omitempty"`

	Evidence *ReportEvidence `json:"evidence,omitempty"`

	KeyID     string `json:"key_id"`
	Algorithm string `json:"alg"`
	Signature string `json:"signature"`
}

// MonitorRef names a monitor definition by the version that was in
// force during the period.
type MonitorRef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     uint64 `json:"version"`
	ComponentID string `json:"component_id"`
	IntervalSec int    `json:"interval_seconds"`
}

// ASTSummary is the agreed service time arithmetic.
type ASTSummary struct {
	// Scheduled is the seconds inside the agreed service time before
	// exclusions.
	Scheduled int64 `json:"scheduled_seconds"`
	// Excluded is the seconds removed by applied exclusions.
	Excluded int64 `json:"excluded_seconds"`
	// Net is what the availability denominator actually is.
	Net int64 `json:"net_seconds"`
	// Intervals is the scheduled series itself, so a verifier can add it
	// up rather than take the total on trust.
	Intervals []Interval `json:"intervals"`
}

// Interval is a half-open [from, to) range of Unix seconds.
type Interval struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// Seconds is the interval's length.
func (i Interval) Seconds() int64 {
	if i.To <= i.From {
		return 0
	}
	return i.To - i.From
}

// DowntimeSummary is the reliability side of the report: frequency and
// duration, reported next to the percentage because they buy different
// remedies.
type DowntimeSummary struct {
	Seconds int64 `json:"seconds"`
	Outages int   `json:"outages"`
	// MTBF and MTRS are in seconds, zero when there is nothing to
	// average.
	MTBF int64 `json:"mtbf_seconds"`
	MTRS int64 `json:"mtrs_seconds"`
	// LongestSeconds is the worst single interruption.
	LongestSeconds int64 `json:"longest_seconds"`
}

// Results are the headline figures, in parts per million.
type Results struct {
	AvailabilityPPM     int64 `json:"availability_ppm"`
	UserAvailabilityPPM int64 `json:"user_availability_ppm"`
	CoveragePPM         int64 `json:"coverage_ppm"`
	// PotentialUserSeconds and UserOutageSeconds are the user-weighted
	// numerator and denominator, published so the second formula can be
	// checked as easily as the first.
	PotentialUserSeconds int64 `json:"potential_user_seconds"`
	UserOutageSeconds    int64 `json:"user_outage_seconds"`
	// ObservedSeconds is the part of net agreed service time for which a
	// reading exists.
	ObservedSeconds int64 `json:"observed_seconds"`
}

// ComponentResult is the per-component breakdown.
type ComponentResult struct {
	ComponentID string `json:"component_id"`
	Name        string `json:"name"`
	UserWeight  int64  `json:"user_weight"`
	// Rollup is the rule that turned the component's monitors into one
	// verdict. It travels with the report because the verifier has to
	// apply the same rule to reach the same answer.
	Rollup          string `json:"rollup"`
	DowntimeSeconds int64  `json:"downtime_seconds"`
	AvailabilityPPM int64  `json:"availability_ppm"`
	CoveragePPM     int64  `json:"coverage_ppm"`
	Outages         int    `json:"outages"`
}

// Outage is one interruption as the report counts it.
type Outage struct {
	ComponentID string `json:"component_id"`
	From        int64  `json:"from"`
	To          int64  `json:"to"`
	Seconds     int64  `json:"seconds"`
	IncidentID  string `json:"incident_id,omitempty"`
	// Samples names a few of the readings that establish it. A dispute
	// about a specific minute starts here.
	Samples []string `json:"samples,omitempty"`
}

// Exclusion is a declared window and what the report did with it.
type Exclusion struct {
	WindowID   string `json:"window_id"`
	Class      string `json:"class"`
	Title      string `json:"title"`
	DeclaredAt int64  `json:"declared_at"`
	LeadTime   int64  `json:"lead_time"`
	From       int64  `json:"from"`
	To         int64  `json:"to"`
	// Seconds is the part of the window that intersected agreed service
	// time.
	Seconds int64 `json:"seconds"`
	// Applied says whether it was removed from the denominator. A window
	// declared after the fact appears here with applied false and its
	// lead time visible, which is the whole reason the field exists.
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
	TxID    string `json:"txid,omitempty"`
}

// Gap is an interval of agreed service time with no reading.
type Gap struct {
	From    int64  `json:"from"`
	To      int64  `json:"to"`
	Seconds int64  `json:"seconds"`
	Cause   string `json:"cause,omitempty"`
}

// Objective results.
const (
	ObjectiveMet           = "met"
	ObjectiveBreached      = "breached"
	ObjectiveIndeterminate = "indeterminate"
)

// ObjectiveResult is one objective evaluated over the period.
type ObjectiveResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Metric      string `json:"metric"`
	Window      string `json:"window"`
	TargetPPM   int64  `json:"target_ppm"`
	AchievedPPM int64  `json:"achieved_ppm"`
	Result      string `json:"result"`
	// Reason explains an indeterminate result, which is a real answer
	// and not a missing one.
	Reason        string `json:"reason,omitempty"`
	CreditPercent int    `json:"credit_percent,omitempty"`
}

// Alternate is the same period's downtime seen at another cadence.
type Alternate struct {
	Label           string `json:"label"`
	From            int64  `json:"from"`
	To              int64  `json:"to"`
	AvailabilityPPM int64  `json:"availability_ppm"`
}

// ReportEvidence is what makes the document checkable. The evidence
// hash is committed to the ledger with the report row, so one inclusion
// proof covers the whole set.
type ReportEvidence struct {
	Root         string            `json:"root"`
	Version      uint64            `json:"version"`
	Checkpoint   *SignedCheckpoint `json:"checkpoint,omitempty"`
	EvidenceHash string            `json:"evidence_hash"`
	// Buckets are the folded readings the arithmetic used, dense across
	// the period at the stated width.
	Buckets []Bucket `json:"buckets"`
	// Proofs carry inclusion proofs for the report row and, when asked
	// for, for the buckets inside declared outages: the minutes a
	// dispute is actually about.
	Proofs []EvidenceBundle `json:"proofs,omitempty"`
}
