// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package model

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Verdicts. A sample is one of these, and so is the state a monitor,
// component or service is in.
const (
	VerdictUp       = "up"
	VerdictDegraded = "degraded"
	VerdictDown     = "down"
	// VerdictError means the monitor could not take a reading: its own
	// configuration was wrong, a secret was missing, the step could not
	// be built. It is never counted as downtime of the watched service.
	// It is counted against monitoring coverage, which is the honest
	// place for it.
	VerdictError = "error"
)

// Verdicts in order of severity, worst last.
var verdictRank = map[string]int{VerdictUp: 0, VerdictError: 1, VerdictDegraded: 2, VerdictDown: 3}

// WorseVerdict returns the more severe of two verdicts.
func WorseVerdict(a, b string) string {
	if verdictRank[b] > verdictRank[a] {
		return b
	}
	return a
}

// Component rollup rules.
const (
	RollupAll      = "all"      // down only when every child is down
	RollupAny      = "any"      // down as soon as any child is down
	RollupMajority = "majority" // down when more than half are down
)

// Exclusion classes. The class decides whether an interval leaves the
// agreed service time, and every exclusion carries the moment it was
// declared, so a window entered after the outage reads as exactly that.
const (
	ClassPlannedMaintenance = "planned_maintenance"
	ClassThirdParty         = "third_party"
	ClassForceMajeure       = "force_majeure"
	ClassCustomerCaused     = "customer_caused"
	ClassMonitoringFault    = "monitoring_fault"
)

// ExclusionClasses lists the classes a maintenance window may declare.
var ExclusionClasses = []string{
	ClassPlannedMaintenance, ClassThirdParty, ClassForceMajeure,
	ClassCustomerCaused, ClassMonitoringFault,
}

// Incident statuses, in the order a responder moves through them.
const (
	IncidentInvestigating = "investigating"
	IncidentIdentified    = "identified"
	IncidentMonitoring    = "monitoring"
	IncidentResolved      = "resolved"
)

// IncidentStatuses lists them in order.
var IncidentStatuses = []string{
	IncidentInvestigating, IncidentIdentified, IncidentMonitoring, IncidentResolved,
}

// Impact levels, matching what a status page shows.
const (
	ImpactNone     = "none"
	ImpactMinor    = "minor"
	ImpactMajor    = "major"
	ImpactCritical = "critical"
)

// Service is the thing an SLA is about.
type Service struct {
	ID          string `json:"id"`
	Tenant      string `json:"tenant"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	Timezone    string `json:"timezone"`
	ScheduleID  string `json:"schedule_id"`
	// Visibility decides whether the status page serves this service to
	// anonymous readers. Making a service private is a signed
	// transaction, so hiding an incident is itself on the record.
	Visibility string `json:"visibility"`
	// MaintenanceLeadTime is how far ahead a planned window must be
	// declared to be excluded from agreed service time.
	MaintenanceLeadTime int64 `json:"maintenance_lead_time"`
	// CoverageFloorPPM is the monitoring coverage below which an
	// objective is reported as indeterminate rather than met.
	CoverageFloorPPM int64  `json:"coverage_floor_ppm"`
	CallbackURL      string `json:"callback_url,omitempty"`
	CreatedAt        int64  `json:"created_at"`
	UpdatedAt        int64  `json:"updated_at"`
}

// Visibility values.
const (
	VisibilityPublic  = "public"
	VisibilityPrivate = "private"
)

// Component is a user-visible part of a service: the tree the status
// page renders.
type Component struct {
	ID          string `json:"id"`
	ServiceID   string `json:"service_id"`
	ParentID    string `json:"parent_id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// UserWeight is the population this component serves. It is an
	// integer count, not a fraction: two hours affecting one back-office
	// function is not two hours affecting the whole call centre, and the
	// report should not pretend it is.
	UserWeight int64  `json:"user_weight"`
	Rollup     string `json:"rollup"`
	Position   int64  `json:"position"`
	Showcase   bool   `json:"showcase"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

// Monitor is a scheduled journey bound to one component.
//
// Monitors are versioned rather than edited in place. A report names
// the definition that was in force when the readings were taken, which
// is the difference between "we measured 99.95%" and "we measured
// 99.95% of something, and here is exactly what".
type Monitor struct {
	ID          string `json:"id"`
	ServiceID   string `json:"service_id"`
	ComponentID string `json:"component_id"`
	Name        string `json:"name"`
	Version     uint64 `json:"version"`
	Enabled     bool   `json:"enabled"`
	// IntervalSeconds is how often the journey runs; FloorInterval is
	// the smallest value accepted.
	IntervalSeconds int `json:"interval_seconds"`
	TimeoutSeconds  int `json:"timeout_seconds"`
	// FailureThreshold consecutive failing runs mark the monitor down;
	// RecoveryThreshold consecutive passes bring it back up.
	FailureThreshold  int `json:"failure_threshold"`
	RecoveryThreshold int `json:"recovery_threshold"`
	// LatencyBudgetMs, when set, raises `degraded` on a journey that
	// completed but took longer than the budget.
	LatencyBudgetMs int    `json:"latency_budget_ms"`
	Steps           []Step `json:"steps"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
}

// Scheduling bounds.
const (
	FloorInterval   = 10
	DefaultInterval = 60
	DefaultTimeout  = 30
	MaxSteps        = 40
)

// Step kinds.
const (
	StepHTTP    = "http"
	StepAssert  = "assert"
	StepExtract = "extract"
	StepSleep   = "sleep"
)

// Step is one interaction in a journey.
type Step struct {
	Name string `json:"name"`
	Kind string `json:"kind"`

	// Cleanup steps run even when an earlier step failed, so a monitor
	// that creates an order deletes it again. A failing cleanup step is
	// reported but does not, on its own, mark the service down: the
	// customer's service answered, our housekeeping did not.
	Cleanup bool `json:"cleanup,omitempty"`

	// http
	Method          string            `json:"method,omitempty"`
	URL             string            `json:"url,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	ExpectStatus    []int             `json:"expect_status,omitempty"`
	FollowRedirects bool              `json:"follow_redirects,omitempty"`

	// assert
	Assertions []Assertion `json:"assertions,omitempty"`

	// extract
	Extractions []Extraction `json:"extractions,omitempty"`

	// sleep
	SleepMs int `json:"sleep_ms,omitempty"`
}

// Assertion operators.
const (
	OpEq       = "eq"
	OpNe       = "ne"
	OpLt       = "lt"
	OpLte      = "lte"
	OpGt       = "gt"
	OpGte      = "gte"
	OpContains = "contains"
	OpMatches  = "matches"
	OpExists   = "exists"
	OpAbsent   = "absent"
)

// Assertion sources.
const (
	SrcStatus   = "status"
	SrcLatency  = "latency_ms"
	SrcHeader   = "header"
	SrcBody     = "body"
	SrcJSON     = "json"
	SrcVariable = "var"
)

// Assertion is one check over the response of the step it belongs to,
// or over a variable extracted earlier.
type Assertion struct {
	Source string `json:"source"`
	// Target is the header name, JSONPath or variable name the source
	// needs. Unused for status and latency.
	Target string `json:"target,omitempty"`
	Op     string `json:"op"`
	Value  string `json:"value,omitempty"`
	// Message, when set, is what the sample records instead of the
	// generated description. Useful for saying what the assertion means
	// to the business rather than what it compares.
	Message string `json:"message,omitempty"`
}

// Extraction binds a value out of a response into a variable later
// steps can template.
type Extraction struct {
	Var    string `json:"var"`
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	// Secret marks the extracted value as sensitive. It is then redacted
	// from every capture exactly like a configured secret, which matters
	// for session tokens the login step returns.
	Secret bool `json:"secret,omitempty"`
}

// Validate checks a monitor definition before it is accepted. The
// journey engine assumes a valid definition; the API is where a bad one
// is refused.
func (m *Monitor) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return errors.New("monitor: a name is required")
	}
	if m.ComponentID == "" {
		return errors.New("monitor: a component is required")
	}
	if m.IntervalSeconds < FloorInterval {
		return fmt.Errorf("monitor: the interval floor is %ds", FloorInterval)
	}
	if m.TimeoutSeconds <= 0 || m.TimeoutSeconds > m.IntervalSeconds {
		return errors.New("monitor: the timeout must be positive and no longer than the interval")
	}
	if m.FailureThreshold < 1 || m.RecoveryThreshold < 1 {
		return errors.New("monitor: thresholds must be at least 1")
	}
	if len(m.Steps) == 0 {
		return errors.New("monitor: a journey needs at least one step")
	}
	if len(m.Steps) > MaxSteps {
		return fmt.Errorf("monitor: %d steps, the limit is %d", len(m.Steps), MaxSteps)
	}
	seen := map[string]bool{}
	requests := 0
	for i := range m.Steps {
		s := &m.Steps[i]
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("monitor: step %d has no name", i+1)
		}
		if seen[s.Name] {
			return fmt.Errorf("monitor: two steps are named %q", s.Name)
		}
		seen[s.Name] = true
		if err := s.validate(); err != nil {
			return fmt.Errorf("monitor: step %q: %w", s.Name, err)
		}
		if s.Kind == StepHTTP {
			requests++
		}
	}
	if requests == 0 {
		return errors.New("monitor: a journey needs at least one request step")
	}
	return nil
}

func (s *Step) validate() error {
	switch s.Kind {
	case StepHTTP:
		if s.URL == "" {
			return errors.New("a request step needs a URL")
		}
		// The URL may carry template placeholders, which are not valid
		// URL syntax until they are resolved. Parse what is outside them
		// by blanking the placeholders first.
		if u, err := url.Parse(blankTemplates(s.URL)); err != nil {
			return fmt.Errorf("URL: %w", err)
		} else if u.Scheme != "https" && u.Scheme != "http" {
			return fmt.Errorf("URL scheme %q is not http or https", u.Scheme)
		}
		if s.Method == "" {
			return errors.New("a request step needs a method")
		}
	case StepAssert:
		if len(s.Assertions) == 0 {
			return errors.New("an assert step needs at least one assertion")
		}
	case StepExtract:
		if len(s.Extractions) == 0 {
			return errors.New("an extract step needs at least one extraction")
		}
	case StepSleep:
		if s.SleepMs <= 0 || s.SleepMs > 60_000 {
			return errors.New("a sleep step waits between 1ms and 60s")
		}
	default:
		return fmt.Errorf("unknown step kind %q", s.Kind)
	}
	for _, a := range s.Assertions {
		if err := a.validate(); err != nil {
			return err
		}
	}
	for _, e := range s.Extractions {
		if e.Var == "" {
			return errors.New("an extraction needs a variable name")
		}
		switch e.Source {
		case SrcJSON, SrcHeader, SrcBody, SrcStatus:
		default:
			return fmt.Errorf("unknown extraction source %q", e.Source)
		}
	}
	return nil
}

func (a *Assertion) validate() error {
	switch a.Source {
	case SrcStatus, SrcLatency, SrcHeader, SrcBody, SrcJSON, SrcVariable:
	default:
		return fmt.Errorf("unknown assertion source %q", a.Source)
	}
	switch a.Op {
	case OpEq, OpNe, OpLt, OpLte, OpGt, OpGte, OpContains, OpMatches, OpExists, OpAbsent:
	default:
		return fmt.Errorf("unknown assertion operator %q", a.Op)
	}
	if (a.Source == SrcHeader || a.Source == SrcJSON || a.Source == SrcVariable) && a.Target == "" {
		return fmt.Errorf("an assertion on %s needs a target", a.Source)
	}
	return nil
}

// blankTemplates replaces {{ ... }} placeholders with a benign token so
// a templated URL can be syntax-checked before it is resolved.
func blankTemplates(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString("x")
		s = s[i+j+2:]
	}
}

// Objective is a service-level objective evaluated over a period.
type Objective struct {
	ID        string `json:"id"`
	ServiceID string `json:"service_id"`
	Name      string `json:"name"`
	// Metric is availability, user_availability or latency_p95.
	Metric string `json:"metric"`
	// TargetPPM is the target in parts per million: 99.9% is 999000.
	// Integers throughout, because the SQL layer has no DECIMAL and a
	// contractual threshold is the last place to accept binary floating
	// point rounding.
	TargetPPM int64 `json:"target_ppm"`
	// Window is calendar_month, calendar_quarter, calendar_week or
	// rolling_30d.
	Window string `json:"window"`
	// LatencyBudgetMs applies to the latency_p95 metric.
	LatencyBudgetMs int          `json:"latency_budget_ms,omitempty"`
	Credits         []CreditBand `json:"credits,omitempty"`
	CreatedAt       int64        `json:"created_at"`
	UpdatedAt       int64        `json:"updated_at"`
}

// Objective metrics.
const (
	MetricAvailability     = "availability"
	MetricUserAvailability = "user_availability"
	MetricLatencyP95       = "latency_p95"
)

// Objective windows.
const (
	WindowCalendarMonth   = "calendar_month"
	WindowCalendarQuarter = "calendar_quarter"
	WindowCalendarWeek    = "calendar_week"
	WindowRolling30d      = "rolling_30d"
)

// CreditBand maps a shortfall to a service credit.
type CreditBand struct {
	// BelowPPM is the achieved availability under which this band
	// applies, exclusive of the band below it.
	BelowPPM      int64 `json:"below_ppm"`
	CreditPercent int   `json:"credit_percent"`
}

// Schedule is an agreed service time definition: weekly windows plus
// calendar exceptions, in the service's timezone.
type Schedule struct {
	ID         string              `json:"id"`
	ServiceID  string              `json:"service_id"`
	Name       string              `json:"name"`
	Timezone   string              `json:"timezone"`
	Version    uint64              `json:"version"`
	Windows    []ScheduleWindow    `json:"windows"`
	Exceptions []ScheduleException `json:"exceptions,omitempty"`
	CreatedAt  int64               `json:"created_at"`
	UpdatedAt  int64               `json:"updated_at"`
}

// ScheduleWindow is one recurring weekly window. Minutes are from
// midnight local time; a window that ends at 1440 runs to midnight.
type ScheduleWindow struct {
	// Weekday is 0 for Sunday through 6 for Saturday, matching
	// time.Weekday.
	Weekday  int `json:"weekday"`
	StartMin int `json:"start_min"`
	EndMin   int `json:"end_min"`
}

// ScheduleException adjusts a single date: a public holiday removed
// from agreed service time, or an agreed extra window added.
type ScheduleException struct {
	// Date is YYYY-MM-DD in the schedule's timezone.
	Date string `json:"date"`
	// Include is false for a date removed from agreed service time and
	// true for one added.
	Include  bool   `json:"include"`
	StartMin int    `json:"start_min,omitempty"`
	EndMin   int    `json:"end_min,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// AlwaysOn is the 24x7 schedule, which is a choice like any other and
// not the assumption.
func AlwaysOn(id, serviceID, timezone string, now int64) Schedule {
	s := Schedule{
		ID: id, ServiceID: serviceID, Name: "24x7", Timezone: timezone,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	for d := 0; d < 7; d++ {
		s.Windows = append(s.Windows, ScheduleWindow{Weekday: d, StartMin: 0, EndMin: 1440})
	}
	return s
}

// MaintenanceWindow is a declared interval with a class that decides
// whether it leaves the agreed service time.
type MaintenanceWindow struct {
	ID          string   `json:"id"`
	ServiceID   string   `json:"service_id"`
	Components  []string `json:"components,omitempty"`
	Class       string   `json:"class"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	// DeclaredAt is when the window entered the record, not when it
	// starts. The gap between the two is the whole point.
	DeclaredAt int64 `json:"declared_at"`
	StartsAt   int64 `json:"starts_at"`
	EndsAt     int64 `json:"ends_at"`
	// Excluded is decided once, at declaration, from the class and the
	// lead time. A window declared after the fact is recorded, shown and
	// reported, and does not remove the interval from agreed service
	// time.
	Excluded bool `json:"excluded"`
	// LeadTime is StartsAt minus DeclaredAt, kept so a report can state
	// it without recomputing from fields that may have been corrected.
	LeadTime  int64  `json:"lead_time"`
	Published bool   `json:"published"`
	Cancelled bool   `json:"cancelled"`
	TxID      string `json:"txid"`
}

// Active reports whether the window covers an instant.
func (w *MaintenanceWindow) Active(at int64) bool {
	return !w.Cancelled && at >= w.StartsAt && at < w.EndsAt
}

// Incident is an interruption, opened automatically by detection or by
// a responder.
type Incident struct {
	ID         string   `json:"id"`
	ServiceID  string   `json:"service_id"`
	Components []string `json:"components,omitempty"`
	Title      string   `json:"title"`
	Impact     string   `json:"impact"`
	Status     string   `json:"status"`
	OpenedAt   int64    `json:"opened_at"`
	ResolvedAt int64    `json:"resolved_at,omitempty"`
	// Auto marks an incident the monitor opened from its own readings.
	Auto bool `json:"auto"`
	// TriggerSamples names the samples that opened it, so the narrative
	// and the evidence are one click apart.
	TriggerSamples []string         `json:"trigger_samples,omitempty"`
	Updates        []IncidentUpdate `json:"updates,omitempty"`
}

// IncidentUpdate is one entry in an incident's timeline.
type IncidentUpdate struct {
	ID         string `json:"id"`
	IncidentID string `json:"incident_id"`
	Status     string `json:"status"`
	Body       string `json:"body"`
	CreatedAt  int64  `json:"created_at"`
	Author     Author `json:"author"`
	TxID       string `json:"txid"`
}

// Sample is one execution of a journey: the atom of the availability
// record.
type Sample struct {
	ID             string `json:"id"`
	MonitorID      string `json:"monitor_id"`
	MonitorVersion uint64 `json:"monitor_version"`
	ComponentID    string `json:"component_id"`
	ServiceID      string `json:"service_id"`
	// Vantage names where the reading was taken from. One instance today;
	// the field exists so a quorum of vantage points needs no migration.
	Vantage    string `json:"vantage"`
	StartedAt  int64  `json:"started_at"`
	DurationMs int    `json:"duration_ms"`
	Verdict    string `json:"verdict"`
	FailedStep string `json:"failed_step,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
	// Detail is the human reason, already redacted.
	Detail string `json:"detail,omitempty"`
	// Steps carries the per-step outcome, redacted.
	Steps []StepResult `json:"steps,omitempty"`
	// Manual marks an out-of-band run. Manual samples are recorded and
	// visible, and are never folded into the availability series.
	Manual bool `json:"manual"`
	// InMaintenance marks a sample taken during a declared window.
	// Observation never stops; only the arithmetic changes.
	InMaintenance bool `json:"in_maintenance"`
}

// StepResult is what one step did, with secrets already removed.
type StepResult struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Status     int    `json:"status,omitempty"`
	DurationMs int    `json:"duration_ms"`
	OK         bool   `json:"ok"`
	Detail     string `json:"detail,omitempty"`
	// Capture is a redacted head of the response body, kept so a
	// responder can see what the service actually said.
	Capture string `json:"capture,omitempty"`
}

// Error classes, so a report can separate "the service failed" from
// "we could not ask".
const (
	ErrClassAssertion = "assertion"
	ErrClassStatus    = "status"
	ErrClassTimeout   = "timeout"
	ErrClassConnect   = "connect"
	ErrClassTLS       = "tls"
	ErrClassDNS       = "dns"
	ErrClassRedaction = "redaction"
	ErrClassPolicy    = "policy"
	ErrClassInternal  = "internal"
)

// Bucket is a folded interval of samples for one monitor.
type Bucket struct {
	MonitorID   string `json:"monitor_id"`
	ComponentID string `json:"component_id"`
	ServiceID   string `json:"service_id"`
	// Start is the first second of the interval, UTC.
	Start         int64  `json:"start"`
	Width         int64  `json:"width"`
	Up            int    `json:"up"`
	Degraded      int    `json:"degraded"`
	Down          int    `json:"down"`
	Errors        int    `json:"errors"`
	InMaintenance int    `json:"in_maintenance"`
	LatencyP50    int    `json:"latency_p50"`
	LatencyP95    int    `json:"latency_p95"`
	LatencyMax    int    `json:"latency_max"`
	Verdict       string `json:"verdict"`
}

// Total is the number of readings folded into the bucket.
func (b *Bucket) Total() int { return b.Up + b.Degraded + b.Down + b.Errors }

// SecretMeta is everything the record holds about a credential. The
// value is not part of it and never has been.
type SecretMeta struct {
	Name string `json:"name"`
	// Hosts is the binding: the templating engine refuses to place this
	// secret in a request to any other host. Repointing a monitor
	// therefore cannot exfiltrate the credential, and the attempt is a
	// refused, recorded event.
	Hosts       []string `json:"hosts"`
	Description string   `json:"description,omitempty"`
	// Fingerprint is a keyed hash of the value, which lets an operator
	// confirm a rotation actually changed something without the value
	// being readable.
	Fingerprint string `json:"fingerprint"`
	CreatedAt   int64  `json:"created_at"`
	RotatedAt   int64  `json:"rotated_at,omitempty"`
	DestroyedAt int64  `json:"destroyed_at,omitempty"`
	UsedAt      int64  `json:"used_at,omitempty"`
}

// Destroyed reports whether the secret's key has been destroyed.
func (s *SecretMeta) Destroyed() bool { return s.DestroyedAt > 0 }

// RuntimeEvent records something that happened to the monitor itself.
// A restart is a first-class, visible event because a gap in the record
// is otherwise indistinguishable from a quiet period, and a monitor
// that was down cannot certify uptime.
type RuntimeEvent struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	At          int64  `json:"at"`
	Detail      string `json:"detail,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
}

// Runtime event kinds.
const (
	EventBoot      = "boot"
	EventShutdown  = "shutdown"
	EventConfigure = "configure"
	EventGap       = "coverage_gap"
)

// State is the current position of a monitor or component, kept across
// restarts so detection does not start from nothing after a redeploy.
type State struct {
	Subject string `json:"subject"`
	Kind    string `json:"kind"`
	Verdict string `json:"verdict"`
	Since   int64  `json:"since"`
	// Consecutive counts runs of the current raw outcome, which is what
	// the failure and recovery thresholds are compared against.
	Consecutive int    `json:"consecutive"`
	Raw         string `json:"raw"`
	UpdatedAt   int64  `json:"updated_at"`
	// Flaps counts state changes in the damping window.
	Flaps      int    `json:"flaps"`
	FlapsSince int64  `json:"flaps_since"`
	IncidentID string `json:"incident_id,omitempty"`
}

// State subjects.
const (
	StateMonitor   = "monitor"
	StateComponent = "component"
	StateService   = "service"
)
