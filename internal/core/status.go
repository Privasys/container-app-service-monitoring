// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/availability"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// The status document behind the public page.
//
// It is the ordinary shape people expect: a banner, a component tree,
// ninety days of uptime, the open incidents and the maintenance that is
// coming. What is different is underneath. Every figure here is
// computed from folded readings that are ledger rows, so each one can
// be followed to an evidence bundle and checked in the reader's own
// browser, and the page states the measurement of the build that drew
// it. A status page is a marketing surface everywhere else; this one is
// an assertion somebody can test.

// Status indicators, matching what a reader expects from a status page.
const (
	IndicatorNone     = "none"
	IndicatorMinor    = "minor"
	IndicatorMajor    = "major"
	IndicatorCritical = "critical"
	IndicatorMaint    = "maintenance"
)

// Component statuses, in the vocabulary status-page consumers already
// parse.
const (
	StatusOperational      = "operational"
	StatusDegraded         = "degraded_performance"
	StatusPartialOutage    = "partial_outage"
	StatusMajorOutage      = "major_outage"
	StatusUnderMaintenance = "under_maintenance"
)

// StatusPage is the whole document.
type StatusPage struct {
	Service     string `json:"service"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	Timezone    string `json:"timezone"`
	UpdatedAt   int64  `json:"updated_at"`

	Indicator   string                    `json:"indicator"`
	Headline    string                    `json:"headline"`
	Components  []ComponentStatus         `json:"components"`
	Incidents   []model.Incident          `json:"incidents"`
	History     []model.Incident          `json:"history,omitempty"`
	Maintenance []model.MaintenanceWindow `json:"maintenance,omitempty"`

	// Attestation is what makes this page different from every other
	// status page: it names the build that produced the figures and the
	// authenticated state they were read at.
	Attestation Attestation `json:"attestation"`
}

// Attestation is the page's own provenance.
type Attestation struct {
	Instance    string `json:"instance"`
	ImageDigest string `json:"image_digest,omitempty"`
	AppID       string `json:"app_id,omitempty"`
	Root        string `json:"root"`
	Version     uint64 `json:"version"`
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"`
	Vantage     string `json:"vantage"`
}

// ComponentStatus is one row of the component tree.
type ComponentStatus struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ParentID    string `json:"parent_id,omitempty"`
	Status      string `json:"status"`
	Since       int64  `json:"since,omitempty"`
	// Days is the uptime bar: one entry per day, oldest first.
	Days []DayStatus `json:"days"`
	// UptimePPM is the availability over the days shown.
	UptimePPM int64 `json:"uptime_ppm"`
}

// DayStatus is one bar of the uptime chart.
type DayStatus struct {
	Date string `json:"date"`
	// Start is the first second of the day, in the service's timezone.
	Start int64 `json:"start"`
	// UptimePPM is the day's availability, or -1 when nothing was
	// observed. A day with no readings is drawn as unknown rather than
	// as a good day, because a monitor that was not watching did not see
	// a service that was up.
	UptimePPM int64  `json:"uptime_ppm"`
	Status    string `json:"status"`
	// DowntimeSeconds is what the bar's tooltip shows.
	DowntimeSeconds int64 `json:"downtime_seconds"`
}

// StatusDays is how much history the bars show.
const StatusDays = 90

// Status builds the document for one service.
func (m *Monitor) Status(serviceID string, now int64) (*StatusPage, error) {
	svc, err := m.Service(serviceID)
	if err != nil {
		return nil, err
	}
	if svc == nil {
		return nil, nil
	}
	components, err := m.Components(svc.ID)
	if err != nil {
		return nil, err
	}
	states, err := m.States()
	if err != nil {
		return nil, err
	}
	incidents, err := m.OpenIncidents(svc.ID)
	if err != nil {
		return nil, err
	}
	history, err := m.Incidents(svc.ID, now-StatusDays*86400, now, 25)
	if err != nil {
		return nil, err
	}
	maintenance, err := m.UpcomingMaintenance(svc.ID, now)
	if err != nil {
		return nil, err
	}

	loc, err := time.LoadLocation(svc.Timezone)
	if err != nil {
		loc = time.UTC
	}
	// Bars run to the end of today, so the last bar is the day in
	// progress rather than yesterday.
	endOfToday := startOfDay(now, loc).AddDate(0, 0, 1)
	from := endOfToday.AddDate(0, 0, -StatusDays)

	buckets, err := m.Buckets(svc.ID, WidthHour, from.Unix(), endOfToday.Unix())
	if err != nil {
		return nil, err
	}
	minutes, err := m.Buckets(svc.ID, WidthMinute, startOfDay(now, loc).Unix(), endOfToday.Unix())
	if err != nil {
		return nil, err
	}
	buckets = append(buckets, minutes...)

	byComponent := map[string][]model.Bucket{}
	for _, b := range buckets {
		byComponent[b.ComponentID] = append(byComponent[b.ComponentID], b)
	}

	inMaintenance := map[string]bool{}
	active, err := m.ActiveMaintenance(now)
	if err != nil {
		return nil, err
	}
	for _, w := range active {
		for _, c := range w.Components {
			inMaintenance[c] = true
		}
		if len(w.Components) == 0 {
			for _, c := range components {
				inMaintenance[c.ID] = true
			}
		}
	}

	page := &StatusPage{
		Service: svc.Name, Slug: svc.Slug, Description: svc.Description,
		Timezone: svc.Timezone, UpdatedAt: now,
		Incidents: incidents, Maintenance: maintenance,
	}
	for _, inc := range history {
		if inc.Status == model.IncidentResolved {
			page.History = append(page.History, inc)
		}
	}

	worst := IndicatorNone
	for _, c := range components {
		cs := ComponentStatus{
			ID: c.ID, Name: c.Name, Description: c.Description, ParentID: c.ParentID,
			Status: StatusOperational,
		}
		if st, ok := states[c.ID]; ok {
			cs.Status = statusOf(st.Verdict)
			cs.Since = st.Since
		}
		if inMaintenance[c.ID] {
			cs.Status = StatusUnderMaintenance
		}
		cs.Days, cs.UptimePPM = uptimeBars(byComponent[c.ID], c.Rollup, from, endOfToday, loc)
		page.Components = append(page.Components, cs)
		worst = worseIndicator(worst, indicatorOf(cs.Status))
	}

	page.Indicator = worst
	page.Headline = headline(worst)

	page.Attestation = Attestation{
		Instance: m.opts.Name, ImageDigest: m.opts.ImageDigest, Vantage: m.opts.Vantage,
	}
	page.Attestation.KeyID, page.Attestation.PublicKey = m.VerificationKey()
	if err := m.st.Do(func(tx *store.Tx) error {
		page.Attestation.Root, page.Attestation.Version = tx.Root()
		return nil
	}); err != nil {
		return nil, err
	}
	return page, nil
}

// uptimeBars computes one bar per day from the folded readings.
func uptimeBars(buckets []model.Bucket, rollup string, from, to time.Time, loc *time.Location) ([]DayStatus, int64) {
	var days []DayStatus
	var observedTotal, downTotal int64

	// The rollup runs once over the whole range; the days are then read
	// off the resulting intervals. Rolling up per day would give the
	// same answer more slowly, and would invite the two to drift.
	down, observed, err := componentSeriesFor(buckets, rollup)
	if err != nil {
		return nil, availability.PPM
	}

	for day := from; day.Before(to); day = day.AddDate(0, 0, 1) {
		next := day.AddDate(0, 0, 1)
		window := []model.Interval{{From: day.Unix(), To: next.Unix()}}

		dayDown := availability.Total(availability.Intersect(down, window))
		dayObserved := availability.Total(availability.Intersect(observed, window))

		bar := DayStatus{
			Date: day.In(loc).Format("2006-01-02"), Start: day.Unix(),
			DowntimeSeconds: dayDown,
		}
		if dayObserved == 0 {
			// Nothing was watched. That is not a good day; it is an
			// unknown one, and the bar says so.
			bar.UptimePPM = -1
			bar.Status = "unknown"
		} else {
			bar.UptimePPM = availability.Availability(dayObserved, dayDown)
			switch {
			case dayDown == 0:
				bar.Status = StatusOperational
			case bar.UptimePPM < 990_000:
				bar.Status = StatusMajorOutage
			default:
				bar.Status = StatusPartialOutage
			}
			observedTotal += dayObserved
			downTotal += dayDown
		}
		days = append(days, bar)
	}
	return days, availability.Availability(observedTotal, downTotal)
}

// componentSeriesFor exposes the rollup to the status page. It is the
// same function the report and the verifier use, so the number on the
// page and the number in the report cannot drift apart.
func componentSeriesFor(buckets []model.Bucket, rollup string) (down, observed []model.Interval, err error) {
	return availability.ComponentSeries(availability.ComponentInput{
		Rollup: rollup, Buckets: buckets,
	})
}

func statusOf(verdict string) string {
	switch verdict {
	case model.VerdictDown:
		return StatusMajorOutage
	case model.VerdictDegraded:
		return StatusDegraded
	case model.VerdictError:
		return StatusDegraded
	default:
		return StatusOperational
	}
}

func indicatorOf(status string) string {
	switch status {
	case StatusMajorOutage:
		return IndicatorMajor
	case StatusPartialOutage:
		return IndicatorMinor
	case StatusDegraded:
		return IndicatorMinor
	case StatusUnderMaintenance:
		return IndicatorMaint
	default:
		return IndicatorNone
	}
}

var indicatorRank = map[string]int{
	IndicatorNone: 0, IndicatorMaint: 1, IndicatorMinor: 2,
	IndicatorMajor: 3, IndicatorCritical: 4,
}

func worseIndicator(a, b string) string {
	if indicatorRank[b] > indicatorRank[a] {
		return b
	}
	return a
}

func headline(indicator string) string {
	switch indicator {
	case IndicatorNone:
		return "All systems operational"
	case IndicatorMaint:
		return "Maintenance in progress"
	case IndicatorMinor:
		return "Partially degraded service"
	case IndicatorMajor:
		return "Major service outage"
	case IndicatorCritical:
		return "Critical service outage"
	}
	return "Status unknown"
}

func startOfDay(at int64, loc *time.Location) time.Time {
	t := time.Unix(at, 0).In(loc)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
}
