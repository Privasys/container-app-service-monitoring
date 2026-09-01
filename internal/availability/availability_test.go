// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package availability_test

import (
	"testing"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/availability"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// The arithmetic is the product. These tests are mostly about the
// places where a plausible implementation would quietly give the wrong
// answer: a clock change, a maintenance window declared after the
// event, and a period the monitor was not watching.

func TestSubtractRemovesTheOverlapOnly(t *testing.T) {
	base := []model.Interval{{From: 0, To: 100}}
	cut := []model.Interval{{From: 20, To: 30}, {From: 90, To: 200}}
	got := availability.Subtract(base, cut)
	want := []model.Interval{{From: 0, To: 20}, {From: 30, To: 90}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestAvailabilityIsRoundedToNearest(t *testing.T) {
	// 99.9% of a 30-day month is 43.2 minutes of downtime.
	month := int64(30 * 24 * 3600)
	if got := availability.Availability(month, 2592); got != 999000 {
		t.Fatalf("availability = %d, want 999000", got)
	}
	if got := availability.Availability(month, 0); got != 1_000_000 {
		t.Fatalf("a month with no downtime is not 100%%: %d", got)
	}
	// An agreed service time of zero cannot have been unavailable.
	if got := availability.Availability(0, 0); got != 1_000_000 {
		t.Fatalf("empty agreed service time = %d", got)
	}
}

// A schedule is wall-clock, so the day a clock goes forward is really
// an hour shorter. Adding 86400 seconds per day would silently hand the
// customer an extra hour of agreed service time twice a year.
func TestScheduleHonoursTheClockChange(t *testing.T) {
	loc, err := time.LoadLocation("Europe/London")
	if err != nil {
		t.Skip("no zone database")
	}
	schedule := model.AlwaysOn("sch", "svc", "Europe/London", 0)
	// British Summer Time began on 29 March 2026 at 01:00.
	from := time.Date(2026, 3, 29, 0, 0, 0, 0, loc)
	to := from.AddDate(0, 0, 1)
	intervals, err := availability.Expand(schedule, from.Unix(), to.Unix())
	if err != nil {
		t.Fatal(err)
	}
	if total := availability.Total(intervals); total != 23*3600 {
		t.Fatalf("the day the clocks went forward is %d seconds, want %d", total, 23*3600)
	}
}

func TestBusinessHoursScheduleExcludesTheNight(t *testing.T) {
	schedule := model.Schedule{
		ID: "sch", ServiceID: "svc", Timezone: "UTC",
		Windows: []model.ScheduleWindow{
			{Weekday: 1, StartMin: 9 * 60, EndMin: 17 * 60},
		},
	}
	// A Monday in UTC.
	from := time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	intervals, err := availability.Expand(schedule, from.Unix(), from.AddDate(0, 0, 1).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if total := availability.Total(intervals); total != 8*3600 {
		t.Fatalf("agreed service time = %d seconds, want %d", total, 8*3600)
	}
}

// The property the whole product turns on: a window declared before the
// event leaves the denominator, and one declared after it does not,
// with both visible in the result.
func TestExclusionsAreAppliedOnlyWhenDeclared(t *testing.T) {
	day := int64(86400)
	period := model.Period{From: 0, To: day, Timezone: "UTC", Label: "test"}
	scheduled := []model.Interval{{From: 0, To: day}}

	in := availability.Input{
		Period: period, Scheduled: scheduled,
		Exclusions: []model.Exclusion{
			{WindowID: "w1", Class: model.ClassPlannedMaintenance, From: 0, To: 3600, Applied: true},
			{WindowID: "w2", Class: model.ClassPlannedMaintenance, From: 7200, To: 10800, Applied: false},
		},
		Components: []availability.ComponentInput{{ID: "c1", Rollup: model.RollupAny}},
	}
	out, err := availability.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.AST.Excluded != 3600 {
		t.Fatalf("excluded = %d, want 3600", out.AST.Excluded)
	}
	if out.AST.Net != day-3600 {
		t.Fatalf("net agreed service time = %d, want %d", out.AST.Net, day-3600)
	}
	if len(out.Exclusions) != 2 {
		t.Fatalf("both windows should be reported, got %d", len(out.Exclusions))
	}
}

// A monitor that was not watching did not see a service that was up.
func TestCoverageFloorMakesAnObjectiveIndeterminate(t *testing.T) {
	hour := int64(3600)
	period := model.Period{From: 0, To: 10 * hour, Timezone: "UTC"}
	var buckets []model.Bucket
	// Readings for one hour out of ten.
	for i := int64(0); i < 60; i++ {
		buckets = append(buckets, model.Bucket{
			MonitorID: "m1", ComponentID: "c1", Start: i * 60, Width: 60,
			Up: 1, Verdict: model.VerdictUp,
		})
	}
	in := availability.Input{
		Period: period, Scheduled: []model.Interval{{From: 0, To: 10 * hour}},
		CoverageFloorPPM: 990_000,
		Components: []availability.ComponentInput{
			{ID: "c1", Rollup: model.RollupAny, Buckets: buckets},
		},
		Objectives: []model.Objective{
			{ID: "o1", Name: "monthly", Metric: model.MetricAvailability, TargetPPM: 999_000},
		},
	}
	out, err := availability.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Results.CoveragePPM != 100_000 {
		t.Fatalf("coverage = %d, want 100000", out.Results.CoveragePPM)
	}
	if out.Objectives[0].Result != model.ObjectiveIndeterminate {
		t.Fatalf("an objective on a tenth of the evidence is %q, want indeterminate",
			out.Objectives[0].Result)
	}
	if len(out.Gaps) != 1 || out.Gaps[0].Seconds != 9*hour {
		t.Fatalf("gaps = %v, want one of nine hours", out.Gaps)
	}
}

// Two hours affecting one back-office function is not two hours
// affecting the whole call centre.
func TestUserWeightingSeparatesTheTwoFigures(t *testing.T) {
	hour := int64(3600)
	period := model.Period{From: 0, To: hour, Timezone: "UTC"}

	up := func(id string, start int64) model.Bucket {
		return model.Bucket{MonitorID: id, ComponentID: id, Start: start, Width: 60,
			Up: 1, Verdict: model.VerdictUp}
	}
	down := func(id string, start int64) model.Bucket {
		return model.Bucket{MonitorID: id, ComponentID: id, Start: start, Width: 60,
			Down: 1, Verdict: model.VerdictDown}
	}

	var big, small []model.Bucket
	for i := int64(0); i < 60; i++ {
		big = append(big, up("big", i*60))
		if i < 30 {
			small = append(small, down("small", i*60))
		} else {
			small = append(small, up("small", i*60))
		}
	}

	in := availability.Input{
		Period: period, Scheduled: []model.Interval{{From: 0, To: hour}},
		Components: []availability.ComponentInput{
			{ID: "big", UserWeight: 10000, Rollup: model.RollupAny, Buckets: big},
			{ID: "small", UserWeight: 10, Rollup: model.RollupAny, Buckets: small},
		},
	}
	out, err := availability.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	// Half an hour of the small component being down is half the period
	// on the blunt figure.
	if out.Results.AvailabilityPPM != 500_000 {
		t.Fatalf("availability = %d, want 500000", out.Results.AvailabilityPPM)
	}
	// Weighted by who it affected, it is a rounding error.
	if out.Results.UserAvailabilityPPM < 999_000 {
		t.Fatalf("user-weighted availability = %d, want above 999000",
			out.Results.UserAvailabilityPPM)
	}
}

// A minute bucket is the truth for its minute; an hour bucket only
// speaks for the parts of its hour nothing finer covers. Getting this
// wrong would double count an outage or hide it.
func TestFinerReadingsWinOverCoarserOnes(t *testing.T) {
	hour := int64(3600)
	period := model.Period{From: 0, To: hour, Timezone: "UTC"}

	buckets := []model.Bucket{
		// The hour says down, which is the conservative rollup.
		{MonitorID: "m1", ComponentID: "c1", Start: 0, Width: hour, Up: 58, Down: 2,
			Verdict: model.VerdictDown},
	}
	// The two minutes that were actually down.
	for i := int64(0); i < 60; i++ {
		b := model.Bucket{MonitorID: "m1", ComponentID: "c1", Start: i * 60, Width: 60,
			Up: 1, Verdict: model.VerdictUp}
		if i == 10 || i == 11 {
			b = model.Bucket{MonitorID: "m1", ComponentID: "c1", Start: i * 60, Width: 60,
				Down: 1, Verdict: model.VerdictDown}
		}
		buckets = append(buckets, b)
	}

	in := availability.Input{
		Period: period, Scheduled: []model.Interval{{From: 0, To: hour}},
		Components: []availability.ComponentInput{
			{ID: "c1", Rollup: model.RollupAny, Buckets: buckets},
		},
	}
	out, err := availability.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Downtime.Seconds != 120 {
		t.Fatalf("downtime = %d seconds, want 120: the minutes should override the hour",
			out.Downtime.Seconds)
	}
}

func TestErrorsCountAgainstCoverageNotAvailability(t *testing.T) {
	hour := int64(3600)
	period := model.Period{From: 0, To: hour, Timezone: "UTC"}
	var buckets []model.Bucket
	for i := int64(0); i < 60; i++ {
		b := model.Bucket{MonitorID: "m1", ComponentID: "c1", Start: i * 60, Width: 60,
			Up: 1, Verdict: model.VerdictUp}
		if i >= 30 {
			// The monitor could not take a reading at all.
			b = model.Bucket{MonitorID: "m1", ComponentID: "c1", Start: i * 60, Width: 60,
				Errors: 1, Verdict: model.VerdictError}
		}
		buckets = append(buckets, b)
	}
	in := availability.Input{
		Period: period, Scheduled: []model.Interval{{From: 0, To: hour}},
		Components: []availability.ComponentInput{
			{ID: "c1", Rollup: model.RollupAny, Buckets: buckets},
		},
	}
	out, err := availability.Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Downtime.Seconds != 0 {
		t.Fatalf("a reading the monitor could not take is not downtime: %d seconds",
			out.Downtime.Seconds)
	}
	if out.Results.CoveragePPM != 500_000 {
		t.Fatalf("coverage = %d, want 500000", out.Results.CoveragePPM)
	}
}

func TestPeriodBoundariesAreCalendarAndLocal(t *testing.T) {
	if _, err := time.LoadLocation("Europe/Paris"); err != nil {
		t.Skip("no zone database")
	}
	at := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC).Unix()
	period, err := availability.Period(model.WindowCalendarMonth, at, "Europe/Paris")
	if err != nil {
		t.Fatal(err)
	}
	if period.Label != "2026-03" {
		t.Fatalf("label = %q", period.Label)
	}
	start := time.Unix(period.From, 0).UTC()
	// March in Paris starts at 23:00 UTC on 28 February.
	if start.Day() != 28 || start.Hour() != 23 {
		t.Fatalf("the month starts at %s, which is not local midnight in Paris", start)
	}
}
