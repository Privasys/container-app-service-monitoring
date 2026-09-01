// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package availability

import (
	"fmt"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// Agreed service time.
//
// The denominator of the availability formula is not "the whole month".
// It is the time the parties agreed the service would be available,
// expressed as recurring weekly windows in the service's own timezone,
// with calendar exceptions for public holidays and agreed shutdowns.
// 24x7 is one schedule among others, and writing it down as a schedule
// rather than assuming it is what makes a business-hours SLA a first
// class thing rather than a footnote.
//
// Local time is where the traps are. A window is expressed in wall
// clock minutes, so the day a clock goes forward is genuinely an hour
// shorter and the day it goes back is genuinely an hour longer. Both
// are computed here from the zone database rather than by adding 86400
// seconds, because a customer whose maintenance window straddles a
// clock change will notice, and an SLA report that quietly loses an
// hour is exactly the kind of error nobody finds until it matters.

// Expand renders a schedule as the concrete intervals it covers inside
// [from, to).
func Expand(s model.Schedule, from, to int64) ([]model.Interval, error) {
	if to <= from {
		return nil, nil
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return nil, fmt.Errorf("availability: timezone %q: %w", s.Timezone, err)
	}

	byWeekday := map[int][]model.ScheduleWindow{}
	for _, w := range s.Windows {
		byWeekday[w.Weekday] = append(byWeekday[w.Weekday], w)
	}
	exceptions := map[string][]model.ScheduleException{}
	for _, e := range s.Exceptions {
		exceptions[e.Date] = append(exceptions[e.Date], e)
	}

	var out []model.Interval
	// Start a day early and end a day late, then clip: a window that
	// runs to midnight belongs to the day it started on, and the
	// boundaries of the period land inside days rather than on them.
	day := time.Unix(from, 0).In(loc).AddDate(0, 0, -1)
	day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, loc)
	last := time.Unix(to, 0).In(loc).AddDate(0, 0, 1)

	for !day.After(last) {
		date := day.Format("2006-01-02")
		windows := byWeekday[int(day.Weekday())]
		excs := exceptions[date]

		// A date named by an exclusion exception loses its recurring
		// windows entirely; an inclusion exception adds one.
		excluded := false
		for _, e := range excs {
			if !e.Include {
				excluded = true
			}
		}
		if !excluded {
			for _, w := range windows {
				out = append(out, dayWindow(day, loc, w.StartMin, w.EndMin))
			}
		}
		for _, e := range excs {
			if e.Include {
				endMin := e.EndMin
				if endMin == 0 && e.StartMin == 0 {
					endMin = 1440
				}
				out = append(out, dayWindow(day, loc, e.StartMin, endMin))
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return Clip(out, from, to), nil
}

// dayWindow converts wall-clock minutes on a local date into an
// absolute interval, honouring whatever the zone did that day.
func dayWindow(day time.Time, loc *time.Location, startMin, endMin int) model.Interval {
	if endMin <= startMin {
		endMin = startMin
	}
	start := time.Date(day.Year(), day.Month(), day.Day(), 0, startMin, 0, 0, loc)
	end := time.Date(day.Year(), day.Month(), day.Day(), 0, endMin, 0, 0, loc)
	return model.Interval{From: start.Unix(), To: end.Unix()}
}

// Period resolves a named reporting window to absolute bounds in the
// service's timezone. The label travels with the report, because an
// eight-hour outage is 95.2% on the week and 99.6% on the quarter, and
// a percentage without its period is not a fact.
func Period(kind string, at int64, timezone string) (model.Period, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return model.Period{}, fmt.Errorf("availability: timezone %q: %w", timezone, err)
	}
	now := time.Unix(at, 0).In(loc)
	switch kind {
	case model.WindowCalendarMonth, "month":
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
		end := start.AddDate(0, 1, 0)
		return model.Period{Label: start.Format("2006-01"), From: start.Unix(), To: end.Unix(), Timezone: timezone}, nil
	case model.WindowCalendarQuarter, "quarter":
		q := (int(now.Month()) - 1) / 3
		start := time.Date(now.Year(), time.Month(q*3+1), 1, 0, 0, 0, 0, loc)
		end := start.AddDate(0, 3, 0)
		return model.Period{Label: fmt.Sprintf("%dQ%d", start.Year(), q+1),
			From: start.Unix(), To: end.Unix(), Timezone: timezone}, nil
	case model.WindowCalendarWeek, "week":
		// ISO weeks start on Monday.
		offset := (int(now.Weekday()) + 6) % 7
		start := time.Date(now.Year(), now.Month(), now.Day()-offset, 0, 0, 0, 0, loc)
		end := start.AddDate(0, 0, 7)
		year, week := start.ISOWeek()
		return model.Period{Label: fmt.Sprintf("%d-W%02d", year, week),
			From: start.Unix(), To: end.Unix(), Timezone: timezone}, nil
	case model.WindowRolling30d, "30d":
		end := now
		start := end.AddDate(0, 0, -30)
		return model.Period{Label: "rolling 30 days", From: start.Unix(), To: end.Unix(), Timezone: timezone}, nil
	}
	return model.Period{}, fmt.Errorf("availability: %q is not a reporting period", kind)
}

// Previous shifts a calendar period back by one, which is what a report
// for "last month" actually means.
func Previous(p model.Period, kind, timezone string) (model.Period, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return model.Period{}, err
	}
	start := time.Unix(p.From, 0).In(loc)
	switch kind {
	case model.WindowCalendarMonth, "month":
		return Period(kind, start.AddDate(0, 0, -1).Unix(), timezone)
	case model.WindowCalendarQuarter, "quarter":
		return Period(kind, start.AddDate(0, 0, -1).Unix(), timezone)
	case model.WindowCalendarWeek, "week":
		return Period(kind, start.AddDate(0, 0, -1).Unix(), timezone)
	}
	return p, nil
}
