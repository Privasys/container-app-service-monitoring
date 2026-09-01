// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package availability is the arithmetic: agreed service time,
// exclusions, outages, coverage and the objectives evaluated over them.
//
// It is deliberately a pure package. It takes intervals and folded
// readings and returns numbers, with no access to the store, the clock
// or the network. That is what lets the offline verifier run the same
// computation over the evidence bundled with a report and get the same
// answer: if this package needed the running service, the report would
// be a claim rather than a calculation.
//
// Every ratio leaves as parts per million. A contractual threshold is
// the last place to accept binary floating point rounding, and 99.9%
// is 999000 with nothing to argue about.
package availability

import (
	"sort"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// PPM is one hundred per cent in parts per million.
const PPM = 1_000_000

// Merge sorts and coalesces overlapping or touching intervals.
func Merge(in []model.Interval) []model.Interval {
	if len(in) == 0 {
		return nil
	}
	cp := make([]model.Interval, 0, len(in))
	for _, iv := range in {
		if iv.To > iv.From {
			cp = append(cp, iv)
		}
	}
	if len(cp) == 0 {
		return nil
	}
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].From != cp[j].From {
			return cp[i].From < cp[j].From
		}
		return cp[i].To < cp[j].To
	})
	out := []model.Interval{cp[0]}
	for _, iv := range cp[1:] {
		last := &out[len(out)-1]
		if iv.From <= last.To {
			if iv.To > last.To {
				last.To = iv.To
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}

// Intersect returns the parts of a that fall inside b. Both sides are
// merged first, so the result is itself normalised.
func Intersect(a, b []model.Interval) []model.Interval {
	a, b = Merge(a), Merge(b)
	var out []model.Interval
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		from := max64(a[i].From, b[j].From)
		to := min64(a[i].To, b[j].To)
		if to > from {
			out = append(out, model.Interval{From: from, To: to})
		}
		if a[i].To < b[j].To {
			i++
		} else {
			j++
		}
	}
	return out
}

// Subtract removes cut from base.
func Subtract(base, cut []model.Interval) []model.Interval {
	base, cut = Merge(base), Merge(cut)
	var out []model.Interval
	for _, b := range base {
		cur := b
		for _, c := range cut {
			if c.To <= cur.From {
				continue
			}
			if c.From >= cur.To {
				break
			}
			if c.From > cur.From {
				out = append(out, model.Interval{From: cur.From, To: min64(c.From, cur.To)})
			}
			if c.To >= cur.To {
				cur.From = cur.To
				break
			}
			cur.From = c.To
		}
		if cur.To > cur.From {
			out = append(out, cur)
		}
	}
	return Merge(out)
}

// Total is the length of a set of intervals, after merging.
func Total(in []model.Interval) int64 {
	var sum int64
	for _, iv := range Merge(in) {
		sum += iv.Seconds()
	}
	return sum
}

// Clip restricts a set of intervals to a window.
func Clip(in []model.Interval, from, to int64) []model.Interval {
	return Intersect(in, []model.Interval{{From: from, To: to}})
}

// Ratio returns numerator over denominator in parts per million,
// rounded to nearest. A zero denominator is 100%: there was no agreed
// service time to be unavailable in, and reporting 0% for a service
// nobody had agreed to run would be worse than saying nothing.
func Ratio(numerator, denominator int64) int64 {
	if denominator <= 0 {
		return PPM
	}
	if numerator <= 0 {
		return 0
	}
	if numerator >= denominator {
		return PPM
	}
	return (numerator*PPM*2 + denominator) / (denominator * 2)
}

// Availability is the headline formula: agreed service time less
// downtime, over agreed service time.
func Availability(ast, downtime int64) int64 {
	if ast <= 0 {
		return PPM
	}
	up := ast - downtime
	if up < 0 {
		up = 0
	}
	return Ratio(up, ast)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
