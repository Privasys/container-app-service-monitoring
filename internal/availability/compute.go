// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package availability

import (
	"fmt"
	"sort"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// Compute is the whole calculation, in one pure function.
//
// The service and the offline verifier both call it: the service to
// produce a report, the verifier to check that the report's numbers are
// what its own evidence implies. That is the difference between a
// signed assertion and a signed computation, and it is why this
// function may not read the clock, the store or the network.

// Input is everything the calculation needs.
type Input struct {
	Period model.Period
	// Scheduled is the expanded agreed service time for the period.
	Scheduled []model.Interval
	// Exclusions are the declared windows, each already carrying the
	// decision made when it was declared.
	Exclusions []model.Exclusion
	Components []ComponentInput
	// CoverageFloorPPM is the coverage below which an objective cannot
	// be reported as met.
	CoverageFloorPPM int64
	Objectives       []model.Objective
}

// ComponentInput is one component and the readings taken on it.
type ComponentInput struct {
	ID         string
	Name       string
	UserWeight int64
	Rollup     string
	// Buckets are every folded reading for every monitor on this
	// component, in any order.
	Buckets []model.Bucket
	// Monitors names the monitors expected to be reporting, which is
	// what makes a missing reading detectable rather than invisible.
	Monitors []model.MonitorRef
}

// Output is the calculation.
type Output struct {
	AST        model.ASTSummary
	Downtime   model.DowntimeSummary
	Results    model.Results
	Components []model.ComponentResult
	Outages    []model.Outage
	Exclusions []model.Exclusion
	Gaps       []model.Gap
	Objectives []model.ObjectiveResult
}

// Compute runs the calculation.
func Compute(in Input) (Output, error) {
	var out Output

	scheduled := Clip(in.Scheduled, in.Period.From, in.Period.To)
	out.AST.Intervals = scheduled
	out.AST.Scheduled = Total(scheduled)

	// Exclusions. Each window was judged when it was declared: a planned
	// window with enough notice leaves agreed service time, anything
	// else is recorded with its lead time and left in the denominator.
	// The report shows both kinds, which is what makes a window entered
	// after the outage visible as exactly that.
	var applied []model.Interval
	out.Exclusions = make([]model.Exclusion, 0, len(in.Exclusions))
	for _, ex := range in.Exclusions {
		clipped := Intersect([]model.Interval{{From: ex.From, To: ex.To}}, scheduled)
		ex.Seconds = Total(clipped)
		if ex.Seconds == 0 {
			continue
		}
		if ex.Applied {
			applied = append(applied, clipped...)
		}
		out.Exclusions = append(out.Exclusions, ex)
	}
	out.AST.Excluded = Total(applied)
	net := Subtract(scheduled, applied)
	out.AST.Net = Total(net)

	// Per component: roll the monitors up into one verdict per interval,
	// then read the outages off the result.
	var serviceOutages []model.Interval
	var observedAll []model.Interval
	var potentialUser, userOutage int64

	for _, c := range in.Components {
		down, observed, err := ComponentSeries(c)
		if err != nil {
			return out, err
		}
		downInAST := Intersect(down, net)
		observedInAST := Intersect(observed, net)

		cr := model.ComponentResult{
			ComponentID: c.ID, Name: c.Name, UserWeight: c.UserWeight,
			DowntimeSeconds: Total(downInAST),
			Outages:         len(Merge(downInAST)),
		}
		cr.AvailabilityPPM = Availability(out.AST.Net, cr.DowntimeSeconds)
		cr.CoveragePPM = Ratio(Total(observedInAST), out.AST.Net)
		out.Components = append(out.Components, cr)

		for _, iv := range Merge(downInAST) {
			out.Outages = append(out.Outages, model.Outage{
				ComponentID: c.ID, From: iv.From, To: iv.To, Seconds: iv.Seconds(),
			})
		}
		serviceOutages = append(serviceOutages, downInAST...)
		observedAll = append(observedAll, observedInAST...)

		potentialUser += c.UserWeight * out.AST.Net
		userOutage += c.UserWeight * cr.DowntimeSeconds
	}

	sort.Slice(out.Outages, func(i, j int) bool {
		if out.Outages[i].From != out.Outages[j].From {
			return out.Outages[i].From < out.Outages[j].From
		}
		return out.Outages[i].ComponentID < out.Outages[j].ComponentID
	})

	// The service is impaired while any of its components is. That is
	// the blunt figure, and it is deliberately pessimistic; the
	// user-weighted figure beside it is the fair one, and reporting both
	// is how a small component's outage stops looking like a whole
	// service failure without anyone having to hide it.
	downMerged := Merge(serviceOutages)
	out.Downtime.Seconds = Total(downMerged)
	out.Downtime.Outages = len(downMerged)
	for _, iv := range downMerged {
		if s := iv.Seconds(); s > out.Downtime.LongestSeconds {
			out.Downtime.LongestSeconds = s
		}
	}
	if out.Downtime.Outages > 0 {
		out.Downtime.MTRS = out.Downtime.Seconds / int64(out.Downtime.Outages)
		uptime := out.AST.Net - out.Downtime.Seconds
		if uptime < 0 {
			uptime = 0
		}
		out.Downtime.MTBF = uptime / int64(out.Downtime.Outages)
	}

	out.Results.AvailabilityPPM = Availability(out.AST.Net, out.Downtime.Seconds)
	out.Results.PotentialUserSeconds = potentialUser
	out.Results.UserOutageSeconds = userOutage
	if potentialUser > 0 {
		out.Results.UserAvailabilityPPM = Ratio(potentialUser-userOutage, potentialUser)
	} else {
		// No component declared a user population, so there is nothing to
		// weight by. Reporting the unweighted figure is honest; inventing
		// a weighting is not.
		out.Results.UserAvailabilityPPM = out.Results.AvailabilityPPM
	}

	observedMerged := Merge(observedAll)
	out.Results.ObservedSeconds = Total(observedMerged)
	out.Results.CoveragePPM = Ratio(out.Results.ObservedSeconds, out.AST.Net)
	for _, iv := range Subtract(net, observedMerged) {
		out.Gaps = append(out.Gaps, model.Gap{From: iv.From, To: iv.To, Seconds: iv.Seconds()})
	}

	out.Objectives = evaluate(in, &out)
	return out, nil
}

// segment is one monitor's verdict over one stretch of time.
type segment struct {
	from, to int64
	observed bool
	down     bool
}

// monitorSegments turns one monitor's folded readings into a
// non-overlapping series.
//
// Readings arrive at more than one width on purpose. A report over a
// month reads hour buckets everywhere and minute buckets only for the
// hours that were not uniformly up, which is the difference between
// bundling a few hundred rows of evidence and bundling forty thousand.
// The rule is that the finest reading wins: a minute bucket is the
// truth for its minute, and an hour bucket only speaks for the parts of
// its hour that no finer reading covers.
func monitorSegments(buckets []model.Bucket) []segment {
	ordered := append([]model.Bucket(nil), buckets...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Width != ordered[j].Width {
			return ordered[i].Width < ordered[j].Width
		}
		return ordered[i].Start < ordered[j].Start
	})

	var covered []model.Interval
	var out []segment
	for _, b := range ordered {
		width := b.Width
		if width <= 0 {
			continue
		}
		whole := []model.Interval{{From: b.Start, To: b.Start + width}}
		for _, iv := range Subtract(whole, covered) {
			out = append(out, segment{
				from: iv.From, to: iv.To,
				// A reading made only of errors is not a reading of the
				// service. It counts against coverage, never against
				// availability.
				observed: b.Up+b.Degraded+b.Down > 0,
				down:     b.Verdict == model.VerdictDown,
			})
		}
		covered = Merge(append(covered, whole...))
	}
	return out
}

// componentSeries rolls a component's monitors up into the intervals it
// was down, and the intervals it was observed at all.
//
// The rollup runs as a sweep over every boundary any monitor produced,
// so monitors reporting at different intervals, and evidence bundled at
// different widths, combine without anyone having to line up on a grid.
// ComponentSeries is exported because the status page, the report and
// the offline verifier must all roll a component up the same way. A
// second implementation of this rule would be a second answer.
func ComponentSeries(c ComponentInput) (down, observed []model.Interval, err error) {
	byMonitor := map[string][]model.Bucket{}
	for _, b := range c.Buckets {
		byMonitor[b.MonitorID] = append(byMonitor[b.MonitorID], b)
	}

	var all []segment
	points := map[int64]bool{}
	for _, buckets := range byMonitor {
		segs := monitorSegments(buckets)
		all = append(all, segs...)
		for _, s := range segs {
			points[s.from] = true
			points[s.to] = true
		}
	}
	if len(all) == 0 {
		return nil, nil, nil
	}

	bounds := make([]int64, 0, len(points))
	for p := range points {
		bounds = append(bounds, p)
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i] < bounds[j] })

	rollup := c.Rollup
	if rollup == "" {
		rollup = model.RollupAny
	}

	for i := 0; i+1 < len(bounds); i++ {
		from, to := bounds[i], bounds[i+1]
		if to <= from {
			continue
		}
		seen, isDown := 0, 0
		for _, s := range all {
			if s.from > from || s.to < to || !s.observed {
				continue
			}
			seen++
			if s.down {
				isDown++
			}
		}
		if seen == 0 {
			continue
		}
		iv := model.Interval{From: from, To: to}
		observed = append(observed, iv)
		bad := false
		switch rollup {
		case model.RollupAll:
			bad = isDown == seen
		case model.RollupMajority:
			bad = isDown*2 > seen
		default:
			bad = isDown > 0
		}
		if bad {
			down = append(down, iv)
		}
	}
	return Merge(down), Merge(observed), nil
}

// evaluate scores the objectives.
//
// The coverage floor is the rule that keeps the report honest. A
// monitor that was down for a third of the month cannot certify that
// the service was up, and an objective evaluated on a third of the
// evidence is not met or breached: it is indeterminate, and the gaps
// are named.
func evaluate(in Input, out *Output) []model.ObjectiveResult {
	results := make([]model.ObjectiveResult, 0, len(in.Objectives))
	for _, o := range in.Objectives {
		r := model.ObjectiveResult{
			ID: o.ID, Name: o.Name, Metric: o.Metric, Window: o.Window, TargetPPM: o.TargetPPM,
		}
		switch o.Metric {
		case model.MetricAvailability:
			r.AchievedPPM = out.Results.AvailabilityPPM
		case model.MetricUserAvailability:
			r.AchievedPPM = out.Results.UserAvailabilityPPM
		case model.MetricLatencyP95:
			r.AchievedPPM = latencyWithinBudget(in.Components, o.LatencyBudgetMs)
		default:
			r.Result = model.ObjectiveIndeterminate
			r.Reason = "unknown metric " + o.Metric
			results = append(results, r)
			continue
		}

		switch {
		case out.AST.Net == 0:
			r.Result = model.ObjectiveIndeterminate
			r.Reason = "the period contained no agreed service time"
		case in.CoverageFloorPPM > 0 && out.Results.CoveragePPM < in.CoverageFloorPPM:
			r.Result = model.ObjectiveIndeterminate
			r.Reason = fmt.Sprintf("monitoring coverage was %s, below the %s floor for this service",
				FormatPPM(out.Results.CoveragePPM), FormatPPM(in.CoverageFloorPPM))
		case r.AchievedPPM >= o.TargetPPM:
			r.Result = model.ObjectiveMet
		default:
			r.Result = model.ObjectiveBreached
			r.CreditPercent = credit(o.Credits, r.AchievedPPM)
		}
		results = append(results, r)
	}
	return results
}

// latencyWithinBudget is the fraction of folded intervals whose 95th
// percentile was inside the budget. Stating it that way keeps the
// objective an integer comparison and keeps its meaning plain: how much
// of the period was fast enough.
func latencyWithinBudget(components []ComponentInput, budgetMs int) int64 {
	if budgetMs <= 0 {
		return PPM
	}
	var within, total int64
	for _, c := range components {
		for _, b := range c.Buckets {
			if b.Up+b.Degraded == 0 {
				continue
			}
			total++
			if b.LatencyP95 <= budgetMs {
				within++
			}
		}
	}
	return Ratio(within, total)
}

func credit(bands []model.CreditBand, achieved int64) int {
	best := 0
	for _, b := range bands {
		if achieved < b.BelowPPM && b.CreditPercent > best {
			best = b.CreditPercent
		}
	}
	return best
}

// FormatPPM renders parts per million as a percentage with three
// decimal places, which is the resolution an SLA is usually written to.
func FormatPPM(ppm int64) string {
	return fmt.Sprintf("%d.%03d%%", ppm/10000, (ppm%10000)/10)
}
