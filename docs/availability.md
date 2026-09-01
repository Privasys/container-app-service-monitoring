# The availability model

This is the document to read before arguing with a report. It sets out
exactly what is measured, what is excluded, and what the service refuses
to claim.

## The formula

```
Availability = ((Agreed Service Time - Downtime) / Agreed Service Time) x 100
```

Every term in it is a decision that was written down.

### Agreed service time

Not "the whole month". A schedule is a set of recurring weekly windows
in the service's own timezone, plus calendar exceptions for public
holidays and agreed shutdowns. `24x7` is one schedule among others, and
writing it as a schedule rather than assuming it is what makes a
business-hours agreement a first-class thing.

Windows are wall-clock. The day a clock goes forward is genuinely an
hour shorter and the day it goes back is genuinely an hour longer,
computed from the zone database rather than by adding 86400 seconds. A
customer whose window straddles a clock change will notice, and a report
that quietly loses an hour is the kind of error nobody finds until it
matters.

### Downtime

Contiguous time inside agreed service time during which the service was
judged unavailable. The judgement runs in three stages.

**A reading** is one execution of a journey. Its verdict is `up`,
`degraded`, `down` or `error`.

**A folded interval** is the readings for one monitor over one minute.
The interval is `down` when at least half of its readings failed, so a
single failure in a minute with one reading is downtime, and one failure
in four is `degraded` rather than `down`: a request that succeeded on
the retry is not the same fact as a service that was not there. An hour
is `down` if any minute inside it was, which is deliberately
pessimistic, and is why a report reads the minutes of any hour that was
not uniformly up rather than resting on the hour.

**A component** is `down` when its monitors say so under its declared
rollup rule, which is `any`, `all` or `majority`.

The service is impaired while any of its components is. That figure is
deliberately blunt; the user-weighted figure beside it is the fair one.

### Errors are not downtime

A reading the monitor could not take, because a credential was missing,
a target was undeclared or a template did not resolve, is recorded as
`error`. It never counts as downtime of the watched service, it moves no
detection threshold in either direction, and it costs monitoring
coverage. A monitor that charged its own misconfiguration to the
customer's availability would be worse than no monitor.

## The user-weighted figure

```
Availability = ((Potential User Minutes - User Outage Minutes) / Potential User Minutes) x 100
```

Each component declares a `user_weight`, the population it serves.
Reporting both figures is how a small component's outage stops looking
like a whole service failure without anyone having to hide it. Where no
component declares a population, the weighted figure is the unweighted
one and the report says so rather than inventing a weighting.

## Exclusions

Every exclusion is a declared window with a class, and the decision
about it is made once, when it is declared.

| Class | Treatment |
| --- | --- |
| `planned_maintenance` | Removed from agreed service time **only if declared at least `maintenance_lead_time` before it starts** (default 24 hours). |
| `third_party` | Recorded; excluded only if the agreement says so. |
| `force_majeure` | Recorded; excluded only if the agreement says so. |
| `customer_caused` | Recorded; excluded only if the agreement says so. |
| `monitoring_fault` | Excluded from the availability numerator and deducted from coverage. |

The window carries the moment it was declared, and the report states the
notice it had either way. A window declared after the outage it covers
appears with a negative lead time and stays in the denominator. Nobody
has to be trusted to have been honest about the order of events, because
the order of events is in the ledger.

Whether a third-party or force-majeure interruption is excluded is a
matter for the contract, not for the monitor, so the monitor declines to
assume and records it instead.

## Coverage

```
Coverage = (agreed service time with at least one reading) / (agreed service time)
```

A monitor that was down cannot certify uptime. Every report states
coverage beside availability, enumerates the gaps, and reports an
objective as `indeterminate` rather than met when coverage falls below
the service's floor (default 99%). `indeterminate` is a real answer, not
a missing one, and it names the gaps that caused it.

The monitor's own restarts are written into the record as events, so the
gap a redeploy leaves is a visible fact rather than a quiet period.

## Reliability

Frequency and duration are reported separately from the percentage,
because they buy different remedies. A report carries the outage count,
MTBF, MTRS and the longest single interruption. One eight-hour outage
and ninety-six five-minute ones are the same percentage and very
different problems.

## Reporting periods

A report declares its period, and shows the worst day and the worst week
inside it. The same eight hours of downtime is 95.2% on the week and
99.6% on the quarter; a percentage without its period is not a fact, and
a long period can flatter a bad day into invisibility.

Objectives are evaluated over the window the agreement names:
`calendar_month`, `calendar_week`, `calendar_quarter` or `rolling_30d`,
with calendar boundaries taken in the service's timezone.

## Objectives and credits

An objective is a metric, a target in parts per million, and a window.
`availability` and `user_availability` compare the figures above.
`latency_p95` is the fraction of folded intervals whose 95th-percentile
latency was inside the budget, which keeps the comparison an integer and
keeps its meaning plain: how much of the period was fast enough.

A credit schedule maps achieved availability to a percentage credit. The
report computes it; nobody has to.

Every ratio is an integer in parts per million. 99.9% is `999000`, with
nothing to argue about.

## What a report contains

- The period, the timezone, the schedule version in force, and the
  monitor definitions in force, by version.
- Agreed service time, what was excluded and what was left.
- Availability, the user-weighted figure, coverage, downtime, outage
  count, MTBF and MTRS.
- Every outage, every exclusion with its declared-at and lead time,
  every coverage gap, every incident.
- Each objective: met, breached or indeterminate, with the reason.
- The folded readings the arithmetic used, an inclusion proof for the
  report's own row, and the signed checkpoint anchoring the state it was
  recorded in.

## Checking one

`monitor-verify report` recomputes all of it from the bundled evidence
and compares. It also looks for downtime present in the readings and
absent from the report, which is the check that matters in an argument.
See [auditing.md](auditing.md).
