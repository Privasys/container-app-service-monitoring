// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"fmt"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// When to quarantine, and when to release.
//
// A quarantine stops the gateways serving an enclave's apps, so users
// are not handed answers computed on a frozen or wrong clock. It is
// decided on a poll's answer, never on an incident report, because
// anyone can send a report and only an attested runtime can answer a
// poll. These quarantine:
//
//   - the runtime's verdict is host_clock_wrong: the floor and NTS agree
//     and the host does not;
//   - the runtime answers flagged: it is serving a frozen time;
//   - the runtime has no trusted time at all and is failing closed,
//     whether it says so in an answer (nts_unreachable) or refuses the
//     floor because its host and the floor disagree and NTS is silent;
//   - the host clock is more than the tolerance from the monitor's, and
//     the runtime did not find the monitor to be the one that is wrong.
//
// And silence: an enclave that was flagged at its last answer and now
// does not answer is quarantined at once, and any enclave that does not
// answer MaxFailedPolls polls in a row is quarantined whatever it said
// before, with the reason "unreachable". A host that blocks the monitor
// must not keep users on a clock it broke.
//
// A release needs the opposite, all of it at once: an attested answer,
// verdict in_sync, not flagged, and within the tolerance. The monitor
// only ever lifts a quarantine it placed itself. One an operator placed
// is theirs to lift.
//
// A runtime that does not hold this monitor's key is not a clock
// problem. It is reported, and never quarantined for on its own.

// MaxFailedPolls is how many polls in a row may get no answer before the
// enclave is quarantined, whatever it said before. A host can keep the
// monitor out (drop the manager route, or hold the runtime's NTS fetch
// past the poll timeout) while its clock is wrong and nothing is flagged
// yet. Two silent rounds in a row, about five minutes apart, are enough
// to act on; one lost connection is not.
const MaxFailedPolls = 2

// Decision is what a reading calls for.
type Decision struct {
	// Op is model.ClockOpQuarantine, model.ClockOpRelease, or empty.
	Op     string
	Reason string
}

// configMissing reports whether a reading shows that the runtime does
// not hold this monitor's key.
func configMissing(r model.ClockReading, keyID string) bool {
	switch r.Outcome {
	case model.ClockOutcomeOK:
		return r.ConfigKeyID != keyID
	case model.ClockOutcomeRefused:
		// 409: no monitor pinned. 401: a floor that is not the pinned
		// monitor's, which for a genuine floor means another key.
		return r.HTTPStatus == 409 || r.HTTPStatus == 401
	}
	return false
}

// Decide applies the rules to one reading. prev is the position before
// it; platformQuarantined is what the platform last said.
func Decide(prev model.ClockEnclave, r model.ClockReading, platformQuarantined bool, keyID string) Decision {
	ours := prev.Quarantined
	if r.Outcome == model.ClockOutcomeOK {
		if reason := clockProblem(r); reason != "" {
			if ours || platformQuarantined {
				// Already out of service: ours stays, an operator's is
				// theirs.
				return Decision{}
			}
			return Decision{Op: model.ClockOpQuarantine, Reason: reason}
		}
		if ours && r.Verdict == VerdictInSync && !r.Flagged && r.TrustedMs != 0 &&
			abs(r.DriftMs) <= Tolerance {
			return Decision{Op: model.ClockOpRelease, Reason: fmt.Sprintf(
				"clock: the host clock is back in sync (drift %s, verdict in_sync, not flagged)",
				fmtMs(r.DriftMs))}
		}
		return Decision{}
	}
	if configMissing(r, keyID) {
		return Decision{}
	}
	if failedClosed(r) && !ours && !platformQuarantined {
		return Decision{Op: model.ClockOpQuarantine, Reason: fmt.Sprintf(
			"clock: the runtime cannot establish its time and has failed closed (%s)", orDash(r.Error))}
	}
	if r.Outcome == model.ClockOutcomeUnreachable && prev.FailedPolls+1 >= MaxFailedPolls &&
		!ours && !platformQuarantined {
		return Decision{Op: model.ClockOpQuarantine, Reason: fmt.Sprintf(
			"unreachable: %d consecutive polls got no answer (%s)", prev.FailedPolls+1, orDash(r.Error))}
	}
	if prev.LastFlagged && !ours && !platformQuarantined {
		return Decision{Op: model.ClockOpQuarantine, Reason: fmt.Sprintf(
			"clock: the runtime was flagged at its last answer (%s) and is now %s",
			orDash(prev.LastReason), r.Outcome)}
	}
	return Decision{}
}

// clockProblem returns why an answered reading calls for a quarantine,
// or "" when it does not.
func clockProblem(r model.ClockReading) string {
	switch {
	case r.Verdict == VerdictHostWrong:
		return fmt.Sprintf("clock: host_clock_wrong (host %s, NTS %s, monitor %s)",
			fmtTime(r.HostMs), fmtTime(r.NTSMs), fmtTime(r.SentMs))
	case r.Verdict == VerdictMonitorWrong:
		// The runtime asked NTS and found the host right and the monitor
		// wrong. Nothing about the enclave calls for a quarantine.
		return ""
	case r.TrustedMs == 0 || r.Reason == ReasonNTSUnreachable:
		return fmt.Sprintf("clock: the runtime has no trusted time and is failing closed (reason: %s)",
			orDash(r.Reason))
	case r.Flagged:
		return fmt.Sprintf("clock: the runtime is serving a frozen time (flagged: %s)", orDash(r.Reason))
	case abs(r.DriftMs) > Tolerance:
		return fmt.Sprintf("clock: host clock drift of %s (host %s, monitor %s)",
			fmtMs(r.DriftMs), fmtTime(r.HostMs), fmtTime(r.MonitorMs))
	}
	return ""
}

// failedClosed reports a runtime that refused the floor because it
// cannot establish its time: its host and the floor disagree and NTS
// did not answer. A runtime that merely lacks the clock (an older
// build) answers differently and is not a clock problem.
func failedClosed(r model.ClockReading) bool {
	return r.Outcome == model.ClockOutcomeRefused && r.HTTPStatus == 503 &&
		!strings.Contains(strings.ToLower(r.Error), "not enabled")
}

// Drift is the host's time minus the monitor's at the midpoint of the
// round trip.
func Drift(hostMs, sentMs, receivedMs int64) int64 {
	return hostMs - (sentMs + (receivedMs-sentMs)/2)
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func fmtMs(ms int64) string {
	return (time.Duration(ms) * time.Millisecond).String()
}

func fmtTime(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
