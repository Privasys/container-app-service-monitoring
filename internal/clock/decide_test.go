// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

const key = "0123456789abcdef"

func answered(verdict string, flagged bool, drift int64) model.ClockReading {
	return model.ClockReading{
		Outcome: model.ClockOutcomeOK, Verdict: verdict, Flagged: flagged,
		DriftMs: drift, ConfigKeyID: key, TrustedMs: 1789000000000,
	}
}

func TestTheQuarantineRules(t *testing.T) {
	clean := model.ClockEnclave{}
	flaggedBefore := model.ClockEnclave{LastFlagged: true, LastReason: ReasonHostClockWrong}
	ours := model.ClockEnclave{Quarantined: true}

	cases := []struct {
		name       string
		prev       model.ClockEnclave
		reading    model.ClockReading
		platformQ  bool
		wantOp     string
		wantReason bool
	}{
		{"in sync", clean, answered(VerdictInSync, false, 200), false, "", false},
		{"host clock wrong", clean, answered(VerdictHostWrong, true, -3_600_000), false, model.ClockOpQuarantine, true},
		{"drift over the tolerance", clean, answered(VerdictIgnoredStale, false, 11_000), false, model.ClockOpQuarantine, true},
		{"drift under the tolerance", clean, answered(VerdictInSync, false, 9_000), false, "", false},
		{"serving a frozen time", clean, answered(VerdictIgnoredStale, true, 0), false, model.ClockOpQuarantine, true},
		// The monitor is the one that is wrong: whatever the drift, the
		// enclave is fine.
		{"monitor clock wrong", clean, answered(VerdictMonitorWrong, false, 90_000), false, "", false},
		// Already out of service: nothing more to ask for.
		{"already ours", ours, answered(VerdictHostWrong, true, 0), true, "", false},
		{"an operator's", clean, answered(VerdictHostWrong, true, 0), true, "", false},
		// Released only on a clean answer, and only when it is ours.
		{"release", ours, answered(VerdictInSync, false, 100), true, model.ClockOpRelease, true},
		{"no release while flagged", ours, answered(VerdictInSync, true, 100), true, "", false},
		{"no release on ignored_stale", ours, answered(VerdictIgnoredStale, false, 100), true, "", false},
		{"never lift an operator's", clean, answered(VerdictInSync, false, 0), true, "", false},
		// Silence.
		{"unreachable after flagged", flaggedBefore,
			model.ClockReading{Outcome: model.ClockOutcomeUnreachable}, false, model.ClockOpQuarantine, true},
		{"unverified after flagged", flaggedBefore,
			model.ClockReading{Outcome: model.ClockOutcomeUnverified}, false, model.ClockOpQuarantine, true},
		{"unreachable, never flagged", clean,
			model.ClockReading{Outcome: model.ClockOutcomeUnreachable}, false, "", false},
		// A runtime that lost the monitor's key is a configuration problem.
		{"refused as unconfigured after flagged", flaggedBefore,
			model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 409}, false, "", false},
		{"refused as failed closed after flagged", flaggedBefore,
			model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 503}, false, model.ClockOpQuarantine, true},
		// A runtime whose time cannot be established is unhealthy, flagged
		// before or not.
		{"failed closed", clean,
			model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 503,
				Error: `{"error":"trusted time unavailable: no two NTS servers agreed"}`},
			false, model.ClockOpQuarantine, true},
		{"answering but failing closed", clean,
			model.ClockReading{Outcome: model.ClockOutcomeOK, Verdict: VerdictInSync, ConfigKeyID: key,
				Reason: ReasonNTSUnreachable, TrustedMs: 0},
			false, model.ClockOpQuarantine, true},
		{"no release while failing closed", ours,
			model.ClockReading{Outcome: model.ClockOutcomeOK, Verdict: VerdictInSync, ConfigKeyID: key,
				Reason: ReasonNTSUnreachable},
			true, "", false},
		// An older runtime without the clock is not a clock problem.
		{"clock not enabled", clean,
			model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 503,
				Error: `{"error":"trusted clock not enabled on this runtime"}`},
			false, "", false},
		{"no clock route", clean,
			model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 404}, false, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(c.prev, c.reading, c.platformQ, key)
			if d.Op != c.wantOp {
				t.Fatalf("op %q, want %q (reason %q)", d.Op, c.wantOp, d.Reason)
			}
			if (d.Reason != "") != c.wantReason {
				t.Fatalf("reason %q", d.Reason)
			}
		})
	}
}

func TestAMissingConfigIsRecognised(t *testing.T) {
	for _, c := range []struct {
		r    model.ClockReading
		want bool
	}{
		{model.ClockReading{Outcome: model.ClockOutcomeOK, ConfigKeyID: key}, false},
		{model.ClockReading{Outcome: model.ClockOutcomeOK, ConfigKeyID: "ffffffffffffffff"}, true},
		{model.ClockReading{Outcome: model.ClockOutcomeOK}, true},
		{model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 409}, true},
		{model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 401}, true},
		{model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 503}, false},
		{model.ClockReading{Outcome: model.ClockOutcomeUnreachable}, false},
	} {
		if got := configMissing(c.r, key); got != c.want {
			t.Fatalf("%+v: missing=%v, want %v", c.r, got, c.want)
		}
	}
}

func TestDriftIsMeasuredAtTheMidpoint(t *testing.T) {
	// Sent at 1000, answered at 1200: the host said 1100 at the midpoint.
	if d := Drift(1100, 1000, 1200); d != 0 {
		t.Fatalf("drift %d, want 0", d)
	}
	if d := Drift(1100+15_000, 1000, 1200); d != 15_000 {
		t.Fatalf("drift %d, want 15000", d)
	}
}
