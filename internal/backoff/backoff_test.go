// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package backoff

import (
	"testing"
	"time"
)

func TestWaitsGrowUpToTheCapAndStartAgainAfterASuccess(t *testing.T) {
	b := New(10*time.Second, 80*time.Second)
	for i, ceil := range []time.Duration{10, 20, 40, 80, 80, 80} {
		ceil *= time.Second
		d := b.Fail()
		if d < ceil/2 || d > ceil {
			t.Fatalf("failure %d: wait %v, want between %v and %v", i+1, d, ceil/2, ceil)
		}
	}
	b.Succeed()
	if d := b.Fail(); d > 10*time.Second {
		t.Fatalf("after a success the wait is %v, want at most the base", d)
	}
}

func TestWaitsAreSpreadOut(t *testing.T) {
	b := New(time.Minute, time.Minute)
	seen := map[time.Duration]bool{}
	for range 20 {
		seen[b.Fail()] = true
	}
	if len(seen) < 2 {
		t.Fatal("every wait was the same: no jitter")
	}
}
