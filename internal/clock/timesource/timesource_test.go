// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package timesource

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeServers answers each host with a fixed offset from the local
// clock, or an error.
type fakeServers struct {
	mu      sync.Mutex
	offsets map[string]time.Duration
	rtt     map[string]time.Duration
	fail    map[string]bool
	asked   []string
}

func (f *fakeServers) query(_ context.Context, host string, _ func() time.Time, _ func() time.Time) (Sample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, host)
	if f.fail[host] {
		return Sample{}, errors.New("no answer")
	}
	return Sample{Offset: f.offsets[host], RTT: f.rtt[host]}, nil
}

var hosts = []Server{{Host: "a"}, {Host: "b"}, {Host: "c"}, {Host: "d"}}

// inOrder makes the "random" choice deterministic: a, b, c, d.
func inOrder(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func newSource(f *fakeServers) *Source {
	s := NewWith(f.query, hosts)
	s.rng = inOrder
	return s
}

func TestTwoAgreeingServersAreEnough(t *testing.T) {
	f := &fakeServers{offsets: map[string]time.Duration{"a": time.Hour, "b": time.Hour + time.Second}}
	s := newSource(f)
	samples, err := s.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 || len(f.asked) != 2 {
		t.Fatalf("asked %v, kept %d samples; two agreeing servers should be enough", f.asked, len(samples))
	}
	now, ok := s.Now()
	if !ok {
		t.Fatal("no trusted time after a successful refresh")
	}
	// The mean of the two offsets, on top of the local clock.
	want := time.Now().Add(time.Hour + 500*time.Millisecond)
	if d := now.Sub(want); d < -time.Second || d > time.Second {
		t.Fatalf("trusted time %s, want about %s", now, want)
	}
}

func TestADisagreementIsSettledByAThirdServer(t *testing.T) {
	f := &fakeServers{offsets: map[string]time.Duration{
		"a": 0, "b": 10 * time.Minute, "c": 500 * time.Millisecond,
	}}
	s := newSource(f)
	samples, err := s.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 3 {
		t.Fatalf("asked %v; a disagreement should bring in exactly one more server", f.asked)
	}
	for _, smp := range samples {
		if smp.Server == "b" {
			t.Fatal("the server in the minority was kept")
		}
	}
}

func TestNoMajorityMeansNoTime(t *testing.T) {
	f := &fakeServers{offsets: map[string]time.Duration{
		"a": 0, "b": 10 * time.Minute, "c": 20 * time.Minute,
	}}
	s := newSource(f)
	if _, err := s.Refresh(context.Background()); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("three disagreeing servers gave %v, want no quorum", err)
	}
	if _, ok := s.Now(); ok {
		t.Fatal("a source with no quorum reported a trusted time")
	}
	if st := s.Status(); st.Synced || st.LastError == "" {
		t.Fatalf("the status hides the failure: %+v", st)
	}
}

func TestASilentServerIsReplacedButTwoAreNot(t *testing.T) {
	f := &fakeServers{offsets: map[string]time.Duration{"b": time.Second, "c": time.Second}, fail: map[string]bool{"a": true}}
	s := newSource(f)
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatalf("one silent server should be replaced by a third: %v", err)
	}

	f = &fakeServers{offsets: map[string]time.Duration{"c": 0}, fail: map[string]bool{"a": true, "b": true}}
	s = newSource(f)
	if _, err := s.Refresh(context.Background()); err == nil {
		t.Fatal("a single answering server was taken as a quorum")
	}
}

func TestASlowReplyIsRefused(t *testing.T) {
	f := &fakeServers{
		offsets: map[string]time.Duration{"a": 0, "b": 0, "c": 0},
		rtt:     map[string]time.Duration{"a": 5 * time.Second},
	}
	s := newSource(f)
	samples, err := s.Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, smp := range samples {
		if smp.Server == "a" {
			t.Fatal("a reply slower than the limit was used")
		}
	}
}

func TestAStaleFetchStopsBeingTrustedTimeButStaysAFloor(t *testing.T) {
	f := &fakeServers{offsets: map[string]time.Duration{"a": time.Hour, "b": time.Hour}}
	s := newSource(f)
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Age the fetch past the limit by moving the anchor back.
	s.mu.Lock()
	s.fetched = s.fetched.Add(-MaxAge - time.Minute)
	s.mu.Unlock()
	if _, ok := s.Now(); ok {
		t.Fatal("a fetch older than the limit is still reported as trusted time")
	}
	if floor := s.Floor(); floor.Before(time.Now().Add(59 * time.Minute)) {
		t.Fatalf("the floor %s fell back below what was fetched", floor)
	}
}

func TestTheFloorNeverGoesBelowTheBuild(t *testing.T) {
	s := newSource(&fakeServers{})
	if s.Floor().Before(MinTrustedTime) {
		t.Fatalf("floor %s is below the build's minimum %s", s.Floor(), MinTrustedTime)
	}
	// A host clock set years back does not move the certificate check
	// time below the floor.
	s.wall = func() time.Time { return time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC) }
	if at := s.verifyAt(); at.Before(MinTrustedTime) {
		t.Fatalf("certificates would be checked at %s, below the floor", at)
	}
	later := time.Now().Add(365 * 24 * time.Hour)
	s.SetFloor(later)
	if s.Floor().Before(later) {
		t.Fatal("SetFloor did not raise the floor")
	}
}

func TestThePinnedListIsTenOperators(t *testing.T) {
	if len(Servers) != 10 {
		t.Fatalf("%d servers pinned, want 10", len(Servers))
	}
	seen := map[string]bool{}
	for _, s := range Servers {
		if seen[s.Operator] {
			t.Fatalf("operator %q is pinned twice", s.Operator)
		}
		seen[s.Operator] = true
	}
}
