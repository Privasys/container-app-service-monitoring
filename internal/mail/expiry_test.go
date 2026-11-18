// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package mail

import (
	"testing"
	"time"
)

func TestExpiryWarningsAreGivenOnceEach(t *testing.T) {
	expires := time.Date(2028, 11, 17, 12, 0, 0, 0, time.UTC)
	days := func(n int) time.Time { return expires.Add(-time.Duration(n) * 24 * time.Hour) }
	cases := []struct {
		name   string
		at     time.Time
		warned []int
		want   int
	}{
		{"far off", days(61), nil, 0},
		{"at sixty days", days(60), nil, 60},
		{"sixty already given", days(45), []int{60}, 0},
		{"at thirty days", days(30), []int{60}, 30},
		{"both given", days(10), []int{60, 30}, 0},
		{"down through the first mark", days(20), nil, 30},
		{"already expired and unwarned", days(-1), nil, 30},
	}
	for _, c := range cases {
		got, ok := DueWarning(expires, c.at, c.warned)
		if got != c.want || ok != (c.want != 0) {
			t.Errorf("%s: %d %v, want %d", c.name, got, ok, c.want)
		}
	}
}

func TestGivenWarningsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	if got, err := LoadWarned(dir); err != nil || got != nil {
		t.Fatalf("empty: %v %v", got, err)
	}
	if err := SaveWarned(dir, []int{60}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWarned(dir)
	if err != nil || len(got) != 1 || got[0] != 60 {
		t.Fatalf("reloaded: %v %v", got, err)
	}
}
