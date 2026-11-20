// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package tenancy

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestAListingAskedForEarlyComesWithinSeconds(t *testing.T) {
	saved := syncMinGap
	syncMinGap = 20 * time.Millisecond
	defer func() { syncMinGap = saved }()

	h := New(Options{Dir: t.TempDir()}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var reads atomic.Int32
	source := func(context.Context) ([]App, bool, error) {
		reads.Add(1)
		return nil, false, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.RunSync(ctx, source, time.Hour)

	wait := func(n int32) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for reads.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("expected %d listings, saw %d", n, reads.Load())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	wait(1)
	// Three requests close together share one early read.
	h.RequestSync()
	h.RequestSync()
	h.RequestSync()
	wait(2)
	time.Sleep(100 * time.Millisecond)
	if n := reads.Load(); n > 3 {
		t.Fatalf("requests close together read %d times", n)
	}
}
