// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package backoff spaces out retries of a call that keeps failing: each
// failure doubles the wait up to a cap, and every wait is jittered so
// many callers refused at once do not come back at once.
package backoff

import (
	"math/rand/v2"
	"sync"
	"time"
)

// Backoff counts consecutive failures. The zero value is not usable;
// build one with New. It is safe for concurrent use.
type Backoff struct {
	base, max time.Duration

	mu       sync.Mutex
	failures int
}

// New returns a backoff whose first wait is about base and whose waits
// never exceed max.
func New(base, max time.Duration) *Backoff {
	if base <= 0 {
		base = time.Second
	}
	if max < base {
		max = base
	}
	return &Backoff{base: base, max: max}
}

// Fail records a failure and returns how long to wait before trying
// again: base·2^(n-1) capped at max, then jittered to between half and
// all of it.
func (b *Backoff) Fail() time.Duration {
	b.mu.Lock()
	b.failures++
	n := b.failures
	b.mu.Unlock()
	return jitter(b.ceiling(n))
}

// Succeed forgets the failures.
func (b *Backoff) Succeed() {
	b.mu.Lock()
	b.failures = 0
	b.mu.Unlock()
}

func (b *Backoff) ceiling(n int) time.Duration {
	d := b.base
	for i := 1; i < n && d < b.max; i++ {
		d *= 2
	}
	if d > b.max {
		d = b.max
	}
	return d
}

func jitter(d time.Duration) time.Duration {
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + rand.N(half+1)
}
