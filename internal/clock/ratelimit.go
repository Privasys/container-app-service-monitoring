// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import "time"

// rateLimit admits at most perKey events a minute for one key and
// global events a minute in all, each as a token bucket that refills
// evenly over the minute. It is not safe for concurrent use; the service
// calls it under its own lock.
type rateLimit struct {
	perKey, global float64
	all            bucket
	keys           map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newRateLimit(perKey, global int) *rateLimit {
	return &rateLimit{perKey: float64(perKey), global: float64(global), keys: map[string]*bucket{}}
}

// take refills b for the time since it was last used and spends one
// token if there is one.
func (b *bucket) take(capacity float64, now time.Time, spend bool) bool {
	if b.at.IsZero() {
		b.tokens = capacity
	} else if elapsed := now.Sub(b.at); elapsed > 0 {
		b.tokens += capacity * elapsed.Minutes()
		if b.tokens > capacity {
			b.tokens = capacity
		}
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	if spend {
		b.tokens--
	}
	return true
}

// allow reports whether one more event for key is admitted, and counts
// it when it is. A refusal by either bucket spends nothing.
func (r *rateLimit) allow(key string, now time.Time) bool {
	b, ok := r.keys[key]
	if !ok {
		// Keys are enclave ids from the platform's list, so the map stays
		// the size of the fleet.
		b = &bucket{}
		r.keys[key] = b
	}
	if !b.take(r.perKey, now, false) || !r.all.take(r.global, now, false) {
		return false
	}
	b.take(r.perKey, now, true)
	r.all.take(r.global, now, true)
	return true
}
