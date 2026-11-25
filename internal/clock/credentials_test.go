// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// refusingPlatform refuses every credentials call, as a control plane
// under load or with a lapsed identity does.
type refusingPlatform struct {
	fakePlatform
	asked atomic.Int32
}

func (p *refusingPlatform) AttestationCredentials(context.Context) (string, string, time.Time, error) {
	p.asked.Add(1)
	return "", "", time.Time{}, errors.New("answered 401")
}

func TestARefusalIsNotAskedAgainForEveryEnclave(t *testing.T) {
	p := &refusingPlatform{fakePlatform: fakePlatform{quarantined: map[string]string{}}}
	s := &Service{platform: p}
	for range 25 {
		if _, _, err := s.credentials(context.Background()); err == nil {
			t.Fatal("a refused call answered credentials")
		}
	}
	if n := p.asked.Load(); n != 1 {
		t.Fatalf("the control plane was asked %d times in one round, want once", n)
	}
	s.mu.Lock()
	wait := time.Until(s.creds.retryAt)
	s.mu.Unlock()
	if wait < credentialRetryBase/2-time.Second || wait > credentialRetryBase {
		t.Fatalf("next attempt in %v, want between %v and %v", wait, credentialRetryBase/2, credentialRetryBase)
	}

	// Once the wait has passed the next refusal doubles it.
	s.mu.Lock()
	s.creds.retryAt = time.Now()
	s.mu.Unlock()
	_, _, _ = s.credentials(context.Background())
	s.mu.Lock()
	wait = time.Until(s.creds.retryAt)
	s.mu.Unlock()
	if p.asked.Load() != 2 || wait < credentialRetryBase-time.Second || wait > 2*credentialRetryBase {
		t.Fatalf("second refusal: asked %d, next attempt in %v", p.asked.Load(), wait)
	}
}
