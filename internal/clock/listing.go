// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"context"
	"errors"
	"time"
)

// The enclave list.
//
// The list decides which incident reports are taken, so it must exist
// before the first report arrives and must catch up with an enclave that
// registered since the last round. It is fetched once as soon as the
// clock starts, again at every round, and when a report names an enclave
// the list does not have, at most once a listRefreshGap for that reason.
// Fetches never overlap: whoever asks while one is in flight waits for
// it, so a flood of reports naming made-up enclaves costs the control
// plane at most one call a minute.

// listRefreshGap is the shortest gap between two fetches that an unknown
// enclave id can cause.
const listRefreshGap = time.Minute

// listTimeout bounds one fetch of the list.
const listTimeout = 20 * time.Second

// listFlight is a fetch in progress.
type listFlight struct {
	done chan struct{}
	err  error
}

// refreshList fetches the list. force is for the start and the rounds;
// without it, a fetch that started less than listRefreshGap ago means no
// new one. Either way a fetch in flight is joined, not repeated. The
// fetch runs on its own deadline, so a caller that gives up waiting does
// not cancel it for the others.
func (s *Service) refreshList(ctx context.Context, force bool) error {
	s.mu.Lock()
	if f := s.listing; f != nil {
		s.mu.Unlock()
		return waitFlight(ctx, f)
	}
	if !force && !s.listTried.IsZero() && time.Since(s.listTried) < listRefreshGap {
		s.mu.Unlock()
		return nil
	}
	platform := s.platform
	if platform == nil {
		s.mu.Unlock()
		return errors.New("clock: the platform clock is off")
	}
	f := &listFlight{done: make(chan struct{})}
	s.listing, s.listTried = f, time.Now()
	s.mu.Unlock()

	go func() {
		fetchCtx, cancel := context.WithTimeout(context.Background(), listTimeout)
		listed, err := platform.Enclaves(fetchCtx)
		cancel()
		s.mu.Lock()
		if err == nil {
			s.enclaves = make(map[string]Enclave, len(listed))
			for _, e := range listed {
				s.enclaves[e.ID] = e
			}
			s.listedAt = time.Now()
		}
		f.err = err
		s.listing = nil
		s.mu.Unlock()
		close(f.done)
	}()
	return waitFlight(ctx, f)
}

func waitFlight(ctx context.Context, f *listFlight) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// lookup finds an enclave in the current list.
func (s *Service) lookup(enclaveID string) (Enclave, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.enclaves[enclaveID]
	return e, ok
}

// lookupOrRefresh finds an enclave, fetching the list once (within the
// limits above) when it is not there.
func (s *Service) lookupOrRefresh(ctx context.Context, enclaveID string) (Enclave, bool) {
	if e, ok := s.lookup(enclaveID); ok {
		return e, true
	}
	if err := s.refreshList(ctx, false); err != nil {
		s.log.Warn("could not refresh the enclave list", "error", err)
	}
	return s.lookup(enclaveID)
}
