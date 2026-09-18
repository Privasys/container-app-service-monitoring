// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// Shutting down.
//
// Work the clock starts in the background (the poll an incident report
// causes, and the round in flight) writes to the record, and the record
// is closed when the process stops. So shutdown is an order, not a
// signal: no new background work is started, the work in flight is told
// to stop and waited for, a bounded time, and only then is the record
// let go. Any write that comes later still, from work that did not stop
// in time, is dropped rather than made to a closed store.

// shutdownWait bounds how long Shutdown waits for background work.
var shutdownWait = 5 * time.Second

// ErrShuttingDown refuses work that arrives once shutdown has begun.
var ErrShuttingDown = errors.New("clock: the monitor is shutting down")

// lifecycle is the part of the service that shutdown needs.
type lifecycle struct {
	// bgCtx is cancelled when shutdown begins; background work runs on it.
	bgCtx    context.Context
	bgCancel context.CancelFunc
	bg       sync.WaitGroup

	// storeMu guards every write to the record against the store closing:
	// writers hold it shared, Shutdown takes it exclusively to set gone.
	storeMu sync.RWMutex
	closing bool
	gone    bool
}

func newLifecycle() lifecycle {
	ctx, cancel := context.WithCancel(context.Background())
	return lifecycle{bgCtx: ctx, bgCancel: cancel}
}

// goBackground runs fn as tracked background work, or reports false
// once shutdown has begun.
func (s *Service) goBackground(fn func(ctx context.Context)) bool {
	s.life.storeMu.RLock()
	defer s.life.storeMu.RUnlock()
	if s.life.closing {
		return false
	}
	s.life.bg.Add(1)
	go func() {
		defer s.life.bg.Done()
		fn(s.life.bgCtx)
	}()
	return true
}

// Shutdown stops the clock for good: no new background work, the work in
// flight cancelled and waited for (at most shutdownWait), the scheduled
// rounds stopped, and every later write dropped. The caller may close
// the record once it returns.
func (s *Service) Shutdown() {
	s.life.storeMu.Lock()
	s.life.closing = true
	s.life.storeMu.Unlock()
	s.life.bgCancel()

	finished := make(chan struct{})
	go func() {
		s.Stop()
		s.life.bg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(shutdownWait):
		s.log.Warn("clock work was still running at shutdown; its writes will be dropped")
	}

	s.life.storeMu.Lock()
	s.life.gone = true
	s.life.storeMu.Unlock()
}

// withStore runs fn unless the record has been let go.
func (s *Service) withStore(fn func() error) error {
	s.life.storeMu.RLock()
	defer s.life.storeMu.RUnlock()
	if s.life.gone {
		return ErrShuttingDown
	}
	return fn()
}

// The record calls the clock makes, each guarded.

func (s *Service) raiseAlert(event, subject, message string, payload map[string]any) error {
	return s.withStore(func() error { return s.mon.RaiseClockAlert(event, subject, message, payload) })
}

func (s *Service) recordReadings(readings []model.ClockReading, states []model.ClockEnclave, message string) error {
	return s.withStore(func() error {
		_, err := s.mon.RecordClockReadings(readings, states, message)
		return err
	})
}

func (s *Service) recordAction(a model.ClockAction, st model.ClockEnclave, event string, payload map[string]any) error {
	return s.withStore(func() error {
		_, err := s.mon.RecordClockAction(a, st, event, payload)
		return err
	})
}

func (s *Service) recordIncident(inc model.ClockIncident) error {
	return s.withStore(func() error {
		_, err := s.mon.RecordClockIncident(inc)
		return err
	})
}

func (s *Service) enclaveState(enclaveID string) (*model.ClockEnclave, error) {
	var st *model.ClockEnclave
	err := s.withStore(func() error {
		var err error
		st, err = s.mon.ClockEnclave(enclaveID)
		return err
	})
	return st, err
}

// shuttingDown reports whether shutdown has begun.
func (s *Service) shuttingDown() bool {
	s.life.storeMu.RLock()
	defer s.life.storeMu.RUnlock()
	return s.life.closing
}
