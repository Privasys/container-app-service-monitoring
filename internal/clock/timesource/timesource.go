// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package timesource is the platform clock's own idea of the time.
//
// The monitor runs on a host too, and its host can be wrong or lie in
// exactly the way the enclaves' hosts can. So the time it signs into a
// floor does not come from the host's wall clock. It comes from Network
// Time Security (RFC 8915): a TLS 1.3 key exchange with a named server
// whose certificate is checked, then NTP packets authenticated with the
// keys that exchange produced. A host that answers NTP on a server's
// behalf cannot forge those packets.
//
// Two servers are asked, picked at random from a list compiled into the
// build. They must agree within two seconds. If they do not, a third is
// asked and two that agree win. Otherwise there is no trusted time, and
// the monitor says so rather than guessing.
//
// Between two fetches the time moves with Go's monotonic clock, which
// the host cannot set. The fetched value is kept as an offset from that
// monotonic reading, never from the wall clock, so a host that steps its
// wall clock after a fetch changes nothing.
package timesource

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

// Server is one pinned NTS server. One per operator, so two servers
// picked at random always come from two different organisations.
type Server struct {
	Host     string `json:"host"`
	Operator string `json:"operator"`
	Country  string `json:"country"`
}

// Servers is the pinned list. It is compiled in, so it is part of the
// measurement: whoever could change the list could point the monitor at
// servers they run, and a valid certificate for a hostname one controls
// is easy to get. Changing it is a new build.
var Servers = []Server{
	{Host: "nts.netnod.se", Operator: "Netnod", Country: "SE"},
	{Host: "ptbtime1.ptb.de", Operator: "PTB", Country: "DE"},
	{Host: "nts.time.nl", Operator: "TimeNL (SIDN)", Country: "NL"},
	{Host: "time.cloudflare.com", Operator: "Cloudflare", Country: "EU"},
	{Host: "ntp3.fau.de", Operator: "FAU Erlangen-Nuernberg", Country: "DE"},
	{Host: "ntp1.cam.ac.uk", Operator: "University of Cambridge", Country: "GB"},
	{Host: "nts2.ntp.hr", Operator: "University of Zagreb, FER", Country: "HR"},
	{Host: "paris.time.system76.com", Operator: "System76", Country: "FR"},
	{Host: "ntp1.rdem-systems.com", Operator: "RDEM Systems", Country: "FR"},
	{Host: "nts.teambelgium.net", Operator: "Team Belgium", Country: "BE"},
}

// MinTrustedTime is the earliest time this build will ever accept. A
// fresh instance never believes a time before its own source was
// written, whatever its host says. Bumped from time to time.
var MinTrustedTime = time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)

const (
	// Agreement is how close two servers must be to count as agreeing.
	Agreement = 2 * time.Second
	// MaxRTT is the slowest reply accepted. The round trip is measured on
	// the monotonic clock, and a reply held back by the host moves the
	// estimate by at most half of it.
	MaxRTT = 2 * time.Second
	// MaxAge is how long a fetched time keeps being extrapolated when
	// later fetches fail. Past it the monitor has no trusted time.
	MaxAge = 30 * time.Minute
	// queryTimeout bounds the key exchange and the NTP query each.
	queryTimeout = 5 * time.Second
)

// Sample is one server's answer, as an offset from the source's local
// monotonic clock.
type Sample struct {
	Server string        `json:"server"`
	Offset time.Duration `json:"-"`
	RTT    time.Duration `json:"-"`
	RTTMs  int64         `json:"rtt_ms"`
}

// Query asks one server. local is the clock the round trip and offset
// are measured against; verifyAt is the time the server's certificate
// is checked at.
type Query func(ctx context.Context, host string, local, verifyAt func() time.Time) (Sample, error)

// Status is what the fleet view shows about the monitor's own time.
type Status struct {
	Synced        bool     `json:"synced"`
	NowMs         int64    `json:"now_ms,omitempty"`
	LastFetchMs   int64    `json:"last_fetch_ms,omitempty"`
	AgeSeconds    int64    `json:"age_seconds,omitempty"`
	Servers       []string `json:"servers,omitempty"`
	LastError     string   `json:"last_error,omitempty"`
	LastErrorAtMs int64    `json:"last_error_at_ms,omitempty"`
}

// Source is the monitor's trusted time.
type Source struct {
	query   Query
	servers []Server
	rng     func(n int) []int
	wall    func() time.Time

	// base anchors the local clock: a reading of the monotonic clock,
	// and the wall time it happened to carry. Only the monotonic part
	// moves the local clock afterwards.
	base time.Time

	mu       sync.Mutex
	has      bool
	offset   time.Duration
	fetched  time.Time // local clock at the last successful fetch
	used     []string
	floor    time.Time
	lastErr  error
	lastErrL time.Time
}

// New returns a source over the pinned servers.
func New() *Source {
	return NewWith(queryNTS, Servers)
}

// NewWith returns a source with an injected query, for tests.
func NewWith(q Query, servers []Server) *Source {
	return &Source{
		query: q, servers: servers, base: time.Now(), wall: time.Now,
		rng: func(n int) []int { return rand.Perm(n) },
	}
}

// local is the monotonic clock, expressed as a time.
func (s *Source) local() time.Time {
	return s.base.Add(time.Since(s.base)).Round(0)
}

// SetFloor raises the earliest time the source will report, from a
// value it trusted before (the last reading in the record).
func (s *Source) SetFloor(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.After(s.floor) {
		s.floor = t
	}
}

// Now returns the trusted time, and false when there is none: never
// fetched, or last fetched longer ago than MaxAge.
func (s *Source) Now() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nowLocked()
}

func (s *Source) nowLocked() (time.Time, bool) {
	if !s.has {
		return time.Time{}, false
	}
	l := s.local()
	if l.Sub(s.fetched) > MaxAge {
		return time.Time{}, false
	}
	t := l.Add(s.offset)
	if t.Before(s.floor) {
		t = s.floor
	}
	return t.UTC(), true
}

// Floor is the earliest time the source can vouch for right now: the
// trusted time when there is one, otherwise the highest time it trusted
// before, and never earlier than the build.
func (s *Source) Floor() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := MinTrustedTime
	if s.floor.After(f) {
		f = s.floor
	}
	if s.has {
		// A stale fetch is still a lower bound: the monotonic clock only
		// moves forward.
		if t := s.local().Add(s.offset); t.After(f) {
			f = t
		}
	}
	return f.UTC()
}

// verifyAt is the time an NTS server's certificate is checked at.
//
// It is never earlier than the floor, so a host that rolls its clock
// back cannot make a certificate that has since expired look valid.
// When the host's clock is ahead of the floor it is used instead: that
// can only make more certificates look expired, never fewer, and it
// keeps a certificate issued after the floor from being refused as not
// yet valid by an instance that has been away a long time.
func (s *Source) verifyAt() time.Time {
	f := s.Floor()
	if h := s.wall(); h.After(f) {
		return h
	}
	return f
}

// Status reports the source's position.
func (s *Source) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Servers: append([]string(nil), s.used...)}
	if t, ok := s.nowLocked(); ok {
		st.Synced = true
		st.NowMs = t.UnixMilli()
	}
	if s.has {
		st.LastFetchMs = s.fetched.Add(s.offset).UnixMilli()
		st.AgeSeconds = int64(s.local().Sub(s.fetched) / time.Second)
	}
	if s.lastErr != nil {
		st.LastError = s.lastErr.Error()
		st.LastErrorAtMs = s.lastErrL.Add(s.offset).UnixMilli()
	}
	return st
}

// ErrNoQuorum means no two servers agreed.
var ErrNoQuorum = errors.New("timesource: no two NTS servers agreed")

// Refresh asks the servers and, when two agree, adopts their time.
func (s *Source) Refresh(ctx context.Context) ([]Sample, error) {
	samples, offset, err := s.quorum(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr, s.lastErrL = err, s.local()
		return samples, err
	}
	s.has, s.offset, s.fetched = true, offset, s.local()
	s.used = s.used[:0]
	for _, smp := range samples {
		s.used = append(s.used, smp.Server)
	}
	s.lastErr = nil
	return samples, nil
}

// quorum runs the two-then-three selection.
func (s *Source) quorum(ctx context.Context) ([]Sample, time.Duration, error) {
	if len(s.servers) < 2 {
		return nil, 0, errors.New("timesource: fewer than two servers are pinned")
	}
	order := s.rng(len(s.servers))
	var got []Sample
	var failures []string
	next := 0

	ask := func(n int) {
		type result struct {
			sample Sample
			err    error
			host   string
		}
		results := make(chan result, n)
		launched := 0
		for i := 0; i < n && next < len(order); i++ {
			host := s.servers[order[next]].Host
			next++
			go func(host string) {
				smp, err := s.query(ctx, host, s.local, s.verifyAt)
				if err == nil && smp.RTT > MaxRTT {
					err = fmt.Errorf("round trip of %s exceeds %s", smp.RTT.Round(time.Millisecond), MaxRTT)
				}
				smp.Server = host
				smp.RTTMs = smp.RTT.Milliseconds()
				results <- result{sample: smp, err: err, host: host}
			}(host)
			launched++
		}
		for i := 0; i < launched; i++ {
			r := <-results
			if r.err != nil {
				failures = append(failures, r.host+": "+r.err.Error())
				continue
			}
			got = append(got, r.sample)
		}
	}

	// Two at random, then one more for a majority when they disagree or
	// one did not answer. Three servers is the most a single refresh
	// asks: a network that loses more than that is not one to take a
	// time from.
	ask(2)
	if offset, pair, ok := agreeing(got); ok {
		return pair, offset, nil
	}
	ask(1)
	if offset, pair, ok := agreeing(got); ok {
		return pair, offset, nil
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		return got, 0, fmt.Errorf("%w (%d answered; %v)", ErrNoQuorum, len(got), failures)
	}
	return got, 0, ErrNoQuorum
}

// agreeing returns the mean offset of the closest pair of samples that
// agree within Agreement.
func agreeing(samples []Sample) (time.Duration, []Sample, bool) {
	found := false
	var bestPair [2]int
	var bestGap time.Duration
	for i := 0; i < len(samples); i++ {
		for j := i + 1; j < len(samples); j++ {
			gap := samples[i].Offset - samples[j].Offset
			if gap < 0 {
				gap = -gap
			}
			if gap <= Agreement && (!found || gap < bestGap) {
				found, bestGap, bestPair = true, gap, [2]int{i, j}
			}
		}
	}
	if !found {
		return 0, nil, false
	}
	a, b := samples[bestPair[0]], samples[bestPair[1]]
	return a.Offset + (b.Offset-a.Offset)/2, []Sample{a, b}, true
}

// queryNTS is the real query: an NTS key exchange, then one
// authenticated NTP exchange.
func queryNTS(ctx context.Context, host string, local, verifyAt func() time.Time) (Sample, error) {
	type result struct {
		sample Sample
		err    error
	}
	done := make(chan result, 1)
	go func() {
		session, err := nts.NewSessionWithOptions(host, &nts.SessionOptions{
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Time: verifyAt},
			Timeout:   queryTimeout,
		})
		if err != nil {
			done <- result{err: fmt.Errorf("key exchange: %w", err)}
			return
		}
		resp, err := session.QueryWithOptions(&ntp.QueryOptions{
			Timeout: queryTimeout, GetSystemTime: local,
		})
		if err != nil {
			done <- result{err: fmt.Errorf("query: %w", err)}
			return
		}
		if err := resp.Validate(); err != nil {
			done <- result{err: fmt.Errorf("reply: %w", err)}
			return
		}
		done <- result{sample: Sample{Offset: resp.ClockOffset, RTT: resp.RTT}}
	}()
	select {
	case <-ctx.Done():
		return Sample{}, ctx.Err()
	case r := <-done:
		return r.sample, r.err
	}
}
