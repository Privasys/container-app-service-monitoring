// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package tickets is an app's support desk.
//
// Tickets hold what people write about themselves and their problems, so
// they are kept in ordinary files on the app's sealed volume and never in
// the append-only ledger: a ticket can be corrected, and it can be deleted.
package tickets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// The life of a ticket.
const (
	StatusNew        = "new"
	StatusTriaged    = "triaged"
	StatusAssigned   = "assigned"
	StatusInProgress = "in_progress"
	StatusWaiting    = "waiting" // on the requester
	StatusResolved   = "resolved"
	StatusClosed     = "closed"
)

var statuses = []string{StatusNew, StatusTriaged, StatusAssigned, StatusInProgress, StatusWaiting, StatusResolved, StatusClosed}

// Priorities.
const (
	PriorityLow    = "low"
	PriorityNormal = "normal"
	PriorityHigh   = "high"
	PriorityUrgent = "urgent"
)

var priorities = []string{PriorityLow, PriorityNormal, PriorityHigh, PriorityUrgent}

// Who may open a ticket for an app.
const (
	IntakeOff    = "off"
	IntakeTeam   = "team"   // the app's own team
	IntakePublic = "public" // anyone signed in with the wallet
)

// Limits on what one ticket may hold.
const (
	maxSubject  = 200
	maxBody     = 20000
	maxComments = 1000
	maxEvents   = 500
	maxCategory = 60
)

// Default rate limits, per person. They are generous on purpose: someone
// may be filing through an agent or the CLI.
const (
	DefaultTicketsPerHour  = 60
	DefaultTicketsPerDay   = 300
	DefaultCommentsPerHour = 300
)

// Errors a caller tells apart.
var (
	ErrNotFound = errors.New("no such ticket")
	ErrLimited  = errors.New("too many requests; try again later")
)

// InvalidError is a request that cannot be honoured as written.
type InvalidError struct{ Reason string }

func (e InvalidError) Error() string { return e.Reason }

func invalid(format string, a ...any) error { return InvalidError{fmt.Sprintf(format, a...)} }

// Comment is one reply on a ticket. An internal comment is a note for the
// team, which the requester never sees.
type Comment struct {
	ID         int    `json:"id"`
	Author     string `json:"author"`
	AuthorName string `json:"author_name,omitempty"`
	Team       bool   `json:"team"`
	Internal   bool   `json:"internal,omitempty"`
	Body       string `json:"body"`
	At         int64  `json:"at"`
}

// Event is one step of a ticket's history, for the team.
type Event struct {
	At     int64  `json:"at"`
	Actor  string `json:"actor,omitempty"`
	What   string `json:"what"`
	Detail string `json:"detail,omitempty"`
}

// Ticket is one request for help.
type Ticket struct {
	Number          int64     `json:"number"`
	Subject         string    `json:"subject"`
	Body            string    `json:"body"`
	Status          string    `json:"status"`
	Priority        string    `json:"priority"`
	Category        string    `json:"category,omitempty"`
	Requester       string    `json:"requester"`
	RequesterName   string    `json:"requester_name,omitempty"`
	Assignee        string    `json:"assignee,omitempty"`
	IncidentID      string    `json:"incident_id,omitempty"`
	Comments        []Comment `json:"comments,omitempty"`
	Events          []Event   `json:"events,omitempty"`
	CreatedAt       int64     `json:"created_at"`
	UpdatedAt       int64     `json:"updated_at"`
	FirstResponseAt int64     `json:"first_response_at,omitempty"`
	ResolvedAt      int64     `json:"resolved_at,omitempty"`
	ClosedAt        int64     `json:"closed_at,omitempty"`
}

// ForRequester is the ticket as the person who opened it sees it: the
// replies meant for them, and nothing of how the team works it.
func (t Ticket) ForRequester() Ticket {
	out := t
	out.Assignee, out.IncidentID, out.Events = "", "", nil
	out.Comments = nil
	for _, c := range t.Comments {
		if !c.Internal {
			out.Comments = append(out.Comments, c)
		}
	}
	return out
}

// Target is how soon a priority should be answered and resolved.
type Target struct {
	FirstResponseMinutes int `json:"first_response_minutes"`
	ResolutionMinutes    int `json:"resolution_minutes"`
}

// DefaultTargets are the targets an app starts with.
func DefaultTargets() map[string]Target {
	return map[string]Target{
		PriorityUrgent: {FirstResponseMinutes: 60, ResolutionMinutes: 8 * 60},
		PriorityHigh:   {FirstResponseMinutes: 4 * 60, ResolutionMinutes: 24 * 60},
		PriorityNormal: {FirstResponseMinutes: 8 * 60, ResolutionMinutes: 3 * 24 * 60},
		PriorityLow:    {FirstResponseMinutes: 24 * 60, ResolutionMinutes: 7 * 24 * 60},
	}
}

// Settings are how an app runs its desk.
type Settings struct {
	Intake          string            `json:"intake"`
	Categories      []string          `json:"categories,omitempty"`
	TicketsPerHour  int               `json:"tickets_per_hour"`
	TicketsPerDay   int               `json:"tickets_per_day"`
	CommentsPerHour int               `json:"comments_per_hour"`
	Targets         map[string]Target `json:"targets"`
}

// DefaultSettings is a desk that is closed until the team opens it.
func DefaultSettings() Settings {
	return Settings{
		Intake: IntakeOff, TicketsPerHour: DefaultTicketsPerHour, TicketsPerDay: DefaultTicketsPerDay,
		CommentsPerHour: DefaultCommentsPerHour, Targets: DefaultTargets(),
	}
}

// Validate refuses settings that could not be run.
func (s Settings) Validate() error {
	if s.Intake != IntakeOff && s.Intake != IntakeTeam && s.Intake != IntakePublic {
		return invalid("intake must be off, team or public")
	}
	if len(s.Categories) > 30 {
		return invalid("at most 30 categories")
	}
	for _, c := range s.Categories {
		if err := checkText("a category", c, maxCategory, false); err != nil {
			return err
		}
	}
	if s.TicketsPerHour < 1 || s.TicketsPerDay < s.TicketsPerHour || s.CommentsPerHour < 1 {
		return invalid("the limits must be positive, and the daily limit at least the hourly one")
	}
	for p, t := range s.Targets {
		if !slices.Contains(priorities, p) {
			return invalid("unknown priority %q", p)
		}
		if t.FirstResponseMinutes < 1 || t.ResolutionMinutes < t.FirstResponseMinutes {
			return invalid("a resolution target cannot be shorter than the first response")
		}
	}
	return nil
}

// Due is where a ticket stands against its targets.
type Due struct {
	FirstResponseBy int64 `json:"first_response_by"`
	ResolutionBy    int64 `json:"resolution_by"`
	FirstBreached   bool  `json:"first_response_breached"`
	ResolveBreached bool  `json:"resolution_breached"`
}

// DueOf works out a ticket's targets at now.
func (s Settings) DueOf(t Ticket, now int64) Due {
	target, ok := s.Targets[t.Priority]
	if !ok {
		target = DefaultTargets()[PriorityNormal]
	}
	d := Due{
		FirstResponseBy: t.CreatedAt + int64(target.FirstResponseMinutes)*60,
		ResolutionBy:    t.CreatedAt + int64(target.ResolutionMinutes)*60,
	}
	first, resolved := t.FirstResponseAt, t.ResolvedAt
	if first == 0 {
		first = now
	}
	if resolved == 0 {
		resolved = now
	}
	d.FirstBreached = first > d.FirstResponseBy
	d.ResolveBreached = resolved > d.ResolutionBy
	return d
}

// checkText refuses empty, oversized or control-laden text.
func checkText(name, s string, max int, multiline bool) error {
	if strings.TrimSpace(s) == "" {
		return invalid("%s is required", name)
	}
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return invalid("%s is at most %d characters", name, max)
	}
	for _, r := range s {
		if r < 0x20 && !(multiline && (r == '\n' || r == '\r' || r == '\t')) || r == 0x7f {
			return invalid("%s contains a control character", name)
		}
	}
	return nil
}

// Store is one app's desk.
type Store struct {
	dir string

	// Account is the defaults of the account the app belongs to
	// (account.go): what the desk runs on until its team sets its own.
	Account func() *Defaults

	mu       sync.Mutex
	settings Settings
	// own is whether the app's team set its settings.
	own     bool
	tickets map[int64]*Ticket
	next    int64
	hits    map[string][]int64
	notice  int64
}

var ticketFile = regexp.MustCompile(`^t-([0-9]+)\.json$`)

// Open reads the desk in dir, starting a closed one if there is none.
func Open(dir string) (*Store, error) {
	s := &Store{dir: dir, settings: DefaultSettings(), tickets: map[int64]*Ticket{}, next: 1, hits: map[string][]int64{}}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tickets: %w", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "settings.json")); err == nil {
		if err := json.Unmarshal(raw, &s.settings); err != nil {
			return nil, fmt.Errorf("tickets: settings: %w", err)
		}
		s.own = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("tickets: %w", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "next")); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && n > 0 {
			s.next = n
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("tickets: %w", err)
	}
	for _, e := range entries {
		if !ticketFile.MatchString(e.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("tickets: %w", err)
		}
		var t Ticket
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("tickets: %s: %w", e.Name(), err)
		}
		s.tickets[t.Number] = &t
		if t.Number >= s.next {
			s.next = t.Number + 1
		}
	}
	return s, nil
}

func (s *Store) writeFile(name string, raw []byte) error {
	tmp := filepath.Join(s.dir, name+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("tickets: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, name)); err != nil {
		return fmt.Errorf("tickets: %w", err)
	}
	return nil
}

func (s *Store) saveLocked(t *Ticket) error {
	raw, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("tickets: %w", err)
	}
	return s.writeFile(fmt.Sprintf("t-%d.json", t.Number), raw)
}

// Settings returns how the desk is run: its own settings, or its
// account's when its team set none.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.effectiveLocked().clone()
}

// SetSettings changes how the desk is run.
func (s *Store) SetSettings(in Settings) error {
	if err := in.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("tickets: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeFile("settings.json", raw); err != nil {
		return err
	}
	s.settings, s.own = in.clone(), true
	return nil
}

// allowLocked counts one use against the limits given as window seconds
// and allowance. Nothing is counted when any limit is already reached.
func (s *Store) allowLocked(key string, now int64, limits map[int64]int) bool {
	const day = 86400
	kept := s.hits[key][:0]
	for _, at := range s.hits[key] {
		if now-at < day {
			kept = append(kept, at)
		}
	}
	s.hits[key] = kept
	for window, allowance := range limits {
		n := 0
		for _, at := range kept {
			if now-at < window {
				n++
			}
		}
		if n >= allowance {
			return false
		}
	}
	s.hits[key] = append(kept, now)
	return true
}

// New is what someone writes when they open a ticket.
type New struct {
	Subject       string
	Body          string
	Category      string
	Requester     string
	RequesterName string
	// Unlimited lifts the rate limit, for the platform's operators.
	Unlimited bool
}

// Create opens a ticket.
func (s *Store) Create(in New, now int64) (Ticket, error) {
	if err := checkText("a subject", in.Subject, maxSubject, false); err != nil {
		return Ticket{}, err
	}
	if err := checkText("a description", in.Body, maxBody, true); err != nil {
		return Ticket{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.effectiveLocked()
	if in.Category != "" && !slices.Contains(cfg.Categories, in.Category) {
		return Ticket{}, invalid("unknown category %q", in.Category)
	}
	if !in.Unlimited && !s.allowLocked("ticket:"+in.Requester, now, map[int64]int{
		3600: cfg.TicketsPerHour, 86400: cfg.TicketsPerDay,
	}) {
		return Ticket{}, ErrLimited
	}
	t := &Ticket{
		Number: s.next, Subject: strings.TrimSpace(in.Subject), Body: in.Body,
		Status: StatusNew, Priority: PriorityNormal, Category: in.Category,
		Requester: in.Requester, RequesterName: in.RequesterName, CreatedAt: now, UpdatedAt: now,
		Events: []Event{{At: now, Actor: in.Requester, What: "opened"}},
	}
	if err := s.writeFile("next", []byte(strconv.FormatInt(s.next+1, 10))); err != nil {
		return Ticket{}, err
	}
	if err := s.saveLocked(t); err != nil {
		return Ticket{}, err
	}
	s.next++
	s.tickets[t.Number] = t
	return clone(t), nil
}

func clone(t *Ticket) Ticket {
	out := *t
	out.Comments = slices.Clone(t.Comments)
	out.Events = slices.Clone(t.Events)
	return out
}

// Get returns one ticket.
func (s *Store) Get(number int64) (Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[number]
	if !ok {
		return Ticket{}, ErrNotFound
	}
	return clone(t), nil
}

// Filter narrows a listing.
type Filter struct {
	Status    string
	Assignee  string
	Requester string
	Limit     int
}

// List returns tickets, most recently changed first.
func (s *Store) List(f Filter) []Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Ticket{}
	for _, t := range s.tickets {
		if (f.Status == "" || t.Status == f.Status) && (f.Assignee == "" || t.Assignee == f.Assignee) &&
			(f.Requester == "" || t.Requester == f.Requester) {
			out = append(out, clone(t))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt != out[j].UpdatedAt {
			return out[i].UpdatedAt > out[j].UpdatedAt
		}
		return out[i].Number > out[j].Number
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}

// Reply is one comment being added.
type Reply struct {
	Author     string
	AuthorName string
	Team       bool
	Internal   bool
	Body       string
	Unlimited  bool
}

// AddComment adds a reply and moves the ticket on: a reply from the team to
// the requester starts the clock on them; a reply from the requester brings
// a waiting or resolved ticket back to the team.
func (s *Store) AddComment(number int64, r Reply, now int64) (Ticket, error) {
	if err := checkText("a comment", r.Body, maxBody, true); err != nil {
		return Ticket{}, err
	}
	if r.Internal && !r.Team {
		return Ticket{}, invalid("only the team writes internal notes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[number]
	if !ok {
		return Ticket{}, ErrNotFound
	}
	if t.Status == StatusClosed && !r.Team {
		return Ticket{}, invalid("this ticket is closed; please open a new one")
	}
	if len(t.Comments) >= maxComments {
		return Ticket{}, invalid("this ticket has reached its limit of comments")
	}
	if !r.Unlimited && !s.allowLocked("comment:"+r.Author, now, map[int64]int{3600: s.effectiveLocked().CommentsPerHour}) {
		return Ticket{}, ErrLimited
	}
	t.Comments = append(t.Comments, Comment{
		ID: len(t.Comments) + 1, Author: r.Author, AuthorName: r.AuthorName,
		Team: r.Team, Internal: r.Internal, Body: r.Body, At: now,
	})
	t.UpdatedAt = now
	switch {
	case r.Internal:
		// A note changes nothing for the requester.
	case r.Team:
		if t.FirstResponseAt == 0 {
			t.FirstResponseAt = now
		}
	case t.Status == StatusWaiting || t.Status == StatusResolved:
		t.moveTo(StatusInProgress, r.Author, now)
	}
	if err := s.saveLocked(t); err != nil {
		return Ticket{}, err
	}
	return clone(t), nil
}

func (t *Ticket) event(at int64, actor, what, detail string) {
	if len(t.Events) < maxEvents {
		t.Events = append(t.Events, Event{At: at, Actor: actor, What: what, Detail: detail})
	}
}

func (t *Ticket) moveTo(status, actor string, now int64) {
	if t.Status == status {
		return
	}
	t.event(now, actor, "status", t.Status+" → "+status)
	t.Status = status
	switch status {
	case StatusResolved:
		t.ResolvedAt = now
		t.ClosedAt = 0
	case StatusClosed:
		t.ClosedAt = now
		if t.ResolvedAt == 0 {
			t.ResolvedAt = now
		}
	default:
		t.ResolvedAt, t.ClosedAt = 0, 0
	}
}

// Change is what the team alters on a ticket. A nil field stays as it is.
type Change struct {
	Status     *string
	Priority   *string
	Category   *string
	Assignee   *string
	IncidentID *string
}

// Update applies the team's change.
func (s *Store) Update(number int64, actor string, c Change, now int64) (Ticket, error) {
	if c.Status != nil && !slices.Contains(statuses, *c.Status) {
		return Ticket{}, invalid("unknown status %q", *c.Status)
	}
	if c.Priority != nil && !slices.Contains(priorities, *c.Priority) {
		return Ticket{}, invalid("unknown priority %q", *c.Priority)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[number]
	if !ok {
		return Ticket{}, ErrNotFound
	}
	if c.Category != nil && *c.Category != "" && !slices.Contains(s.effectiveLocked().Categories, *c.Category) {
		return Ticket{}, invalid("unknown category %q", *c.Category)
	}
	if c.Priority != nil && *c.Priority != t.Priority {
		t.event(now, actor, "priority", t.Priority+" → "+*c.Priority)
		t.Priority = *c.Priority
	}
	if c.Category != nil && *c.Category != t.Category {
		t.event(now, actor, "category", *c.Category)
		t.Category = *c.Category
	}
	if c.IncidentID != nil && *c.IncidentID != t.IncidentID {
		t.event(now, actor, "incident", *c.IncidentID)
		t.IncidentID = *c.IncidentID
	}
	if c.Assignee != nil && *c.Assignee != t.Assignee {
		t.event(now, actor, "assigned", *c.Assignee)
		t.Assignee = *c.Assignee
		// Taking a ticket moves it on, unless the same change says otherwise.
		if *c.Assignee != "" && c.Status == nil && (t.Status == StatusNew || t.Status == StatusTriaged) {
			t.moveTo(StatusAssigned, actor, now)
		}
	}
	if c.Status != nil {
		t.moveTo(*c.Status, actor, now)
	}
	t.UpdatedAt = now
	if err := s.saveLocked(t); err != nil {
		return Ticket{}, err
	}
	return clone(t), nil
}

// CloseByRequester lets the person who opened a ticket say it is done.
func (s *Store) CloseByRequester(number int64, sub string, now int64) (Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[number]
	if !ok || t.Requester != sub {
		return Ticket{}, ErrNotFound
	}
	t.moveTo(StatusClosed, sub, now)
	t.UpdatedAt = now
	if err := s.saveLocked(t); err != nil {
		return Ticket{}, err
	}
	return clone(t), nil
}

// Delete removes a ticket and everything written on it.
func (s *Store) Delete(number int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tickets[number]; !ok {
		return ErrNotFound
	}
	if err := os.Remove(filepath.Join(s.dir, fmt.Sprintf("t-%d.json", number))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("tickets: %w", err)
	}
	delete(s.tickets, number)
	return nil
}

// noticeEvery is the least time between notices of new tickets, so someone
// filing many tickets through an agent does not flood the team's phones.
const noticeEvery = 15 * 60

// NoticeDue reports whether the team should be told about a new ticket now.
func (s *Store) NoticeDue(now int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now-s.notice < noticeEvery {
		return false
	}
	s.notice = now
	return true
}
