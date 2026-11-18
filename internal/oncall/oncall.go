// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package oncall decides who is told about an outage, tells them, and
// keeps telling someone until a person takes it.
//
// What people chose is personal data: an email address, the hours they
// work, when they are away. It is kept in an ordinary file on the app's
// sealed volume, never in the append-only ledger, so a person can change
// or remove it and it goes with the app.
package oncall

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// When a person wants to be alerted.
const (
	WhenAlways   = "always"
	WhenOnCall   = "on_call"
	WhenSchedule = "schedule"
)

// Roles as the control plane names them.
const (
	RoleOwner         = "owner"
	RoleAdmin         = "admin"
	RoleViewer        = "viewer"
	RoleSupportAdmin  = "support-admin"
	RoleSupportMember = "support-member"
	RoleSupportViewer = "support-viewer"
)

// Member is one person on the app's team.
type Member struct {
	Sub  string `json:"sub"`
	Name string `json:"name,omitempty"`
	Role string `json:"role"`
}

// Responder reports whether the role answers incidents. Viewers read.
func (m Member) Responder() bool {
	return m.Role != RoleViewer && m.Role != RoleSupportViewer
}

// Lead reports whether the role leads the team's response.
func (m Member) Lead() bool {
	return m.Role == RoleOwner || m.Role == RoleAdmin || m.Role == RoleSupportAdmin
}

// Weekly is a repeating window in the person's time zone. Days are 0
// (Sunday) to 6. A window whose end is before its start runs overnight,
// and belongs to the day it starts on.
type Weekly struct {
	Days []int  `json:"days"`
	From string `json:"from"`
	To   string `json:"to"`
}

// DateRange is an inclusive pair of calendar dates in the person's zone.
type DateRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Preference is what one person chose.
type Preference struct {
	Sub string `json:"sub"`
	// Wallet asks for a wallet notification; Email, when set, for email.
	Wallet bool   `json:"wallet"`
	Email  string `json:"email,omitempty"`
	When   string `json:"when"`
	// Weekly applies when When is WhenSchedule.
	Weekly   []Weekly `json:"weekly,omitempty"`
	Timezone string   `json:"timezone,omitempty"`
	// Away silences the person on those dates, whatever When says.
	Away      []DateRange `json:"away,omitempty"`
	UpdatedAt int64       `json:"updated_at,omitempty"`
}

// DefaultPreference is what someone who chose nothing gets: their wallet,
// while they are on call.
func DefaultPreference(sub string) Preference {
	return Preference{Sub: sub, Wallet: true, When: WhenOnCall, Timezone: "UTC"}
}

var (
	clockShape = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	emailShape = regexp.MustCompile(`^[^@\s<>"',;]{1,64}@[^@\s<>"',;]{1,255}\.[^@\s<>"',;.]{2,}$`)
)

// Validate refuses a preference that could not be honoured.
func (p Preference) Validate() error {
	if p.When != WhenAlways && p.When != WhenOnCall && p.When != WhenSchedule {
		return errors.New("when must be always, on_call or schedule")
	}
	if p.Email != "" && !emailShape.MatchString(p.Email) {
		return errors.New("that is not an email address")
	}
	if !p.Wallet && p.Email == "" {
		return errors.New("choose the wallet, email, or both")
	}
	if _, err := time.LoadLocation(zoneOf(p.Timezone)); err != nil {
		return fmt.Errorf("unknown time zone %q", p.Timezone)
	}
	if p.When == WhenSchedule && len(p.Weekly) == 0 {
		return errors.New("a schedule needs at least one weekly window")
	}
	if len(p.Weekly) > 28 || len(p.Away) > 64 {
		return errors.New("too many windows")
	}
	for _, w := range p.Weekly {
		if len(w.Days) == 0 || !clockShape.MatchString(w.From) || !clockShape.MatchString(w.To) || w.From == w.To {
			return errors.New("a weekly window needs days, a start and a different end, as HH:MM")
		}
		for _, d := range w.Days {
			if d < 0 || d > 6 {
				return errors.New("days run from 0 (Sunday) to 6")
			}
		}
	}
	for _, r := range p.Away {
		from, err1 := time.Parse(time.DateOnly, r.From)
		to, err2 := time.Parse(time.DateOnly, r.To)
		if err1 != nil || err2 != nil || to.Before(from) {
			return errors.New("away dates are YYYY-MM-DD, the end on or after the start")
		}
	}
	return nil
}

func zoneOf(tz string) string {
	if tz == "" {
		return "UTC"
	}
	return tz
}

// IsAway reports whether the person is away at now.
func (p Preference) IsAway(now time.Time) bool {
	loc, err := time.LoadLocation(zoneOf(p.Timezone))
	if err != nil {
		loc = time.UTC
	}
	today := now.In(loc).Format(time.DateOnly)
	for _, r := range p.Away {
		if today >= r.From && today <= r.To {
			return true
		}
	}
	return false
}

// InSchedule reports whether now falls in one of the weekly windows.
func (p Preference) InSchedule(now time.Time) bool {
	loc, err := time.LoadLocation(zoneOf(p.Timezone))
	if err != nil {
		loc = time.UTC
	}
	local := now.In(loc)
	clock := local.Format("15:04")
	today, yesterday := int(local.Weekday()), (int(local.Weekday())+6)%7
	for _, w := range p.Weekly {
		overnight := w.To < w.From
		for _, d := range w.Days {
			switch {
			case !overnight && d == today && clock >= w.From && clock < w.To:
				return true
			case overnight && d == today && clock >= w.From:
				return true
			case overnight && d == yesterday && clock < w.To:
				return true
			}
		}
	}
	return false
}

// Override puts someone on call for a stretch, over the rotation.
type Override struct {
	Sub  string `json:"sub"`
	From int64  `json:"from"`
	To   int64  `json:"to"`
}

// Plan is the team's rota and how long a page may go unanswered.
type Plan struct {
	// Rotation is who takes turns, each for PeriodDays from StartAt.
	Rotation   []string   `json:"rotation,omitempty"`
	PeriodDays int        `json:"period_days,omitempty"`
	StartAt    int64      `json:"start_at,omitempty"`
	Overrides  []Override `json:"overrides,omitempty"`
	// AckMinutes is how long each level has to take a page.
	AckMinutes int `json:"ack_minutes,omitempty"`
}

// DefaultAckMinutes is how long a level has when the team has not said.
const DefaultAckMinutes = 10

// Ack is the time a level has to take a page.
func (p Plan) Ack() time.Duration {
	if p.AckMinutes <= 0 {
		return DefaultAckMinutes * time.Minute
	}
	return time.Duration(p.AckMinutes) * time.Minute
}

// Validate refuses a plan that could not be run.
func (p Plan) Validate() error {
	if len(p.Rotation) > 0 && (p.PeriodDays < 1 || p.PeriodDays > 90) {
		return errors.New("a rotation changes hands every 1 to 90 days")
	}
	if p.AckMinutes < 0 || p.AckMinutes > 240 {
		return errors.New("the acknowledgement time is 1 to 240 minutes")
	}
	for _, o := range p.Overrides {
		if o.Sub == "" || o.To <= o.From {
			return errors.New("an override needs a person and an end after its start")
		}
	}
	return nil
}

// OnCall is who is on call at now: an override first, then the rotation.
func (p Plan) OnCall(now time.Time) string {
	at := now.Unix()
	for _, o := range p.Overrides {
		if at >= o.From && at < o.To {
			return o.Sub
		}
	}
	if len(p.Rotation) == 0 || p.PeriodDays < 1 {
		return ""
	}
	period := int64(p.PeriodDays) * 86400
	turn := (at - p.StartAt) / period
	if at < p.StartAt {
		turn = (at - p.StartAt - period + 1) / period
	}
	n := int64(len(p.Rotation))
	return p.Rotation[((turn%n)+n)%n]
}

// Levels of a page. Each is tried in turn until someone takes it.
const (
	LevelOnCall   = iota // whoever is on call, and whoever asked to be told now
	LevelTeam            // every responder who is not away
	LevelLeads           // the leads, away or not
	LevelPlatform        // the platform's own team, when nobody on the app's took it
	levelCount
)

// Recipients is who a level reaches at now.
func Recipients(level int, team []Member, plan Plan, prefs map[string]Preference, now time.Time) []Member {
	onCall := plan.OnCall(now)
	var out []Member
	for _, m := range team {
		p, chose := prefs[m.Sub]
		if !chose {
			p = DefaultPreference(m.Sub)
		}
		switch level {
		case LevelOnCall:
			if !m.Responder() && !chose {
				continue
			}
			if p.IsAway(now) {
				continue
			}
			if m.Sub == onCall || p.When == WhenAlways || (p.When == WhenSchedule && p.InSchedule(now)) {
				out = append(out, m)
			}
		case LevelTeam:
			if m.Responder() && !p.IsAway(now) {
				out = append(out, m)
			}
		case LevelLeads:
			if m.Lead() {
				out = append(out, m)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sub < out[j].Sub })
	return out
}

// Page states.
const (
	PageOpen      = "open"
	PageTaken     = "taken"
	PageResolved  = "resolved"
	PageExhausted = "exhausted" // every level was tried and nobody took it
)

// Sent is one form put in front of one person.
type Sent struct {
	Sub      string `json:"sub"`
	Level    int    `json:"level"`
	Digest   string `json:"digest"`
	Declined bool   `json:"declined,omitempty"`
}

// Entry is one step of a page's history.
type Entry struct {
	At     int64  `json:"at"`
	What   string `json:"what"`
	Sub    string `json:"sub,omitempty"`
	Level  int    `json:"level"`
	Detail string `json:"detail,omitempty"`
}

// Page is one outage being put in front of people.
type Page struct {
	ID          string          `json:"id"`
	IncidentID  string          `json:"incident_id,omitempty"`
	ComponentID string          `json:"component_id"`
	Component   string          `json:"component"`
	Detail      string          `json:"detail,omitempty"`
	State       string          `json:"state"`
	Level       int             `json:"level"`
	OpenedAt    int64           `json:"opened_at"`
	LevelAt     int64           `json:"level_at"`
	TakenBy     string          `json:"taken_by,omitempty"`
	TakenAt     int64           `json:"taken_at,omitempty"`
	ClosedAt    int64           `json:"closed_at,omitempty"`
	Forms       map[string]Sent `json:"forms,omitempty"`
	History     []Entry         `json:"history,omitempty"`
}

func (p *Page) log(at int64, what, sub string, detail string) {
	if len(p.History) >= maxHistory {
		return
	}
	p.History = append(p.History, Entry{At: at, What: what, Sub: sub, Level: p.Level, Detail: detail})
}

const (
	maxHistory = 200
	// keepClosed is how many finished pages are kept, newest first.
	keepClosed = 100
)

type state struct {
	Prefs map[string]Preference `json:"prefs"`
	Plan  Plan                  `json:"plan"`
	Pages []*Page               `json:"pages"`
}

// Store keeps an app's on-call data in one file on its sealed volume.
type Store struct {
	path string
	mu   sync.Mutex
	st   state
}

// OpenStore reads the store in dir, starting empty if there is none.
func OpenStore(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "oncall.json"), st: state{Prefs: map[string]Preference{}}}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oncall: %w", err)
	}
	if err := json.Unmarshal(raw, &s.st); err != nil {
		return nil, fmt.Errorf("oncall: %w", err)
	}
	if s.st.Prefs == nil {
		s.st.Prefs = map[string]Preference{}
	}
	return s, nil
}

// saveLocked writes through a temporary file, so a crash leaves the old
// state whole rather than half of the new one.
func (s *Store) saveLocked() error {
	raw, err := json.Marshal(s.st)
	if err != nil {
		return fmt.Errorf("oncall: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("oncall: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("oncall: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("oncall: %w", err)
	}
	return nil
}

// Preference returns what a person chose, or the default.
func (s *Store) Preference(sub string) Preference {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.st.Prefs[sub]; ok {
		return p
	}
	return DefaultPreference(sub)
}

// SetPreference records what a person chose.
func (s *Store) SetPreference(p Preference, now time.Time) (Preference, error) {
	p.Email = strings.TrimSpace(p.Email)
	if err := p.Validate(); err != nil {
		return p, err
	}
	p.UpdatedAt = now.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Prefs[p.Sub] = p
	return p, s.saveLocked()
}

// ForgetPreference removes what a person chose, email address included.
func (s *Store) ForgetPreference(sub string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.st.Prefs, sub)
	return s.saveLocked()
}

// Plan returns the team's plan.
func (s *Store) Plan() Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Plan
}

// SetPlan records the team's plan.
func (s *Store) SetPlan(p Plan) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Plan = p
	return s.saveLocked()
}

// Pages lists the pages, newest first, as copies safe to hand out.
func (s *Store) Pages(limit int) []Page {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Page, 0, len(s.st.Pages))
	for i := len(s.st.Pages) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		p := *s.st.Pages[i]
		p.Forms = nil
		p.History = append([]Entry(nil), p.History...)
		out = append(out, p)
	}
	return out
}

func (s *Store) prefsLocked() map[string]Preference {
	out := make(map[string]Preference, len(s.st.Prefs))
	for k, v := range s.st.Prefs {
		out[k] = v
	}
	return out
}

// pruneLocked drops the oldest finished pages beyond keepClosed.
func (s *Store) pruneLocked() {
	closed := 0
	for i := len(s.st.Pages) - 1; i >= 0; i-- {
		if s.st.Pages[i].State == PageOpen || s.st.Pages[i].State == PageTaken {
			continue
		}
		closed++
		if closed > keepClosed {
			s.st.Pages = append(s.st.Pages[:i], s.st.Pages[i+1:]...)
		}
	}
}
