// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package tickets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const t0 = int64(1_800_000_000)

func ptr(s string) *string { return &s }

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestATicketsLife(t *testing.T) {
	s := open(t)
	tk, err := s.Create(New{Subject: " Cannot sign in ", Body: "It fails.", Requester: "ada", RequesterName: "Ada"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if tk.Number != 1 || tk.Status != StatusNew || tk.Priority != PriorityNormal || tk.Subject != "Cannot sign in" {
		t.Fatalf("opened: %+v", tk)
	}

	// Taking it moves it on.
	tk, err = s.Update(1, "bo", Change{Assignee: ptr("bo"), Priority: ptr(PriorityHigh)}, t0+60)
	if err != nil || tk.Status != StatusAssigned || tk.Assignee != "bo" || tk.Priority != PriorityHigh {
		t.Fatalf("assigned: %v %+v", err, tk)
	}

	// An internal note is not a first response.
	tk, _ = s.AddComment(1, Reply{Author: "bo", Team: true, Internal: true, Body: "Looks like the IdP."}, t0+120)
	if tk.FirstResponseAt != 0 {
		t.Fatal("an internal note counted as a first response")
	}
	tk, _ = s.AddComment(1, Reply{Author: "bo", Team: true, Body: "Which device?"}, t0+180)
	if tk.FirstResponseAt != t0+180 {
		t.Fatalf("first response: %d", tk.FirstResponseAt)
	}

	// The requester sees the reply and not the note, the assignee or the history.
	view := tk.ForRequester()
	if len(view.Comments) != 1 || view.Comments[0].Body != "Which device?" || view.Assignee != "" || view.Events != nil {
		t.Fatalf("requester view: %+v", view)
	}

	// Their reply brings a waiting ticket back to the team.
	if _, err := s.Update(1, "bo", Change{Status: ptr(StatusWaiting)}, t0+200); err != nil {
		t.Fatal(err)
	}
	tk, _ = s.AddComment(1, Reply{Author: "ada", Body: "An iPhone."}, t0+300)
	if tk.Status != StatusInProgress {
		t.Fatalf("status after their reply: %s", tk.Status)
	}

	tk, _ = s.Update(1, "bo", Change{Status: ptr(StatusResolved)}, t0+400)
	if tk.ResolvedAt != t0+400 {
		t.Fatalf("resolved: %+v", tk)
	}
	tk, _ = s.AddComment(1, Reply{Author: "ada", Body: "Still broken."}, t0+500)
	if tk.Status != StatusInProgress || tk.ResolvedAt != 0 {
		t.Fatalf("reopened: %+v", tk)
	}

	if _, err := s.CloseByRequester(1, "someone-else", t0+600); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a stranger closed the ticket: %v", err)
	}
	tk, err = s.CloseByRequester(1, "ada", t0+600)
	if err != nil || tk.Status != StatusClosed {
		t.Fatalf("closed: %v %+v", err, tk)
	}
	if _, err := s.AddComment(1, Reply{Author: "ada", Body: "One more"}, t0+700); err == nil {
		t.Fatal("a closed ticket took a requester's comment")
	}
}

func TestBadInputIsRefused(t *testing.T) {
	s := open(t)
	for name, in := range map[string]New{
		"no subject":   {Subject: "  ", Body: "x", Requester: "a"},
		"no body":      {Subject: "x", Body: "", Requester: "a"},
		"long subject": {Subject: strings.Repeat("x", maxSubject+1), Body: "x", Requester: "a"},
		"control":      {Subject: "a\x00b", Body: "x", Requester: "a"},
		"bad category": {Subject: "x", Body: "x", Category: "nope", Requester: "a"},
	} {
		var bad InvalidError
		if _, err := s.Create(in, t0); !errors.As(err, &bad) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.Create(New{Subject: "x", Body: "x", Requester: "a"}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(1, "b", Change{Status: ptr("lost")}, t0); err == nil {
		t.Fatal("an unknown status was accepted")
	}
	if _, err := s.AddComment(1, Reply{Author: "a", Internal: true, Body: "x"}, t0); err == nil {
		t.Fatal("a requester wrote an internal note")
	}
}

func TestRateLimitsArePerPersonAndSlide(t *testing.T) {
	s := open(t)
	cfg := DefaultSettings()
	cfg.TicketsPerHour, cfg.TicketsPerDay, cfg.CommentsPerHour = 2, 3, 1
	if err := s.SetSettings(cfg); err != nil {
		t.Fatal(err)
	}
	file := func(who string, at int64) error {
		_, err := s.Create(New{Subject: "x", Body: "x", Requester: who}, at)
		return err
	}
	for range 2 {
		if err := file("ada", t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := file("ada", t0+1); !errors.Is(err, ErrLimited) {
		t.Fatalf("the hourly limit: %v", err)
	}
	if err := file("bo", t0+1); err != nil {
		t.Fatalf("one person's limit stopped another: %v", err)
	}
	if err := file("ada", t0+3601); err != nil {
		t.Fatalf("the hour did not pass: %v", err)
	}
	if err := file("ada", t0+7300); !errors.Is(err, ErrLimited) {
		t.Fatalf("the daily limit: %v", err)
	}
	if err := file("ada", t0+86401); err != nil {
		t.Fatalf("the day did not pass: %v", err)
	}
	if _, err := s.Create(New{Subject: "x", Body: "x", Requester: "ada", Unlimited: true}, t0+86401); err != nil {
		t.Fatalf("an operator was limited: %v", err)
	}
	if _, err := s.AddComment(1, Reply{Author: "ada", Body: "1"}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddComment(1, Reply{Author: "ada", Body: "2"}, t0+1); !errors.Is(err, ErrLimited) {
		t.Fatalf("the comment limit: %v", err)
	}
}

func TestTargets(t *testing.T) {
	cfg := DefaultSettings()
	tk := Ticket{Priority: PriorityUrgent, CreatedAt: t0}
	d := cfg.DueOf(tk, t0+30*60)
	if d.FirstBreached || d.ResolveBreached || d.FirstResponseBy != t0+3600 {
		t.Fatalf("in time: %+v", d)
	}
	if d := cfg.DueOf(tk, t0+2*3600); !d.FirstBreached || d.ResolveBreached {
		t.Fatalf("late first response: %+v", d)
	}
	tk.FirstResponseAt = t0 + 600
	if d := cfg.DueOf(tk, t0+9*3600); d.FirstBreached || !d.ResolveBreached {
		t.Fatalf("answered in time, unresolved: %+v", d)
	}
}

func TestTicketsSurviveARestartAndDeletionIsReal(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := s.Create(New{Subject: "secret subject", Body: "my private problem", Requester: "ada"}, t0); err != nil {
			t.Fatal(err)
		}
	}
	cfg := DefaultSettings()
	cfg.Intake, cfg.Categories = IntakePublic, []string{"Billing"}
	if err := s.SetSettings(cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(2); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(again.List(Filter{})); n != 1 {
		t.Fatalf("tickets after a restart: %d", n)
	}
	if got := again.Settings(); got.Intake != IntakePublic || got.Categories[0] != "Billing" {
		t.Fatalf("settings: %+v", got)
	}
	// A deleted ticket's number is not given to someone else.
	tk, err := again.Create(New{Subject: "next", Body: "x", Requester: "bo"}, t0)
	if err != nil || tk.Number != 3 {
		t.Fatalf("next number: %v %d", err, tk.Number)
	}
	if err := again.Delete(1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "t-1.json")); !os.IsNotExist(err) {
		t.Fatalf("the ticket's file survived: %v", err)
	}
	if _, err := again.Get(1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted ticket answered: %v", err)
	}
}

func TestSettingsAreChecked(t *testing.T) {
	for name, change := range map[string]func(*Settings){
		"intake": func(s *Settings) { s.Intake = "everyone" },
		"limits": func(s *Settings) { s.TicketsPerDay = 1 },
		"target": func(s *Settings) { s.Targets[PriorityLow] = Target{FirstResponseMinutes: 10, ResolutionMinutes: 5} },
		"prio":   func(s *Settings) { s.Targets["blocker"] = Target{FirstResponseMinutes: 1, ResolutionMinutes: 1} },
	} {
		cfg := DefaultSettings()
		change(&cfg)
		if cfg.Validate() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	s := open(t)
	if s.Settings().Intake != IntakeOff {
		t.Fatal("a new desk should be closed")
	}
}

func TestNoticesAreThrottled(t *testing.T) {
	s := open(t)
	if !s.NoticeDue(t0) || s.NoticeDue(t0+60) {
		t.Fatal("the second notice in a burst should be held")
	}
	if !s.NoticeDue(t0 + noticeEvery) {
		t.Fatal("the notice should be due again")
	}
}
