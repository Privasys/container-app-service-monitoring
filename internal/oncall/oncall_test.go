// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package oncall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var monday9 = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC) // a Monday

func subs(ms []Member) string {
	out := []string{}
	for _, m := range ms {
		out = append(out, m.Sub)
	}
	return strings.Join(out, ",")
}

func TestScheduleWindows(t *testing.T) {
	p := Preference{Timezone: "Europe/Paris", Weekly: []Weekly{
		{Days: []int{1}, From: "09:00", To: "17:00"},
		{Days: []int{5}, From: "22:00", To: "06:00"},
	}}
	cases := []struct {
		at   time.Time
		want bool
	}{
		{monday9, true},                                         // 10:00 in Paris
		{monday9.Add(7 * time.Hour), true},                      // 17:00 UTC is 18:00 in Paris: no
		{time.Date(2026, 11, 20, 21, 30, 0, 0, time.UTC), true}, // Friday 22:30 Paris
		{time.Date(2026, 11, 21, 4, 0, 0, 0, time.UTC), true},   // Saturday 05:00 Paris
		{time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC), false},  // Saturday 07:00 Paris
		{time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC), false}, // Tuesday
	}
	cases[1].want = false
	for i, c := range cases {
		if got := p.InSchedule(c.at); got != c.want {
			t.Errorf("case %d (%v): %v", i, c.at, got)
		}
	}
}

func TestRotationAndOverrides(t *testing.T) {
	plan := Plan{Rotation: []string{"a", "b", "c"}, PeriodDays: 7, StartAt: monday9.Unix()}
	for weeks, want := range map[int]string{0: "a", 1: "b", 2: "c", 3: "a", -1: "c"} {
		at := monday9.Add(time.Duration(weeks) * 7 * 24 * time.Hour).Add(time.Hour)
		if got := plan.OnCall(at); got != want {
			t.Errorf("week %d: %q, want %q", weeks, got, want)
		}
	}
	plan.Overrides = []Override{{Sub: "z", From: monday9.Unix(), To: monday9.Add(time.Hour).Unix()}}
	if got := plan.OnCall(monday9); got != "z" {
		t.Fatalf("override: %q", got)
	}
	if got := plan.OnCall(monday9.Add(time.Hour)); got != "a" {
		t.Fatalf("after the override: %q", got)
	}
}

func TestWhoEachLevelReaches(t *testing.T) {
	team := []Member{
		{Sub: "owner", Role: RoleOwner}, {Sub: "member", Role: RoleSupportMember},
		{Sub: "always", Role: RoleSupportMember}, {Sub: "away", Role: RoleSupportAdmin},
		{Sub: "viewer", Role: RoleViewer},
	}
	plan := Plan{Rotation: []string{"member"}, PeriodDays: 7, StartAt: monday9.Unix()}
	prefs := map[string]Preference{
		"always": {Sub: "always", Wallet: true, When: WhenAlways},
		"away":   {Sub: "away", Wallet: true, When: WhenAlways, Away: []DateRange{{From: "2026-11-16", To: "2026-11-20"}}},
	}
	for level, want := range map[int]string{
		LevelOnCall: "always,member",
		LevelTeam:   "always,member,owner",
		LevelLeads:  "away,owner",
	} {
		if got := subs(Recipients(level, team, plan, prefs, monday9)); got != want {
			t.Errorf("level %d: %q, want %q", level, got, want)
		}
	}
}

func TestPreferencesAreChecked(t *testing.T) {
	good := Preference{Sub: "a", Wallet: true, When: WhenOnCall}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Preference){
		"no channel":  func(p *Preference) { p.Wallet = false },
		"bad email":   func(p *Preference) { p.Email = "not-an-address" },
		"header":      func(p *Preference) { p.Email = "a@b.org, c@d.org" },
		"bad when":    func(p *Preference) { p.When = "sometimes" },
		"bad zone":    func(p *Preference) { p.Timezone = "Mars/Olympus" },
		"empty sched": func(p *Preference) { p.When = WhenSchedule },
		"bad away":    func(p *Preference) { p.Away = []DateRange{{From: "2026-12-02", To: "2026-12-01"}} },
	} {
		p := good
		change(&p)
		if p.Validate() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

type fakeWallet struct {
	mu       sync.Mutex
	forms    map[string][]string
	messages []string
	fail     map[string]bool
}

func (f *fakeWallet) Form(_ context.Context, sub, form string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[sub] {
		return "no-push-target", nil
	}
	if f.forms == nil {
		f.forms = map[string][]string{}
	}
	f.forms[sub] = append(f.forms[sub], form)
	return "sent", nil
}

func (f *fakeWallet) Message(_ context.Context, sub, title, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages = append(f.messages, sub+":"+title)
	return "sent", nil
}

type harness struct {
	d      *Dispatcher
	wallet *fakeWallet
	mails  []string
	now    time.Time
}

func newHarness(t *testing.T, plan Plan, prefs ...Preference) *harness {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{wallet: &fakeWallet{}, now: monday9}
	if err := st.SetPlan(plan); err != nil {
		t.Fatal(err)
	}
	for _, p := range prefs {
		if _, err := st.SetPreference(p, h.now); err != nil {
			t.Fatal(err)
		}
	}
	h.d = &Dispatcher{
		Store: st, AppID: "app", AppName: func() string { return "Checkout" },
		Team: func(context.Context) ([]Member, error) {
			return []Member{{Sub: "ada", Role: RoleSupportMember}, {Sub: "bo", Role: RoleSupportMember}, {Sub: "lead", Role: RoleOwner}}, nil
		},
		Wallet: h.wallet, Callback: "/api/v1/apps/app/oncall/answer",
		Mail: func(_ context.Context, to, subject, _ string) error {
			h.mails = append(h.mails, to+":"+subject)
			return nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return h.now },
	}
	return h
}

func formOf(t *testing.T, raw string) (id, digest string) {
	t.Helper()
	var f struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(raw))
	return f.ID, hex.EncodeToString(sum[:])
}

func TestAPageEscalatesUntilSomeoneTakesIt(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, Plan{Rotation: []string{"ada"}, PeriodDays: 7, StartAt: monday9.Unix(), AckMinutes: 5},
		Preference{Sub: "ada", Wallet: true, Email: "ada@example.org", When: WhenOnCall})
	h.d.Open(ctx, "inc1", "cmp", "App", "the connection was refused")
	if n := len(h.wallet.forms["ada"]); n != 1 || len(h.wallet.forms["bo"]) != 0 {
		t.Fatalf("level 0 should reach ada only: %v", h.wallet.forms)
	}
	if len(h.mails) != 1 || !strings.HasPrefix(h.mails[0], "ada@example.org:Checkout is down") {
		t.Fatalf("mails: %v", h.mails)
	}
	// A second alert for the same outage does not page again.
	h.d.Open(ctx, "inc1", "cmp", "App", "")
	if n := len(h.wallet.forms["ada"]); n != 1 {
		t.Fatalf("paged twice: %d", n)
	}

	h.now = h.now.Add(4 * time.Minute)
	h.d.Tick(ctx)
	if len(h.wallet.forms["bo"]) != 0 {
		t.Fatal("escalated before its time")
	}
	h.now = h.now.Add(time.Minute)
	h.d.Tick(ctx)
	if len(h.wallet.forms["bo"]) != 1 || len(h.wallet.forms["lead"]) != 1 {
		t.Fatalf("level 1 should reach the whole team: %v", h.wallet.forms)
	}

	// Bo takes it; nothing escalates any more.
	id, digest := formOf(t, h.wallet.forms["bo"][0])
	if err := h.d.Answer(ctx, id, "ada", digest, ActionTake); !errors.Is(err, ErrNoForm) {
		t.Fatalf("someone else's form was answered: %v", err)
	}
	if err := h.d.Answer(ctx, id, "bo", "wrong", ActionTake); !errors.Is(err, ErrNoForm) {
		t.Fatalf("a changed form was answered: %v", err)
	}
	if err := h.d.Answer(ctx, id, "bo", digest, ActionTake); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Hour)
	h.d.Tick(ctx)
	if len(h.wallet.forms["lead"]) != 1 {
		t.Fatal("a taken page escalated")
	}
	page := h.d.Store.Pages(1)[0]
	if page.State != PageTaken || page.TakenBy != "bo" {
		t.Fatalf("page: %+v", page)
	}

	// Recovery closes it and tells those who were paged.
	h.d.Resolve(ctx, "cmp")
	if page := h.d.Store.Pages(1)[0]; page.State != PageResolved {
		t.Fatalf("page: %+v", page)
	}
	if len(h.wallet.messages) != 3 {
		t.Fatalf("recovery notices: %v", h.wallet.messages)
	}
}

func TestDecliningPassesItOnAtOnceAndAnUnreachablePersonIsSkipped(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, Plan{Rotation: []string{"ada"}, PeriodDays: 7, StartAt: monday9.Unix()})
	h.d.Open(ctx, "inc", "cmp", "App", "")
	id, digest := formOf(t, h.wallet.forms["ada"][0])
	if err := h.d.Answer(ctx, id, "ada", digest, ActionDecline); err != nil {
		t.Fatal(err)
	}
	if len(h.wallet.forms["bo"]) != 1 {
		t.Fatalf("declining should reach the team at once: %v", h.wallet.forms)
	}

	// Nobody on call and no wallet for anyone: every level is tried and
	// the page says so rather than waiting.
	h2 := newHarness(t, Plan{})
	h2.wallet.fail = map[string]bool{"ada": true, "bo": true, "lead": true}
	h2.d.Open(ctx, "inc", "cmp", "App", "")
	page := h2.d.Store.Pages(1)[0]
	if page.State != PageExhausted {
		t.Fatalf("page: %+v", page)
	}
	saw := strings.Builder{}
	for _, e := range page.History {
		saw.WriteString(e.What + " ")
	}
	for _, want := range []string{"nobody_reached", "wallet_failed", "exhausted"} {
		if !strings.Contains(saw.String(), want) {
			t.Fatalf("the record lacks %s: %s", want, saw.String())
		}
	}
}

func TestThePlatformTeamIsTheLastLevel(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, Plan{AckMinutes: 5})
	h.d.Platform = func(context.Context) ([]Member, error) {
		return []Member{{Sub: "operator", Role: RoleOwner}, {Sub: "reader", Role: RoleViewer}}, nil
	}
	h.d.Open(ctx, "inc", "cmp", "App", "")
	if len(h.wallet.forms["operator"]) != 0 {
		t.Fatal("the platform team was paged before the app's own team had its turn")
	}
	// With nobody on call the page starts at the team; the leads come next.
	h.now = h.now.Add(5 * time.Minute)
	h.d.Tick(ctx)
	if len(h.wallet.forms["operator"]) != 0 {
		t.Fatal("the platform team was paged before the app's leads had their turn")
	}
	h.now = h.now.Add(5 * time.Minute)
	h.d.Tick(ctx)
	if len(h.wallet.forms["operator"]) != 1 || len(h.wallet.forms["reader"]) != 0 {
		t.Fatalf("the last level should reach the platform's leads: %v", h.wallet.forms)
	}
	id, digest := formOf(t, h.wallet.forms["operator"][0])
	if err := h.d.Answer(ctx, id, "operator", digest, ActionTake); err != nil {
		t.Fatal(err)
	}
	if p := h.d.Store.Pages(1)[0]; p.State != PageTaken || p.TakenBy != "operator" {
		t.Fatalf("page: %+v", p)
	}
}

func TestTheFormStaysInsideTheWalletsVocabulary(t *testing.T) {
	h := newHarness(t, Plan{})
	long := strings.Repeat("x", 500) + "‮\nend"
	raw, err := h.d.buildForm("form1", &Page{Component: long, Detail: long, OpenedAt: monday9.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 3<<10 {
		t.Fatalf("the form is %d bytes", len(raw))
	}
	if strings.ContainsRune(raw, '‮') || strings.Contains(raw, `\n`) {
		t.Fatal("the form carries a character the wallet refuses")
	}
	var f struct {
		Actions []struct{ ID, Kind string } `json:"actions"`
	}
	if err := json.Unmarshal([]byte(raw), &f); err != nil || len(f.Actions) != 2 || f.Actions[0].Kind != "accept" {
		t.Fatalf("actions: %v %+v", err, f)
	}
}

func TestChoicesSurviveARestartAndCanBeForgotten(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetPreference(Preference{Sub: "ada", Wallet: true, Email: "ada@example.org", When: WhenAlways}, monday9); err != nil {
		t.Fatal(err)
	}
	again, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.Preference("ada").Email != "ada@example.org" {
		t.Fatal("the choice was lost")
	}
	if err := again.ForgetPreference("ada"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "oncall.json"))
	if strings.Contains(string(raw), "ada@example.org") {
		t.Fatal("the address survived being forgotten")
	}
	if got := again.Preference("ada"); got.When != WhenOnCall || got.Email != "" {
		t.Fatalf("default: %+v", got)
	}
}
