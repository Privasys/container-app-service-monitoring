// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package tickets

import (
	"errors"
	"testing"
)

func TestADeskRunsOnItsAccountsSettingsUntilItHasItsOwn(t *testing.T) {
	accounts := NewAccounts(t.TempDir())
	acc, err := accounts.Get("acc-1")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Account = func() *Defaults { return acc }

	// Neither set anything: the desk is closed.
	if s.Settings().Intake != IntakeOff || s.InheritsAccount() {
		t.Fatalf("a new desk: %+v", s.Settings())
	}

	// The account opens its apps' desks.
	cfg := DefaultSettings()
	cfg.Intake, cfg.Categories = IntakePublic, []string{"Billing"}
	if err := acc.Set(cfg); err != nil {
		t.Fatal(err)
	}
	if got := s.Settings(); got.Intake != IntakePublic || !s.InheritsAccount() {
		t.Fatalf("inherited: %+v", got)
	}
	if _, err := s.Create(New{Subject: "Card", Body: "Refused", Category: "Billing", Requester: "u1"}, 1000); err != nil {
		t.Fatalf("an account category: %v", err)
	}

	// The app's team sets its own: the account's no longer apply.
	own := DefaultSettings()
	own.Intake = IntakeTeam
	if err := s.SetSettings(own); err != nil {
		t.Fatal(err)
	}
	if got := s.Settings(); got.Intake != IntakeTeam || s.InheritsAccount() {
		t.Fatalf("own: %+v", got)
	}
	var bad InvalidError
	if _, err := s.Create(New{Subject: "Card", Body: "Again", Category: "Billing", Requester: "u1"}, 1001); !errors.As(err, &bad) {
		t.Fatalf("the account's category on an app with its own: %v", err)
	}

	// Its own survive a restart, and clearing them goes back to the account.
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	again.Account = s.Account
	if again.Settings().Intake != IntakeTeam {
		t.Fatal("own settings lost on restart")
	}
	if err := again.UseAccountSettings(); err != nil {
		t.Fatal(err)
	}
	if again.Settings().Intake != IntakePublic || !again.InheritsAccount() {
		t.Fatalf("back on the account: %+v", again.Settings())
	}

	// The account's settings survive a restart too.
	reopened, err := NewAccounts(accounts.dir).Get("acc-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, set := reopened.Get(); !set || got.Intake != IntakePublic {
		t.Fatalf("account settings after restart: %+v %v", got, set)
	}
}
