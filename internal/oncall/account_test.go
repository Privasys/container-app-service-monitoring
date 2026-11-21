// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package oncall

import (
	"testing"
	"time"
)

func TestAnAppWithoutARotaRunsOnItsAccountsRota(t *testing.T) {
	accounts := NewAccounts(t.TempDir())
	acc, err := accounts.Get("aaaaaaaa-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.SetPlan(Plan{Rotation: []string{"ada", "bob"}, PeriodDays: 7, AckMinutes: 15}); err != nil {
		t.Fatal(err)
	}
	if _, err := acc.SetPreference(Preference{Sub: "ada", When: "always", Wallet: true, Email: "ada@example.com"}, time.Now()); err != nil {
		t.Fatal(err)
	}

	// No rota of its own: the account's, with the app's acknowledgement time.
	plan, prefs := Effective(Plan{AckMinutes: 5}, map[string]Preference{}, acc)
	if len(plan.Rotation) != 2 || plan.AckMinutes != 5 {
		t.Fatalf("inherited plan: %+v", plan)
	}
	if prefs["ada"].Email != "ada@example.com" {
		t.Fatalf("account-wide channels missing: %+v", prefs)
	}

	// Its own rota wins, and channels set on the app win for that person.
	plan, prefs = Effective(Plan{Rotation: []string{"cy"}, PeriodDays: 1},
		map[string]Preference{"ada": {Sub: "ada", Email: "ada@app.example"}}, acc)
	if len(plan.Rotation) != 1 || plan.Rotation[0] != "cy" {
		t.Fatalf("own plan: %+v", plan)
	}
	if prefs["ada"].Email != "ada@app.example" {
		t.Fatalf("app channels did not win: %+v", prefs["ada"])
	}

	// No account: the app's own, unchanged.
	if plan, _ := Effective(Plan{AckMinutes: 3}, nil, nil); plan.AckMinutes != 3 || plan.HasRota() {
		t.Fatalf("without an account: %+v", plan)
	}
}
