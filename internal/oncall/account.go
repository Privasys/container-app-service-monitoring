// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package oncall

// The account's rota.
//
// An account keeps one on-call plan for all its apps, and each person sets
// their alert channels once for the account. An app runs on the account's
// rota unless it has one of its own (a rotation or an override), and a
// person's channels set on an app take the place of their account-wide
// ones for that app. The account's store is the same file shape as an
// app's, under the account's own directory; it holds no pages.

import (
	"path/filepath"
	"sync"
)

// HasRota reports whether a plan says who is on call.
func (p Plan) HasRota() bool {
	return len(p.Rotation) > 0 || len(p.Overrides) > 0
}

// Snapshot is the store's plan and a copy of its preferences.
func (s *Store) Snapshot() (Plan, map[string]Preference) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Plan, s.prefsLocked()
}

// HasPreference reports whether a person set their own channels here.
func (s *Store) HasPreference(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.st.Prefs[sub]
	return ok
}

// Effective is the plan and preferences an app runs on: its own rota when
// it has one, else the account's (keeping the app's acknowledgement time
// when it set one), and each person's channels from the app where they set
// them there, else from the account.
func Effective(app Plan, appPrefs map[string]Preference, account *Store) (Plan, map[string]Preference) {
	if account == nil {
		return app, appPrefs
	}
	accPlan, accPrefs := account.Snapshot()
	plan := app
	if !app.HasRota() {
		plan = accPlan
		if app.AckMinutes > 0 {
			plan.AckMinutes = app.AckMinutes
		}
	}
	merged := accPrefs
	for sub, p := range appPrefs {
		merged[sub] = p
	}
	return plan, merged
}

// Accounts keeps one store per account, opened on first use under dir.
type Accounts struct {
	dir    string
	mu     sync.Mutex
	stores map[string]*Store
}

// NewAccounts keeps account stores under dir.
func NewAccounts(dir string) *Accounts {
	return &Accounts{dir: dir, stores: map[string]*Store{}}
}

// Get opens the account's store. An empty id is no account.
func (a *Accounts) Get(accountID string) (*Store, error) {
	if accountID == "" {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.stores[accountID]; ok {
		return s, nil
	}
	s, err := OpenStore(filepath.Join(a.dir, accountID))
	if err != nil {
		return nil, err
	}
	a.stores[accountID] = s
	return s, nil
}

// --- the dispatcher's view ---

func (d *Dispatcher) accountStore() *Store {
	if d.Account == nil {
		return nil
	}
	return d.Account()
}

// EffectivePlan is the plan the app runs on now.
func (d *Dispatcher) EffectivePlan() Plan {
	own, prefs := d.Store.Snapshot()
	plan, _ := Effective(own, prefs, d.accountStore())
	return plan
}

// InheritsAccount reports whether the app runs on its account's rota.
func (d *Dispatcher) InheritsAccount() bool {
	return d.accountStore() != nil && !d.Store.Plan().HasRota()
}

// Preference is a person's channels for this app: set on the app, else
// set for the account, else the default.
func (d *Dispatcher) Preference(sub string) Preference {
	if d.Store.HasPreference(sub) {
		return d.Store.Preference(sub)
	}
	if acc := d.accountStore(); acc != nil && acc.HasPreference(sub) {
		return acc.Preference(sub)
	}
	return d.Store.Preference(sub)
}

// mergedPrefs adds the account's preferences under the app's.
func (d *Dispatcher) mergedPrefs(appPrefs map[string]Preference) map[string]Preference {
	_, prefs := Effective(Plan{Rotation: []string{"-"}}, appPrefs, d.accountStore())
	return prefs
}
