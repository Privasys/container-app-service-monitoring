// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package tickets

// The account's desk defaults.
//
// An account sets how its apps run their desks once: who may file, the
// categories, the limits and the targets. An app runs on them until its
// team gives it settings of its own, and goes back to them when its own
// are cleared. Nothing about tickets is kept here, only the settings, in
// the account's own directory beside its rota.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// clone is a copy that shares nothing with s.
func (s Settings) clone() Settings {
	out := s
	out.Categories = slices.Clone(s.Categories)
	out.Targets = make(map[string]Target, len(s.Targets))
	for k, v := range s.Targets {
		out.Targets[k] = v
	}
	return out
}

// Defaults are one account's desk settings.
type Defaults struct {
	path string

	mu       sync.Mutex
	set      bool
	settings Settings
}

// OpenDefaults reads the account's settings in dir, if it set any.
func OpenDefaults(dir string) (*Defaults, error) {
	d := &Defaults{path: filepath.Join(dir, "support.json"), settings: DefaultSettings()}
	raw, err := os.ReadFile(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tickets: %w", err)
	}
	if err := json.Unmarshal(raw, &d.settings); err != nil {
		return nil, fmt.Errorf("tickets: account settings: %w", err)
	}
	d.set = true
	return d, nil
}

// Get is the account's settings, and whether it set any; when it did not,
// the settings are the closed desk every app starts with.
func (d *Defaults) Get() (Settings, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.settings.clone(), d.set
}

// Set changes the account's settings.
func (d *Defaults) Set(in Settings) error {
	if err := in.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("tickets: %w", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(d.path), 0o700); err != nil {
		return fmt.Errorf("tickets: %w", err)
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("tickets: %w", err)
	}
	if err := os.Rename(tmp, d.path); err != nil {
		return fmt.Errorf("tickets: %w", err)
	}
	d.settings, d.set = in.clone(), true
	return nil
}

// Accounts keeps each account's defaults, opened on first use under dir.
type Accounts struct {
	dir    string
	mu     sync.Mutex
	opened map[string]*Defaults
}

// NewAccounts keeps account defaults under dir, one directory each.
func NewAccounts(dir string) *Accounts {
	return &Accounts{dir: dir, opened: map[string]*Defaults{}}
}

// Get opens the account's defaults. An empty id is no account.
func (a *Accounts) Get(accountID string) (*Defaults, error) {
	if accountID == "" {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if d, ok := a.opened[accountID]; ok {
		return d, nil
	}
	d, err := OpenDefaults(filepath.Join(a.dir, accountID))
	if err != nil {
		return nil, err
	}
	a.opened[accountID] = d
	return d, nil
}

// --- the desk's view ---

// effectiveLocked is what the desk runs on: its own settings when its team
// set some, else its account's when the account set some, else the closed
// desk every app starts with.
func (s *Store) effectiveLocked() Settings {
	if s.own || s.Account == nil {
		return s.settings
	}
	if acc := s.Account(); acc != nil {
		if cfg, set := acc.Get(); set {
			return cfg
		}
	}
	return s.settings
}

// OwnSettings is the app's own settings, and whether its team set any.
func (s *Store) OwnSettings() (Settings, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.clone(), s.own
}

// InheritsAccount reports whether the desk runs on its account's settings.
func (s *Store) InheritsAccount() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.own || s.Account == nil {
		return false
	}
	acc := s.Account()
	if acc == nil {
		return false
	}
	_, set := acc.Get()
	return set
}

// UseAccountSettings forgets the app's own settings: the desk runs on its
// account's again, or is closed when the account set none.
func (s *Store) UseAccountSettings() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(filepath.Join(s.dir, "settings.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("tickets: %w", err)
	}
	s.settings, s.own = DefaultSettings(), false
	return nil
}
