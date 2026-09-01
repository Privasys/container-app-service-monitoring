// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package pack loads a service model from a document.
//
// A pack is a whole watched service written down: the service, its
// agreed service time, its components, the journeys that exercise them
// and the objectives they are held to. It exists so that bringing a
// monitor up is a configuration step rather than a dozen API calls, and
// so that the end-to-end test drives the same path a customer does.
//
// Packs are baked into the image and named by reference at configure
// time, or delivered inline. Either way what lands in the ledger is the
// resolved service model, as ordinary signed transactions: the pack is
// how the model arrived, not a second place the model lives.
package pack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// Pack is the document.
type Pack struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`

	Service    ServiceSpec     `json:"service"`
	Schedule   *ScheduleSpec   `json:"schedule,omitempty"`
	Components []ComponentSpec `json:"components"`
	Monitors   []MonitorSpec   `json:"monitors"`
	Objectives []ObjectiveSpec `json:"objectives,omitempty"`
	// Secrets declares the credentials the monitors expect, so an
	// operator is told what to supply instead of discovering it from a
	// failing journey. Values never appear in a pack.
	Secrets []SecretSpec `json:"secrets,omitempty"`
}

// ServiceSpec describes the watched service.
type ServiceSpec struct {
	Name        string `json:"name"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
	Visibility  string `json:"visibility,omitempty"`
	// MaintenanceLeadTime is in seconds.
	MaintenanceLeadTime int64 `json:"maintenance_lead_time,omitempty"`
	CoverageFloorPPM    int64 `json:"coverage_floor_ppm,omitempty"`
}

// ScheduleSpec is the agreed service time.
type ScheduleSpec struct {
	Name       string                    `json:"name"`
	Timezone   string                    `json:"timezone,omitempty"`
	Windows    []model.ScheduleWindow    `json:"windows"`
	Exceptions []model.ScheduleException `json:"exceptions,omitempty"`
}

// ComponentSpec is one user-visible part of the service.
type ComponentSpec struct {
	// Ref is how monitors in the same pack name this component.
	Ref         string `json:"ref"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	UserWeight  int64  `json:"user_weight,omitempty"`
	Rollup      string `json:"rollup,omitempty"`
	Position    int64  `json:"position,omitempty"`
	Showcase    bool   `json:"showcase,omitempty"`
}

// MonitorSpec is a journey.
type MonitorSpec struct {
	Name      string `json:"name"`
	Component string `json:"component"`
	// Engine is "http" (the default) or "browser".
	Engine            string         `json:"engine,omitempty"`
	Viewport          model.Viewport `json:"viewport,omitempty"`
	IntervalSeconds   int            `json:"interval_seconds,omitempty"`
	TimeoutSeconds    int            `json:"timeout_seconds,omitempty"`
	FailureThreshold  int            `json:"failure_threshold,omitempty"`
	RecoveryThreshold int            `json:"recovery_threshold,omitempty"`
	LatencyBudgetMs   int            `json:"latency_budget_ms,omitempty"`
	Steps             []model.Step   `json:"steps"`
}

// ObjectiveSpec is a service-level objective.
type ObjectiveSpec struct {
	Name            string             `json:"name"`
	Metric          string             `json:"metric"`
	TargetPPM       int64              `json:"target_ppm"`
	Window          string             `json:"window"`
	LatencyBudgetMs int                `json:"latency_budget_ms,omitempty"`
	Credits         []model.CreditBand `json:"credits,omitempty"`
}

// SecretSpec declares a credential a monitor will ask for.
type SecretSpec struct {
	Name        string   `json:"name"`
	Hosts       []string `json:"hosts"`
	Description string   `json:"description,omitempty"`
}

// Load reads a pack from a file.
func Load(path string) (*Pack, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	return Parse(raw)
}

// LoadRef resolves a pack baked into the image by name.
func LoadRef(dir, ref string) (*Pack, error) {
	if strings.ContainsAny(ref, `/\.`) {
		return nil, fmt.Errorf("pack: %q is not a pack name", ref)
	}
	return Load(filepath.Join(dir, ref, "model.json"))
}

// Available lists the packs baked into the image.
func Available(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "model.json")); err == nil {
			out = append(out, e.Name())
		}
	}
	return out
}

// Parse decodes and validates a pack.
func Parse(raw []byte) (*Pack, error) {
	var p Pack
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks a pack is coherent before any of it is committed.
// Half a service model is worse than none: the monitor would run, and
// report availability for something nobody meant.
func (p *Pack) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("pack: a pack needs a name")
	}
	if strings.TrimSpace(p.Service.Name) == "" {
		return errors.New("pack: a pack needs a service")
	}
	if len(p.Components) == 0 {
		return errors.New("pack: a service with no components has nothing to report on")
	}
	refs := map[string]bool{}
	for _, c := range p.Components {
		if c.Ref == "" || c.Name == "" {
			return errors.New("pack: every component needs a ref and a name")
		}
		if refs[c.Ref] {
			return fmt.Errorf("pack: two components are called %q", c.Ref)
		}
		refs[c.Ref] = true
	}
	if len(p.Monitors) == 0 {
		return errors.New("pack: a service with no monitors is not being watched")
	}
	for _, mon := range p.Monitors {
		if !refs[mon.Component] {
			return fmt.Errorf("pack: monitor %q names unknown component %q", mon.Name, mon.Component)
		}
		candidate := model.Monitor{
			Name: mon.Name, ComponentID: "pending", Steps: mon.Steps,
			Engine: mon.Engine, Viewport: mon.Viewport,
			IntervalSeconds:   orDefault(mon.IntervalSeconds, model.DefaultInterval),
			TimeoutSeconds:    orDefault(mon.TimeoutSeconds, model.DefaultTimeout),
			FailureThreshold:  orDefault(mon.FailureThreshold, 2),
			RecoveryThreshold: orDefault(mon.RecoveryThreshold, 2),
			LatencyBudgetMs:   mon.LatencyBudgetMs,
		}
		if err := candidate.Validate(); err != nil {
			return fmt.Errorf("pack: %w", err)
		}
	}
	for _, o := range p.Objectives {
		switch o.Metric {
		case model.MetricAvailability, model.MetricUserAvailability, model.MetricLatencyP95:
		default:
			return fmt.Errorf("pack: objective %q has unknown metric %q", o.Name, o.Metric)
		}
		if o.TargetPPM <= 0 || o.TargetPPM > 1_000_000 {
			return fmt.Errorf("pack: objective %q has an impossible target", o.Name)
		}
	}
	return nil
}

// Hosts lists every host the pack's monitors will contact, which is
// what the outbound allowlist is seeded from.
func (p *Pack) Hosts() []string {
	seen := map[string]bool{}
	var out []string
	for _, mon := range p.Monitors {
		for _, s := range mon.Steps {
			host := hostOf(s.URL)
			if host != "" && !seen[host] {
				seen[host] = true
				out = append(out, host)
			}
		}
	}
	return out
}

func hostOf(raw string) string {
	if raw == "" {
		return ""
	}
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if strings.Contains(rest, "{{") {
		return ""
	}
	if i := strings.LastIndex(rest, ":"); i > 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}

func orDefault(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}
