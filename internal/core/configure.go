// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/pack"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Configuration, and coming back from a restart.
//
// The runtime owns the configure gate: every other path answers 503
// until the configure endpoint returns success, and the gate re-arms on
// each restart. That is right for a first boot and wrong for every
// boot after it, because a long-running monitor has its configuration
// on its own sealed volume and nobody is standing by at three in the
// morning to type it again. So on boot the monitor reads what it had,
// lifts the gate itself through the manager's per-container callback,
// and republishes the attested extensions the leaf certificate carries.
// Without that, every redeploy looks like configuration loss while the
// configuration was never gone.

// registryConfigKey is where the configuration lives in the ledger.
const registryConfigKey = "config"

// ConfigureRequest is what the configure tool accepts.
type ConfigureRequest struct {
	Tenant string `json:"tenant"`
	// PackRef names a service model baked into the image.
	PackRef string `json:"pack_ref,omitempty"`
	// Pack is an inline service model, used instead of a reference.
	Pack json.RawMessage `json:"pack,omitempty"`
	// CommitmentKey is the ledger key, 64 hex characters. Empty means
	// the monitor derives one from its sealed master secret.
	CommitmentKey string `json:"commitment_key,omitempty"`
	// CallbackURL is where alerts are delivered.
	CallbackURL string `json:"callback_url,omitempty"`
	// CallbackHosts extends the outbound allowlist beyond the callback
	// URL's own host.
	CallbackHosts []string `json:"callback_hosts,omitempty"`
	// RawRetentionDays is how long individual readings are kept.
	RawRetentionDays int `json:"raw_retention_days,omitempty"`
	// MaintenanceLeadTime is the notice a planned window needs to leave
	// agreed service time, in seconds.
	MaintenanceLeadTime int64 `json:"maintenance_lead_time,omitempty"`
}

// ConfigureResult is what the caller is told.
type ConfigureResult struct {
	Tenant      string   `json:"tenant"`
	ServiceID   string   `json:"service_id,omitempty"`
	ServiceName string   `json:"service_name,omitempty"`
	Components  int      `json:"components"`
	Monitors    int      `json:"monitors"`
	Objectives  int      `json:"objectives"`
	Secrets     []string `json:"secrets_expected,omitempty"`
	Egress      []string `json:"egress_allowlist,omitempty"`
	Root        string   `json:"root"`
	Version     uint64   `json:"version"`
}

// Configure brings the instance up.
func (m *Monitor) Configure(p *auth.Principal, req ConfigureRequest, packDir string) (*ConfigureResult, error) {
	tenant := strings.TrimSpace(req.Tenant)
	if tenant == "" {
		tenant = m.opts.Tenant
	}
	if tenant == "" {
		return nil, fmt.Errorf("configure: a tenant is required")
	}

	var loaded *pack.Pack
	var err error
	switch {
	case len(req.Pack) > 0:
		loaded, err = pack.Parse(req.Pack)
	case req.PackRef != "":
		loaded, err = pack.LoadRef(packDir, req.PackRef)
	}
	if err != nil {
		return nil, err
	}

	cfg := Config{
		Tenant:              tenant,
		PackRef:             req.PackRef,
		RawRetentionDays:    req.RawRetentionDays,
		MaintenanceLeadTime: req.MaintenanceLeadTime,
		ConfiguredAt:        m.Now(),
	}
	if cfg.RawRetentionDays <= 0 {
		cfg.RawRetentionDays = DefaultRawRetentionDays
	}
	if cfg.MaintenanceLeadTime <= 0 {
		cfg.MaintenanceLeadTime = DefaultMaintenanceLeadTime
	}
	hosts := append([]string(nil), req.CallbackHosts...)
	if h := hostOfTemplate(req.CallbackURL); h != "" {
		hosts = append(hosts, h)
	}
	cfg.CallbackHosts = hosts

	m.mu.Lock()
	m.opts.Tenant = tenant
	m.config = cfg
	m.mu.Unlock()

	result := &ConfigureResult{Tenant: tenant}

	// The configuration itself is a transaction: what the instance was
	// told, by whom and when, is part of the record it keeps.
	err = m.st.Do(func(tx *store.Tx) error {
		op, err := registryPut(registryConfigKey, cfg)
		if err != nil {
			return err
		}
		_, err = m.commit(tx, model.Envelope{
			Kind: model.KindConfigure, Tenant: tenant,
			Author: p.Author(), Timestamp: m.Now(),
			Message: "Configure the monitor for " + clip(tenant, 40),
		}, []model.WriteOp{op})
		return err
	})
	if err != nil {
		return nil, err
	}

	if loaded != nil {
		seeded, err := m.SeedPack(p, loaded, req.CallbackURL)
		if err != nil {
			return nil, err
		}
		result.ServiceID = seeded.ServiceID
		result.ServiceName = seeded.ServiceName
		result.Components = seeded.Components
		result.Monitors = seeded.Monitors
		result.Objectives = seeded.Objectives
		result.Secrets = seeded.Secrets
	}

	m.mu.Lock()
	m.configured = true
	m.mu.Unlock()
	m.refreshEgress()
	result.Egress = m.egress.Entries()

	if err := m.RecordRuntimeEvent(model.EventConfigure, "configured for "+tenant); err != nil {
		return nil, err
	}
	if _, err := m.IssueCheckpoint(ReasonBootstrap); err != nil {
		return nil, err
	}
	_ = m.st.Do(func(tx *store.Tx) error {
		result.Root, result.Version = tx.Root()
		return nil
	})
	return result, nil
}

// SeedResult reports what a pack brought into being.
type SeedResult struct {
	ServiceID   string
	ServiceName string
	Components  int
	Monitors    int
	Objectives  int
	Secrets     []string
}

// SeedPack turns a service model document into signed transactions.
func (m *Monitor) SeedPack(p *auth.Principal, pk *pack.Pack, callbackURL string) (*SeedResult, error) {
	out := &SeedResult{ServiceName: pk.Service.Name}

	svc := model.Service{
		Name: pk.Service.Name, Slug: pk.Service.Slug, Description: pk.Service.Description,
		Timezone: pk.Service.Timezone, Visibility: pk.Service.Visibility,
		MaintenanceLeadTime: pk.Service.MaintenanceLeadTime,
		CoverageFloorPPM:    pk.Service.CoverageFloorPPM,
		CallbackURL:         callbackURL,
	}
	// A pack may be seeded onto an instance that already holds the same
	// service, which is what happens on every restart of a
	// self-configuring development instance. Reuse it rather than
	// creating a second one.
	if existing, err := m.ServiceBySlug(Slug(orString(pk.Service.Slug, pk.Service.Name))); err == nil && existing != nil {
		svc.ID = existing.ID
		svc.ScheduleID = existing.ScheduleID
	}
	created, _, err := m.UpsertService(p, svc, "Seed the service from pack "+pk.Name)
	if err != nil {
		return nil, err
	}
	out.ServiceID = created.ID

	if pk.Schedule != nil {
		timezone := pk.Schedule.Timezone
		if timezone == "" {
			timezone = created.Timezone
		}
		sched := model.Schedule{
			ID: created.ScheduleID, ServiceID: created.ID, Name: pk.Schedule.Name,
			Timezone: timezone, Windows: pk.Schedule.Windows, Exceptions: pk.Schedule.Exceptions,
		}
		if _, _, err := m.UpsertSchedule(p, sched, "Set the agreed service time from pack "+pk.Name); err != nil {
			return nil, err
		}
	}

	existingComponents, err := m.Components(created.ID)
	if err != nil {
		return nil, err
	}
	byName := map[string]string{}
	for _, c := range existingComponents {
		byName[c.Name] = c.ID
	}

	refs := map[string]string{}
	for _, c := range pk.Components {
		component := model.Component{
			ID: byName[c.Name], ServiceID: created.ID, Name: c.Name, Description: c.Description,
			UserWeight: c.UserWeight, Rollup: c.Rollup, Position: c.Position, Showcase: c.Showcase,
		}
		saved, _, err := m.UpsertComponent(p, component, "Add the "+c.Name+" component")
		if err != nil {
			return nil, err
		}
		refs[c.Ref] = saved.ID
		out.Components++
	}

	existingMonitors, err := m.Monitors(created.ID)
	if err != nil {
		return nil, err
	}
	monitorByName := map[string]string{}
	for _, mon := range existingMonitors {
		monitorByName[mon.Name] = mon.ID
	}

	for _, ms := range pk.Monitors {
		mon := model.Monitor{
			ID: monitorByName[ms.Name], ComponentID: refs[ms.Component], Name: ms.Name,
			IntervalSeconds: ms.IntervalSeconds, TimeoutSeconds: ms.TimeoutSeconds,
			FailureThreshold: ms.FailureThreshold, RecoveryThreshold: ms.RecoveryThreshold,
			LatencyBudgetMs: ms.LatencyBudgetMs, Steps: ms.Steps,
		}
		if _, _, err := m.UpsertMonitor(p, mon, "Add the "+ms.Name+" journey"); err != nil {
			return nil, err
		}
		out.Monitors++
	}

	existingObjectives, err := m.Objectives(created.ID)
	if err != nil {
		return nil, err
	}
	objectiveByName := map[string]string{}
	for _, o := range existingObjectives {
		objectiveByName[o.Name] = o.ID
	}
	for _, os := range pk.Objectives {
		o := model.Objective{
			ID: objectiveByName[os.Name], ServiceID: created.ID, Name: os.Name,
			Metric: os.Metric, TargetPPM: os.TargetPPM, Window: os.Window,
			LatencyBudgetMs: os.LatencyBudgetMs, Credits: os.Credits,
		}
		if _, _, err := m.UpsertObjective(p, o, "Set the "+os.Name+" objective"); err != nil {
			return nil, err
		}
		out.Objectives++
	}

	for _, s := range pk.Secrets {
		out.Secrets = append(out.Secrets, s.Name)
	}
	return out, nil
}

// LoadConfig restores the configuration a previous boot wrote.
func (m *Monitor) LoadConfig() (Config, bool, error) {
	var cfg Config
	found := false
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		found, err = registryGet(tx, registryConfigKey, &cfg)
		return err
	})
	if err != nil || !found {
		return cfg, false, err
	}
	m.mu.Lock()
	m.config = cfg
	m.configured = true
	if cfg.Tenant != "" {
		m.opts.Tenant = cfg.Tenant
	}
	m.mu.Unlock()
	m.refreshEgress()
	return cfg, true, nil
}

// RecordRuntimeEvent writes down something that happened to the monitor
// itself.
//
// A restart matters to the record. A gap in the readings is otherwise
// indistinguishable from a period nobody was watching, and coverage is
// reported next to availability precisely so that a monitor which was
// down cannot certify uptime.
func (m *Monitor) RecordRuntimeEvent(kind, detail string) error {
	id, err := NewID("evt")
	if err != nil {
		return err
	}
	now := m.Now()
	return m.st.Do(func(tx *store.Tx) error {
		_, err := m.commit(tx, model.Envelope{
			Kind: model.KindRuntimeEvent, ObjectIDs: []string{id},
			Author: model.SystemAuthor(), Timestamp: now,
			Message: "Record a " + kind + " event",
		}, []model.WriteOp{{
			Table: "runtime_events", Key: map[string]any{"id": id},
			Values: map[string]any{
				"kind": kind, "at_time": now, "detail": clip(detail, 1024),
				"image_digest": clip(m.opts.ImageDigest, 160),
			},
		}})
		return err
	})
}

// LastBoot returns the previous boot event, so the gap between it and
// this one can be recorded as what it is.
func (m *Monitor) LastBoot() (*model.RuntimeEvent, error) {
	var out *model.RuntimeEvent
	err := m.st.Do(func(tx *store.Tx) error {
		row, err := tx.QueryOne("SELECT * FROM `runtime_events` WHERE kind = " +
			store.Lit(model.EventBoot) + " ORDER BY at_time DESC LIMIT 1")
		if err != nil || row == nil {
			return err
		}
		out = &model.RuntimeEvent{
			ID: row.Str("id"), Kind: row.Str("kind"), At: row.Int("at_time"),
			Detail: row.Str("detail"), ImageDigest: row.Str("image_digest"),
		}
		return nil
	})
	return out, err
}

func orString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func jsonUnmarshal(raw []byte, into any) error { return json.Unmarshal(raw, into) }
