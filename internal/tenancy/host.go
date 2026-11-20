// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package tenancy runs one monitor per app on the shared platform
// instance.
//
// Every app the platform hosts is a tenant here, and each tenant is a
// whole monitor of its own: its own ledger, opened under its own
// commitment key; its own credential vault, sealed under its own key;
// its own outbound allowlist; its own scheduler and alert sender. Nothing
// is shared between two apps but the process, the signing key that
// signs every tenant's evidence, and a limit on how many journeys run at
// once. That is a deliberate choice over one ledger with an app column:
// a query that forgot to filter by app cannot leak one team's incidents
// to another when there is nothing else in the database to leak, a
// report and its proofs are about one app only, and removing an app is
// removing its directory.
//
// The platform's own tenant is not in here. It is the instance's
// original record, which keeps the platform clock and its history, and
// it is opened by the process as before.
package tenancy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/keys"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/oncall"
	"github.com/Privasys/container-app-service-monitoring/internal/probe"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
	"github.com/Privasys/container-app-service-monitoring/internal/tickets"
	"github.com/Privasys/container-app-service-monitoring/internal/webhook"
)

// ErrUnknownTenant is returned for an app this instance has no record of.
var ErrUnknownTenant = errors.New("no such app on this monitor")

// Tenant is one app's monitor.
type Tenant struct {
	// ID is the app's id, a lower-case UUID.
	ID string

	Mon       *core.Monitor
	Scheduler *probe.Scheduler
	Sender    *webhook.Sender
	// OnCall pages the app's team, when the process set it up.
	OnCall *oncall.Dispatcher
	// Tickets is the app's support desk.
	Tickets *tickets.Store

	// isSelf reports whether a hostname is this monitor's own.
	isSelf func(host string) bool
	st     *store.Store
	dir    string
	cancel context.CancelFunc
	done   sync.WaitGroup
}

// Options configure the host.
type Options struct {
	// Dir is where the tenants live, one directory each.
	Dir string
	// Material is the instance's sealed key material.
	Material *keys.Material
	// Base is the template every tenant's monitor is built from; Tenant
	// and DataDir are filled in per app.
	Base core.Options
	// PackDir is where the service-model packs baked into the image live.
	PackDir string
	// OpenEgress opens every tenant's outbound allowlist. Development
	// only; the process refuses it on the platform.
	OpenEgress bool
	// Workers bounds the journeys one app runs at once.
	Workers int
	// Shared bounds the journeys all apps run at once.
	Shared int
	// Configure lets the process adjust a tenant's scheduler before it
	// starts, such as the rollup lag and checkpoint interval it uses for
	// its own tenant.
	Configure func(*Tenant)
	// IsSelf reports whether a hostname is this monitor's own, so the
	// zero-config check is not pointed at itself. Nil: never.
	IsSelf func(host string) bool
	// Changed runs after a tenant is created or removed by the host itself
	// (an app the platform deleted), so the process can republish the
	// summary it attests to.
	Changed func()
}

// Host holds the app tenants.
type Host struct {
	opts   Options
	log    *slog.Logger
	shared chan struct{}
	// kick asks RunSync to read the app list again early.
	kick chan struct{}

	mu      sync.Mutex
	tenants map[string]*Tenant
	// apps is the control plane's last app list, and missing how many
	// complete listings in a row have not had each hosted app.
	apps    map[string]App
	missing map[string]int
	ctx     context.Context
	closed  bool
}

// New builds a host. Nothing is opened until Open or Ensure.
func New(opts Options, log *slog.Logger) *Host {
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.Shared <= 0 {
		opts.Shared = 32
	}
	return &Host{
		opts: opts, log: log,
		shared:  make(chan struct{}, opts.Shared),
		kick:    make(chan struct{}, 1),
		tenants: map[string]*Tenant{},
		apps:    map[string]App{},
		missing: map[string]int{},
	}
}

// Canonical returns an app id in the form the host stores it under, or
// an error for anything that is not an app id. Directory names are
// built from it, so nothing else is ever accepted.
func Canonical(appID string) (string, error) {
	key := auth.AppKey(appID)
	if key == "" {
		return "", fmt.Errorf("%q is not an app id", appID)
	}
	return key[0:8] + "-" + key[8:12] + "-" + key[12:16] + "-" + key[16:20] + "-" + key[20:32], nil
}

// Start opens every tenant already on the volume and runs their
// schedulers and senders until ctx ends. A tenant created later starts
// as it is created.
func (h *Host) Start(ctx context.Context) error {
	h.mu.Lock()
	h.ctx = ctx
	h.mu.Unlock()
	ids, err := h.onDisk()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := h.open(id, false); err != nil {
			// One app's record that will not open must not keep every
			// other app unwatched. It is logged and left closed.
			h.log.Error("could not open an app's record", "app", id, "error", err)
		}
	}
	return nil
}

// Get returns an app's tenant if the app is known here.
func (h *Host) Get(appID string) (*Tenant, error) {
	id, err := Canonical(appID)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	t := h.tenants[id]
	h.mu.Unlock()
	if t != nil {
		return t, nil
	}
	return h.open(id, false)
}

// Ensure returns an app's tenant, creating it on first use.
func (h *Host) Ensure(appID string) (*Tenant, error) {
	id, err := Canonical(appID)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	t := h.tenants[id]
	h.mu.Unlock()
	if t != nil {
		return t, nil
	}
	return h.open(id, true)
}

// List returns the open tenants in id order.
func (h *Host) List() []*Tenant {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*Tenant, 0, len(h.tenants))
	for _, t := range h.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Remove closes an app's tenant and deletes everything it held: its
// record, its credentials, its screenshots. This is what happens when
// the app is deleted from the platform; there is no undo, by design.
func (h *Host) Remove(appID string) error {
	id, err := Canonical(appID)
	if err != nil {
		return err
	}
	h.mu.Lock()
	t := h.tenants[id]
	delete(h.tenants, id)
	h.mu.Unlock()
	if t != nil {
		t.close()
	}
	return os.RemoveAll(h.tenantDir(id))
}

// Close stops every tenant and closes its record.
func (h *Host) Close() {
	h.mu.Lock()
	h.closed = true
	all := make([]*Tenant, 0, len(h.tenants))
	for _, t := range h.tenants {
		all = append(all, t)
	}
	h.tenants = map[string]*Tenant{}
	h.mu.Unlock()
	for _, t := range all {
		_ = t.Mon.RecordRuntimeEvent(model.EventShutdown, "the monitor is stopping")
		if _, err := t.Mon.IssueCheckpoint(core.ReasonScheduled); err != nil {
			h.log.Error("could not anchor an app's state on shutdown", "app", t.ID, "error", err)
		}
		t.close()
	}
}

// Roots summarises every tenant's current state as one digest: SHA-256
// over the sorted "app id, root, version" lines, joined by newlines,
// with any extra lines the caller adds (the instance's own record). It
// is what the instance publishes as its ledger root, so a handshake pins
// the state of every app's record at once. Each app's own root and
// proofs come from that app's checkpoints.
func (h *Host) Roots(extra ...string) (string, error) {
	lines := append([]string(nil), extra...)
	for _, t := range h.List() {
		lineage, err := t.Mon.Lineage(auth.System(t.ID))
		if err != nil {
			return "", fmt.Errorf("app %s: %w", t.ID, err)
		}
		if lineage == nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s %d", t.ID, lineage.Root, lineage.Version))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

func (h *Host) tenantDir(id string) string { return filepath.Join(h.opts.Dir, id) }

func (h *Host) onDisk() ([]string, error) {
	entries, err := os.ReadDir(h.opts.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenancy: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if id, err := Canonical(e.Name()); err == nil && id == e.Name() {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// open opens a tenant, creating it only when create is set.
func (h *Host) open(id string, create bool) (*Tenant, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, errors.New("tenancy: the host is closed")
	}
	if t := h.tenants[id]; t != nil {
		return t, nil
	}
	dir := h.tenantDir(id)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) && !create {
		return nil, ErrUnknownTenant
	}

	tk, err := h.opts.Material.TenantKeys(id, dir)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(dir, "record"), tk.Commitment)
	if err != nil {
		return nil, err
	}
	if err := st.Migrate(); err != nil {
		st.Close()
		return nil, err
	}
	vault, err := secrets.Open(filepath.Join(dir, "secrets"), tk.Vault)
	if err != nil {
		st.Close()
		return nil, err
	}
	egress := journey.NewAllowlist()
	if h.opts.OpenEgress {
		egress.Open()
	}
	opts := h.opts.Base
	opts.Tenant = id
	opts.DataDir = dir
	mon := core.New(st, h.opts.Material, vault, egress, opts)

	if _, restored, err := mon.LoadConfig(); err != nil {
		st.Close()
		return nil, err
	} else if !restored {
		// A new app starts configured with nothing to watch yet. What it
		// watches, and who is told, is set by its team afterwards; the
		// configure call of the instance is the platform's, not theirs.
		if _, err := mon.Configure(auth.System(id), core.ConfigureRequest{Tenant: id}, h.opts.PackDir); err != nil {
			st.Close()
			return nil, err
		}
	}

	desk, err := tickets.Open(filepath.Join(dir, "tickets"))
	if err != nil {
		st.Close()
		return nil, err
	}
	t := &Tenant{ID: id, Mon: mon, st: st, dir: dir, isSelf: h.opts.IsSelf, Tickets: desk}
	t.Scheduler = probe.New(mon, h.log.With("app", id))
	t.Scheduler.Workers = h.opts.Workers
	t.Scheduler.Shared = h.shared
	t.Sender = webhook.New(mon, h.opts.Material.Signer, h.opts.Material.KeyID, egress, h.log.With("app", id))
	if h.opts.Configure != nil {
		h.opts.Configure(t)
	}
	mon.SetHooks(core.Hooks{OnAlert: func(a core.Alert) {
		t.Sender.Enqueue(a)
		if t.OnCall != nil {
			t.OnCall.HandleAlert(a)
		}
	}})
	if err := recordBoot(mon); err != nil {
		h.log.Error("could not record an app's boot", "app", id, "error", err)
	}
	h.tenants[id] = t
	if h.ctx != nil {
		t.start(h.ctx)
	}
	return t, nil
}

func (t *Tenant) start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	t.cancel = cancel
	t.done.Add(2)
	if t.OnCall != nil {
		t.done.Add(1)
		go func() { defer t.done.Done(); t.OnCall.Run(ctx) }()
	}
	go func() { defer t.done.Done(); t.Scheduler.Run(ctx) }()
	go func() { defer t.done.Done(); t.Sender.Run(ctx) }()
}

// Dir is the app's directory on the sealed volume.
func (t *Tenant) Dir() string { return t.dir }

func (t *Tenant) close() {
	if t.cancel != nil {
		t.cancel()
		t.done.Wait()
	}
	_ = t.st.Close()
}

// recordBoot writes the boot down with the gap since the last one, the
// way the process does for its own record: a gap in an app's readings is
// otherwise indistinguishable from a quiet period.
func recordBoot(mon *core.Monitor) error {
	detail := "the monitor started"
	if last, err := mon.LastBoot(); err == nil && last != nil {
		if gap := mon.Now() - last.At; gap > 0 {
			detail = fmt.Sprintf("the monitor started after %d seconds away", gap)
		}
	}
	return mon.RecordRuntimeEvent(model.EventBoot, detail)
}
