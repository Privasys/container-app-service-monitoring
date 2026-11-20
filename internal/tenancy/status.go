// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package tenancy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// App is what the control plane says about an app: where it is served,
// whether it is deployed, the account it belongs to, and whether its team
// lists it in that account's directory.
type App struct {
	ID          string
	Name        string
	DisplayName string
	AppType     string
	Hostname    string
	Deployed    bool
	AccountID   string
	AccountSlug string
	AccountName string
	Listed      bool
}

// Account is an account as the app list describes it.
type Account struct {
	ID   string
	Slug string
	Name string
}

// AppSource lists every app on the platform. complete reports whether the
// list is the whole set, so an app missing from it can be taken as gone.
type AppSource func(ctx context.Context) (apps []App, complete bool, err error)

// The zero-config status every app gets when its team turns monitoring
// on. Fixed ids make it idempotent: syncing again finds what it made.
const (
	StatusServiceID   = "svc-app"
	StatusComponentID = "cmp-app"
	ReachableID       = "mon-reachable"
)

// missingBeforeRemoval is how many complete listings in a row must miss
// an app before its monitor is removed. One listing could be a database
// read at an unlucky moment; removing an app's history is not undoable.
const missingBeforeRemoval = 2

// readinessURL is what the zero-config check fetches. The runtime lets a
// GET of /readiness through the gateway with no sealed session, and it
// reaches the app itself: an answer below 500, even a 404 from an app with
// no such route, shows the app is up and serving.
func readinessURL(host string) string { return "https://" + host + "/readiness" }

// EnsureStatus gives an app's monitor its zero-config status: a service
// named after the app, private until the team makes it public, one
// component, and one check that the app answers at its address. What the
// team changed since (the service's name, its visibility, more
// components and journeys) is left alone; only the check's address
// follows the app. It reports whether anything was written.
func (t *Tenant) EnsureStatus(app App) (bool, error) {
	if app.Hostname == "" {
		return false, nil
	}
	p := auth.System(t.ID)
	p.Grant(auth.PermModel)
	changed := false

	svc, err := t.Mon.Service(StatusServiceID)
	if err != nil {
		return false, err
	}
	if svc == nil {
		name := app.DisplayName
		if name == "" {
			name = app.Name
		}
		if _, _, err := t.Mon.UpsertService(p, model.Service{
			ID: StatusServiceID, Name: name, Slug: app.Name,
			Visibility: model.VisibilityPrivate,
		}, "Monitoring turned on for the app"); err != nil {
			return false, fmt.Errorf("status service: %w", err)
		}
		changed = true
	}

	comp, err := t.Mon.Component(StatusComponentID)
	if err != nil {
		return changed, err
	}
	if comp == nil {
		if _, _, err := t.Mon.UpsertComponent(p, model.Component{
			ID: StatusComponentID, ServiceID: StatusServiceID, Name: "App",
			Description: "The app answers at its address.",
			UserWeight:  1, Rollup: model.RollupAny,
		}, "The app's own component"); err != nil {
			return changed, fmt.Errorf("status component: %w", err)
		}
		changed = true
	}

	url := readinessURL(app.Hostname)
	mon, err := t.Mon.Monitor(ReachableID)
	if err != nil {
		return changed, err
	}
	if t.isSelf != nil && t.isSelf(app.Hostname) {
		// The app is this monitor: the runtime maps a container's own
		// hostname to loopback, so the check could only ever be refused,
		// and a monitor cannot report its own outage anyway. The
		// out-of-band instance watches this one.
		if mon != nil && mon.Enabled {
			if _, err := t.Mon.SetMonitorEnabled(p, ReachableID, false,
				"This app is the monitor itself; it is watched from outside"); err != nil {
				return changed, err
			}
			return true, nil
		}
		return changed, nil
	}
	if mon != nil && len(mon.Steps) == 1 && mon.Steps[0].URL == url {
		return changed, nil
	}
	def := model.Monitor{
		ID: ReachableID, ComponentID: StatusComponentID, Name: "Reachable",
		IntervalSeconds: model.DefaultInterval,
		Steps: []model.Step{{
			Name: "readiness", Kind: model.StepHTTP, Method: "GET", URL: url,
		}},
	}
	message := "Watch the app at its address"
	if mon != nil {
		// The address moved (the app was renamed): keep the team's
		// interval and thresholds, and whether it is switched on.
		def.Enabled = mon.Enabled
		def.IntervalSeconds = mon.IntervalSeconds
		def.TimeoutSeconds = mon.TimeoutSeconds
		def.FailureThreshold = mon.FailureThreshold
		def.RecoveryThreshold = mon.RecoveryThreshold
		message = "The app's address changed"
	}
	if _, _, err := t.Mon.UpsertMonitor(p, def, message); err != nil {
		return changed, fmt.Errorf("status check: %w", err)
	}
	return true, nil
}

// Sync brings the hosted apps in line with the control plane's list:
// each one's zero-config status follows its address, and an app that is
// gone has its monitor removed once complete listings have missed it
// missingBeforeRemoval times in a row.
func (h *Host) Sync(apps []App, complete bool) {
	byID := map[string]App{}
	for _, a := range apps {
		if id, err := Canonical(a.ID); err == nil {
			a.ID = id
			byID[id] = a
		}
	}
	h.mu.Lock()
	h.apps = byID
	h.mu.Unlock()

	for _, t := range h.List() {
		app, ok := byID[t.ID]
		if ok {
			h.mu.Lock()
			delete(h.missing, t.ID)
			h.mu.Unlock()
			if changed, err := t.EnsureStatus(app); err != nil {
				h.log.Error("could not set an app's zero-config status", "app", t.ID, "error", err)
			} else if changed {
				t.Scheduler.Reload()
			}
			continue
		}
		if !complete {
			continue
		}
		h.mu.Lock()
		h.missing[t.ID]++
		n := h.missing[t.ID]
		h.mu.Unlock()
		if n < missingBeforeRemoval {
			h.log.Warn("an app with a monitor is missing from the platform's list", "app", t.ID, "times", n)
			continue
		}
		h.log.Info("removing the monitor of an app the platform no longer has", "app", t.ID)
		if err := h.Remove(t.ID); err != nil {
			h.log.Error("could not remove a deleted app's monitor", "app", t.ID, "error", err)
			continue
		}
		h.mu.Lock()
		delete(h.missing, t.ID)
		h.mu.Unlock()
		if h.opts.Changed != nil {
			h.opts.Changed()
		}
	}
}

// KnownApp returns what the last listing said about an app.
func (h *Host) KnownApp(appID string) (App, bool) {
	id, err := Canonical(appID)
	if err != nil {
		return App{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.apps[id]
	return a, ok
}

// Resolve turns what a public address names, an app id or the app's
// platform name, into the app's id. Names come only from the control
// plane's list, never from a service's slug: a team can edit its slug, and
// must not be able to answer at another app's address.
func (h *Host) Resolve(idOrName string) (string, bool) {
	if id, err := Canonical(idOrName); err == nil {
		return id, true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, a := range h.apps {
		if a.Name != "" && a.Name == idOrName {
			return id, true
		}
	}
	return "", false
}

// syncRetry is how soon a failed listing is tried again. The first one
// after a deploy is refused until the control plane marks the deployment
// active, and addresses by name do not resolve until a listing succeeds.
const syncRetry = 30 * time.Second

// RunSync lists the apps every interval until ctx ends, starting now.
func (h *Host) RunSync(ctx context.Context, source AppSource, interval time.Duration) {
	for {
		wait := interval
		apps, complete, err := source(ctx)
		if err != nil {
			h.log.Error("could not list the platform's apps", "error", err)
			wait = syncRetry
		} else {
			h.Sync(apps, complete)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-h.kick:
			// Asked to read again now. Requests close together share one
			// read, and reads are never closer than syncMinGap.
			select {
			case <-ctx.Done():
				return
			case <-time.After(syncMinGap):
			}
		}
	}
}

// syncMinGap is the least time between two listings asked for early.
var syncMinGap = 5 * time.Second

// RequestSync asks for the app list to be read again soon, rather than at
// the next interval: after a team lists or publishes an app, its pages
// follow within seconds. Requests made before that read share it.
func (h *Host) RequestSync() {
	select {
	case h.kick <- struct{}{}:
	default:
	}
}

// ResolvesToLoopback reports whether every address host resolves to here
// is a loopback one: what the runtime does with a container's own
// hostname, so it is how the monitor recognises its own app.
func ResolvesToLoopback(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}
	return true
}

// AccountBySlug finds the account a public address names by its short
// name, which only the control plane's list supplies. Case does not matter.
func (h *Host) AccountBySlug(slug string) (Account, bool) {
	if slug == "" {
		return Account{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, a := range h.apps {
		if a.AccountID != "" && strings.EqualFold(a.AccountSlug, slug) {
			return Account{ID: a.AccountID, Slug: a.AccountSlug, Name: a.AccountName}, true
		}
	}
	return Account{}, false
}

// AccountOf returns the account an app belongs to.
func (h *Host) AccountOf(appID string) (Account, bool) {
	a, ok := h.KnownApp(appID)
	if !ok || a.AccountID == "" {
		return Account{}, false
	}
	return Account{ID: a.AccountID, Slug: a.AccountSlug, Name: a.AccountName}, true
}
