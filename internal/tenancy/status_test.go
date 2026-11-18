// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package tenancy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/keys"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

func TestSyncGivesEachAppItsStatusAndRemovesDeletedApps(t *testing.T) {
	dir := t.TempDir()
	mat, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	h := newHost(t, dir, mat)
	removed := 0
	h.opts.Changed = func() { removed++ }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	a, err := h.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Ensure(appB); err != nil {
		t.Fatal(err)
	}
	listing := []App{
		{ID: appA, Name: "checkout", DisplayName: "Checkout", Hostname: "checkout.apps.example"},
		{ID: appB, Name: "billing", Hostname: "billing.apps.example"},
		// An app with no monitor here is listed and left alone.
		{ID: "22222222-3333-4444-8555-666666666666", Name: "other", Hostname: "other.apps.example"},
	}
	h.Sync(listing, true)

	svc, err := a.Mon.Service(StatusServiceID)
	if err != nil || svc == nil {
		t.Fatalf("no status service: %v", err)
	}
	if svc.Name != "Checkout" || svc.Slug != "checkout" || svc.Visibility != model.VisibilityPrivate {
		t.Fatalf("status service: %+v", svc)
	}
	mon, err := a.Mon.Monitor(ReachableID)
	if err != nil || mon == nil {
		t.Fatalf("no reachability check: %v", err)
	}
	if mon.Steps[0].URL != "https://checkout.apps.example/readiness" || !mon.Enabled {
		t.Fatalf("check: %+v", mon)
	}
	if len(h.List()) != 2 {
		t.Fatal("a listed app without monitoring got a monitor")
	}

	// Syncing again changes nothing; a new address moves the check.
	h.Sync(listing, true)
	if again, _ := a.Mon.Monitor(ReachableID); again.Version != mon.Version {
		t.Fatalf("an unchanged sync wrote a new version: %d → %d", mon.Version, again.Version)
	}
	listing[0].Hostname = "checkout2.apps.example"
	h.Sync(listing, true)
	if moved, _ := a.Mon.Monitor(ReachableID); moved.Steps[0].URL != "https://checkout2.apps.example/readiness" || moved.Version != mon.Version+1 {
		t.Fatalf("the check did not follow the address: %+v", moved)
	}

	// App B disappears. An incomplete list never removes anything; one
	// complete miss warns; the second removes it.
	without := []App{listing[0]}
	h.Sync(without, false)
	h.Sync(without, true)
	if _, err := h.Get(appB); err != nil {
		t.Fatalf("app B was removed after a single miss: %v", err)
	}
	h.Sync(without, true)
	if _, err := h.Get(appB); err != ErrUnknownTenant {
		t.Fatalf("app B survived two complete misses: %v", err)
	}
	if removed != 1 {
		t.Fatalf("the attested summary should be republished once, was %d times", removed)
	}

	// A miss followed by a reappearance resets the count.
	h.Sync(nil, true)
	h.Sync(without, true)
	h.Sync(nil, true)
	if _, err := h.Get(appA); err != nil {
		t.Fatalf("app A was removed although it reappeared between misses: %v", err)
	}
}

func TestTheMonitorDoesNotWatchItself(t *testing.T) {
	dir := t.TempDir()
	mat, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	h := newHost(t, dir, mat)
	h.opts.IsSelf = func(host string) bool { return host == "monitor.apps.example" }
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	a, err := h.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	// A check made before the monitor knew (an older build) is switched off.
	if _, err := a.EnsureStatus(App{ID: appA, Name: "monitor", Hostname: "other.apps.example"}); err != nil {
		t.Fatal(err)
	}
	h.Sync([]App{{ID: appA, Name: "monitor", Hostname: "monitor.apps.example"}}, true)
	mon, _ := a.Mon.Monitor(ReachableID)
	if mon == nil || mon.Enabled {
		t.Fatalf("the check on the monitor's own address is still on: %+v", mon)
	}
	if svc, _ := a.Mon.Service(StatusServiceID); svc == nil {
		t.Fatal("the app's status service should still exist")
	}
	if !ResolvesToLoopback("localhost") || ResolvesToLoopback("192.0.2.1") {
		t.Fatal("loopback detection")
	}
}
