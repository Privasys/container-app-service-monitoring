// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package tenancy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/keys"
)

const (
	appA = "0F2C1D9E-3B4A-4C5D-8E6F-7A8B9C0D1E2F"
	appB = "11111111-2222-4333-8444-555555555555"
)

func newHost(t *testing.T, dir string, mat *keys.Material) *Host {
	t.Helper()
	h := New(Options{
		Dir: filepath.Join(dir, "tenants"), Material: mat,
		Base: core.Options{Name: "test", Vantage: "test"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return h
}

func TestTenantsAreSeparateAndSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	mat, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	h := newHost(t, dir, mat)
	ctx, cancel := context.WithCancel(context.Background())
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := h.Get(appA); err != ErrUnknownTenant {
		t.Fatalf("an app nobody created was opened: %v", err)
	}
	if _, err := h.Ensure("../../etc"); err == nil {
		t.Fatal("a path was accepted as an app id")
	}

	a, err := h.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != "0f2c1d9e-3b4a-4c5d-8e6f-7a8b9c0d1e2f" {
		t.Fatalf("app id not canonical: %q", a.ID)
	}
	if !a.Mon.Configured() || a.Mon.Config().Tenant != a.ID {
		t.Fatalf("a new app should start configured for itself: %+v", a.Mon.Config())
	}
	b, err := h.Ensure(appB)
	if err != nil {
		t.Fatal(err)
	}

	// A credential given to one app is not in the other's vault.
	admin := &auth.Identity{Sub: "ada", Roles: []string{auth.OIDCPlatformAdmin}}
	model, _ := auth.NewAppModel()
	pa, err := model.Resolve(admin, a.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Mon.PutSecret(pa, "db_password", "s3cret", []string{"db.example.com"}, "", "Add the probe account"); err != nil {
		t.Fatal(err)
	}
	if names := a.Mon.Vault().Names(); len(names) != 1 {
		t.Fatalf("app A should hold one credential, holds %v", names)
	}
	if names := b.Mon.Vault().Names(); len(names) != 0 {
		t.Fatalf("app B sees app A's credentials: %v", names)
	}

	// Each app's record is its own: different roots.
	la, _ := a.Mon.Lineage(auth.System(a.ID))
	lb, _ := b.Mon.Lineage(auth.System(b.ID))
	if la == nil || lb == nil || la.Root == lb.Root {
		t.Fatalf("two apps share a record: %+v %+v", la, lb)
	}
	rootsBefore, err := h.Roots()
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	h.Close()

	// After a restart both apps come back with their configuration and
	// their credentials, without anything being delivered again.
	h2 := newHost(t, dir, mat)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := h2.Start(ctx2); err != nil {
		t.Fatal(err)
	}
	if n := len(h2.List()); n != 2 {
		t.Fatalf("expected both apps back, got %d", n)
	}
	a2, err := h2.Get(appA)
	if err != nil {
		t.Fatal(err)
	}
	if names := a2.Mon.Vault().Names(); len(names) != 1 {
		t.Fatalf("app A lost its credential across a restart: %v", names)
	}
	rootsAfter, _ := h2.Roots()
	if rootsAfter == rootsBefore {
		t.Fatal("the summary did not move although the shutdown and the boot were recorded")
	}

	// Removing an app removes everything it held.
	if err := h2.Remove(appA); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tenants", a.ID)); !os.IsNotExist(err) {
		t.Fatalf("app A's directory survived its removal: %v", err)
	}
	if _, err := h2.Get(appA); err != ErrUnknownTenant {
		t.Fatalf("a removed app was reopened: %v", err)
	}
	h2.Close()
}
