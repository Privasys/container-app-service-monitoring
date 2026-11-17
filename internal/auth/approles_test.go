// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package auth

import "testing"

const (
	appA = "0f2c1d9e-3b4a-4c5d-8e6f-7a8b9c0d1e2f"
	appB = "11111111-2222-4333-8444-555555555555"
)

func TestAppRolesAreScopedToTheirApp(t *testing.T) {
	m, err := NewAppModel()
	if err != nil {
		t.Fatal(err)
	}
	keyA := AppKey(appA)
	if keyA != "0f2c1d9e3b4a4c5d8e6f7a8b9c0d1e2f" {
		t.Fatalf("AppKey = %q", keyA)
	}

	owner := &Identity{Sub: "ada", Roles: []string{"privasys-platform:app:" + keyA + ":owner"}}
	p, err := m.Resolve(owner, appA, "")
	if err != nil {
		t.Fatalf("owner of A on A: %v", err)
	}
	if p.Acting != RoleAppAdmin || !p.Can(PermAdmin) || !p.Can(PermSecrets) {
		t.Fatalf("owner of A should be support admin on A, got %+v", p)
	}
	if _, err := m.Resolve(owner, appB, ""); err == nil {
		t.Fatal("an owner of app A was given a role on app B")
	}
	if _, err := m.Resolve(owner, "privasys-platform", ""); err == nil {
		t.Fatal("an app role matched the platform tenant")
	}

	member := &Identity{Sub: "bo", Roles: []string{"privasys-platform:app:" + keyA + ":support-member"}}
	p, err = m.Resolve(member, appA, "")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Can(PermRespond) || p.Can(PermModel) || p.Can(PermSecrets) || p.Can(PermAdmin) {
		t.Fatalf("a support member responds but does not change the model, secrets or team: %+v", p)
	}

	viewer := &Identity{Sub: "cy", Roles: []string{"privasys-platform:app:" + keyA + ":viewer"}}
	p, err = m.Resolve(viewer, appA, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Can(PermRespond) || !p.Can(PermExplorer) {
		t.Fatalf("a viewer reads and does not respond: %+v", p)
	}

	admin := &Identity{Sub: "privasys", Roles: []string{OIDCPlatformAdmin}}
	for _, app := range []string{appA, appB} {
		p, err := m.Resolve(admin, app, "")
		if err != nil || !p.Can(PermAdmin) || !p.Can(PermRetention) {
			t.Fatalf("the platform admin is super admin on %s: %v %+v", app, err, p)
		}
	}

	// The single-tenant roles are not part of an app's model: on the
	// shared instance they would reach every app.
	legacy := &Identity{Sub: "dee", Roles: []string{"monitoring:owner", "privasys-platform:monitoring:owner"}}
	if _, err := m.Resolve(legacy, appA, ""); err == nil {
		t.Fatal("a global monitoring role was accepted on an app tenant")
	}
}
