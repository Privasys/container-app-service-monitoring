// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package keys

import (
	"path/filepath"
	"testing"
)

func TestTenantKeysAreStableAndSeparate(t *testing.T) {
	m, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()

	a1, err := m.TenantKeys("app-a", filepath.Join(base, "a"))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := m.TenantKeys("app-a", filepath.Join(base, "a"))
	if err != nil {
		t.Fatalf("reopening the same tenant: %v", err)
	}
	if a1.Commitment != a2.Commitment || a1.Vault != a2.Vault {
		t.Fatal("a tenant's keys changed between two derivations")
	}
	if a1.Commitment == a1.Vault {
		t.Fatal("the commitment key and the vault key are the same")
	}

	b, err := m.TenantKeys("app-b", filepath.Join(base, "b"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Commitment == a1.Commitment || b.Vault == a1.Vault {
		t.Fatal("two tenants share a key")
	}

	// A tenant's directory opened under another tenant's name is refused
	// rather than opened over.
	if _, err := m.TenantKeys("app-b", filepath.Join(base, "a")); err == nil {
		t.Fatal("app-b's keys were accepted for app-a's record")
	}

	// Another instance's master derives other keys for the same tenant.
	other, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	o, err := other.TenantKeys("app-a", filepath.Join(t.TempDir(), "a"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Commitment == a1.Commitment {
		t.Fatal("two instances derived the same tenant key")
	}
}
