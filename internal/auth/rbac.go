// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package auth

import (
	"fmt"
	"sort"
	"strings"
)

// RoleSpec is one role in the monitor's role model.

type RoleSpec struct {
	Name string `json:"name"`
	// Title is the human name shown in the explorer.
	Title string `json:"title,omitempty"`
	// OIDCRoles are the identity-provider roles that grant this role.
	OIDCRoles []string `json:"oidc_roles"`
	// Permissions are the verbs this role carries.
	Permissions []string `json:"permissions"`
	// PII clears the role to see personal data in the clear. A role
	// without it sees those fields redacted, whatever else it may read.
	PII bool `json:"pii,omitempty"`
	// IncompatibleWith names roles that may not be held alongside this
	// one. A caller who holds both is refused rather than silently
	// acting under the more powerful of the two: separation of duties is
	// only real if the system notices when it is breached.
	IncompatibleWith []string `json:"incompatible_with,omitempty"`
}

// Model is a register's whole role model.
type Model struct {
	roles  map[string]*RoleSpec
	byRole map[string][]string // identity-provider role → register roles
}

// NewModel builds the lookup tables and checks the declarations are
// coherent.
func NewModel(specs []RoleSpec) (*Model, error) {
	m := &Model{roles: map[string]*RoleSpec{}, byRole: map[string][]string{}}
	for i := range specs {
		s := specs[i]
		if s.Name == "" {
			return nil, fmt.Errorf("roles: a role has no name")
		}
		if _, dup := m.roles[s.Name]; dup {
			return nil, fmt.Errorf("roles: %q is declared twice", s.Name)
		}
		m.roles[s.Name] = &s
		for _, r := range s.OIDCRoles {
			m.byRole[r] = append(m.byRole[r], s.Name)
		}
	}
	for _, s := range m.roles {
		for _, other := range s.IncompatibleWith {
			if _, ok := m.roles[other]; !ok {
				return nil, fmt.Errorf("roles: %q is declared incompatible with unknown role %q", s.Name, other)
			}
		}
	}
	return m, nil
}

// Roles lists the declared roles in name order.
func (m *Model) Roles() []*RoleSpec {
	out := make([]*RoleSpec, 0, len(m.roles))
	for _, s := range m.roles {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Role returns one role spec.
func (m *Model) Role(name string) *RoleSpec { return m.roles[name] }

// Principal is an authenticated caller resolved against the role model.
type Principal struct {
	Sub     string   `json:"sub"`
	Display string   `json:"display,omitempty"`
	Email   string   `json:"email,omitempty"`
	Tenant  string   `json:"tenant"`
	Roles   []string `json:"roles"`
	// Acting is the role the caller is acting under for this request.
	Acting string `json:"acting_role"`
	// PII reports whether any held role clears the caller to see
	// personal data in the clear.
	PII bool `json:"pii"`

	perms map[string]bool
}

// Resolve maps a verified identity onto the role model. The requested
// acting role, when given, must be one the caller actually holds.
func (m *Model) Resolve(id *Identity, tenant, requestedRole string) (*Principal, error) {
	held := map[string]bool{}
	for _, r := range id.Roles {
		for _, name := range m.byRole[r] {
			held[name] = true
		}
	}
	if len(held) == 0 {
		return nil, fmt.Errorf("no register role: the caller holds none of this register's identity-provider roles")
	}
	names := make([]string, 0, len(held))
	for name := range held {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		for _, other := range m.roles[name].IncompatibleWith {
			if held[other] {
				return nil, fmt.Errorf("separation of duties: roles %q and %q may not be held together", name, other)
			}
		}
	}

	acting := requestedRole
	if acting == "" {
		acting = names[0]
	} else if !held[acting] {
		return nil, fmt.Errorf("acting role %q is not held by this caller", acting)
	}

	p := &Principal{
		Sub: id.Sub, Display: id.Display, Email: id.Email,
		Tenant: tenant, Roles: names, Acting: acting,
		perms: map[string]bool{},
	}
	if p.Display == "" {
		p.Display = id.Sub
	}
	for _, name := range names {
		spec := m.roles[name]
		if spec.PII {
			p.PII = true
		}
		for _, perm := range spec.Permissions {
			p.perms[perm] = true
		}
	}
	return p, nil
}

// Can reports whether the principal holds a bare permission.
func (p *Principal) Can(perm string) bool { return p.perms[perm] }

// Grant adds a permission to a principal the process constructed for
// itself. It is not reachable from a request: Resolve builds every
// principal that comes from a token, and it grants only what the role
// model declares.
func (p *Principal) Grant(perms ...string) {
	if p.perms == nil {
		p.perms = map[string]bool{}
	}
	for _, perm := range perms {
		p.perms[perm] = true
	}
}

// CanOn reports whether the principal holds a permission over a named
// scope, e.g. CanOn("propose", "ownership_transfer").
func (p *Principal) CanOn(perm, scope string) bool {
	return p.perms[perm] || p.perms[perm+":*"] || p.perms[perm+":"+scope]
}

// Permissions lists the principal's permissions in a stable order.
func (p *Principal) Permissions() []string {
	out := make([]string, 0, len(p.perms))
	for perm := range p.perms {
		out = append(out, perm)
	}
	sort.Strings(out)
	return out
}

// Describe renders the principal for a log line.
func (p *Principal) Describe() string {
	return fmt.Sprintf("%s as %s (%s)", p.Sub, p.Acting, strings.Join(p.Roles, ","))
}
