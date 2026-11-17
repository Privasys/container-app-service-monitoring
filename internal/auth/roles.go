// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package auth

import "github.com/Privasys/container-app-service-monitoring/internal/model"

// The monitor's role model.
//
// It is built in rather than declared in a pack, because unlike a
// register the monitor's verbs do not vary by domain: somebody edits
// the service model, somebody responds to incidents, somebody reads the
// status page. Configure is not in this list at all: it is gated by the
// runtime to the app's owners and admins, at enclave level, so the
// application cannot omit the check.
const (
	PermModel       = "model"       // edit services, components, monitors, schedules, objectives
	PermSecrets     = "secrets"     // put and destroy credentials (never read them)
	PermRun         = "run"         // run a monitor out of band
	PermRespond     = "respond"     // open, update and resolve incidents
	PermMaintenance = "maintenance" // declare and cancel maintenance windows
	PermExplorer    = "explorer"    // read the transaction log
	PermProofs      = "proofs"      // fetch evidence bundles
	PermCheckpoints = "checkpoints" // read and issue root checkpoints
	PermReports     = "reports"     // issue SLA reports
	PermRetention   = "retention"   // run a policy-gated prune
	PermAdmin       = "admin"       // callbacks, export, instance settings
)

// Roles is the built-in role model.
//
// The identity-provider roles are the ones the platform already issues
// for an app's team, plus monitor-specific ones a customer can grant
// their own responders.
var Roles = []RoleSpec{
	{
		Name: "owner", Title: "Owner",
		OIDCRoles: []string{"monitoring:owner", "privasys-platform:monitoring:owner"},
		Permissions: []string{
			PermModel, PermSecrets, PermRun, PermRespond, PermMaintenance,
			PermExplorer, PermProofs, PermCheckpoints, PermReports, PermRetention, PermAdmin,
		},
	},
	{
		Name: "editor", Title: "Editor",
		OIDCRoles: []string{"monitoring:editor", "privasys-platform:monitoring:editor"},
		Permissions: []string{
			PermModel, PermSecrets, PermRun, PermRespond, PermMaintenance,
			PermExplorer, PermProofs, PermCheckpoints, PermReports,
		},
	},
	{
		// A responder runs the incident, and can declare the maintenance
		// window that goes with the fix, but cannot quietly rewrite the
		// monitor that caught it.
		Name: "responder", Title: "Responder",
		OIDCRoles: []string{"monitoring:responder", "privasys-platform:monitoring:responder"},
		Permissions: []string{
			PermRun, PermRespond, PermMaintenance, PermExplorer, PermProofs, PermCheckpoints,
		},
	},
	{
		Name: "auditor", Title: "Auditor",
		OIDCRoles: []string{"monitoring:auditor", "privasys-platform:monitoring:auditor"},
		Permissions: []string{
			PermExplorer, PermProofs, PermCheckpoints, PermReports,
		},
	},
	{
		Name: "viewer", Title: "Viewer",
		OIDCRoles: []string{"monitoring:viewer", "privasys-platform:monitoring:viewer"},
		Permissions: []string{
			PermExplorer, PermProofs, PermCheckpoints,
		},
	},
}

// NewDefaultModel builds the role model.
func NewDefaultModel() (*Model, error) { return NewModel(Roles) }

// Anonymous is the principal behind an unauthenticated request. It
// holds no permissions at all: the public status surface is served by
// handlers that ask for none, and everything else refuses it.
func Anonymous(tenant string) *Principal {
	return &Principal{
		Sub: "anonymous", Display: "Anonymous", Tenant: tenant,
		Acting: "anonymous", Roles: []string{"anonymous"},
		perms: map[string]bool{},
	}
}

// System is the principal the monitor acts as when it writes down what
// it observed rather than what it was told. It is not reachable from a
// request.
func System(tenant string) *Principal {
	p := &Principal{
		Sub: "system", Display: "Monitor", Tenant: tenant,
		Acting: "system", Roles: []string{"system"},
		perms: map[string]bool{},
	}
	p.Grant(PermModel, PermRun, PermRespond, PermExplorer, PermProofs,
		PermCheckpoints, PermReports, PermRetention)
	return p
}

// Author renders the principal as a commit author.
func (p *Principal) Author() model.Author {
	return model.Author{Sub: p.Sub, Display: p.Display, Role: p.Acting}
}

// The role model of an app's tenant on the shared platform instance.
//
// The platform's sign-in already carries a person's role on each app,
// as "privasys-platform:app:<app id>:<tier>", synced there by the
// control plane on every team change. "{app}" in these declarations is
// filled with the id of the app a request is about, so a role on one
// app grants nothing on another. Global roles such as monitoring:owner
// are deliberately absent: on the shared instance they would reach
// every app. The one global role is the Privasys platform's own
// administrator, who is super admin everywhere.
const (
	RolePlatformAdmin = "platform-admin"
	RoleAppAdmin      = "app-admin"
	RoleAppMember     = "app-member"
	RoleAppViewer     = "app-viewer"

	// OIDCPlatformAdmin is the control plane's administrator role.
	OIDCPlatformAdmin = "privasys-platform:admin"
)

// AppRoles is the role model of an app tenant.
var AppRoles = []RoleSpec{
	{
		Name: RolePlatformAdmin, Title: "Privasys",
		OIDCRoles: []string{OIDCPlatformAdmin},
		Permissions: []string{
			PermModel, PermSecrets, PermRun, PermRespond, PermMaintenance,
			PermExplorer, PermProofs, PermCheckpoints, PermReports, PermRetention, PermAdmin,
		},
		PII: true,
	},
	{
		// The app's owners and admins in the portal, and the people they
		// make support admins.
		Name: RoleAppAdmin, Title: "Support admin",
		OIDCRoles: []string{
			"privasys-platform:app:{app}:owner",
			"privasys-platform:app:{app}:admin",
			"privasys-platform:app:{app}:support-admin",
		},
		Permissions: []string{
			PermModel, PermSecrets, PermRun, PermRespond, PermMaintenance,
			PermExplorer, PermProofs, PermCheckpoints, PermReports, PermAdmin,
		},
		PII: true,
	},
	{
		// Responds to incidents and works tickets, cannot change what is
		// watched or who is on the team.
		Name: RoleAppMember, Title: "Support member",
		OIDCRoles: []string{"privasys-platform:app:{app}:support-member"},
		Permissions: []string{
			PermRun, PermRespond, PermMaintenance, PermExplorer, PermProofs, PermCheckpoints,
		},
		PII: true,
	},
	{
		Name: RoleAppViewer, Title: "Support viewer",
		OIDCRoles: []string{
			"privasys-platform:app:{app}:viewer",
			"privasys-platform:app:{app}:support-viewer",
		},
		Permissions: []string{PermExplorer, PermProofs, PermCheckpoints, PermReports},
	},
}

// NewAppModel builds the role model of an app tenant.
func NewAppModel() (*Model, error) { return NewModel(AppRoles) }
