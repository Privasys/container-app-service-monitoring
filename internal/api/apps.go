// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/tenancy"
)

// appPath is where an instance route is served for one app:
// /api/v1/monitors becomes /api/v1/apps/{app}/monitors, and the tools
// move under the same prefix.
func appPath(path string) string {
	if rest, ok := strings.CutPrefix(path, "/api/v1/"); ok {
		return "/api/v1/apps/{app}/" + rest
	}
	return "/api/v1/apps/{app}" + path
}

// wrapApp serves a route for one app's monitor.
//
// The caller is resolved against that app before anything says whether
// the app has a monitor here, so a stranger learns nothing about which
// apps are watched: the answer to "may I" comes first.
func (s *Server) wrapApp(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, principal, ok := s.appCaller(w, r)
		if !ok {
			return
		}
		t, err := s.Tenants.Get(id)
		if err != nil {
			s.tenantError(w, err)
			return
		}
		serve(w, h, &request{w: w, r: r, mon: t.Mon, sched: t.Scheduler, p: principal, oncall: t.OnCall})
	}
}

// appCaller resolves the app named in the path and the caller's role on
// it, writing the error response itself when either fails.
func (s *Server) appCaller(w http.ResponseWriter, r *http.Request) (string, *auth.Principal, bool) {
	if s.Tenants == nil || s.AppRoles == nil {
		writeError(w, http.StatusNotFound, "this monitor does not host apps", "")
		return "", nil, false
	}
	id, err := tenancy.Canonical(r.PathValue("app"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "not an app id", "")
		return "", nil, false
	}
	principal, err := s.authenticate(r, s.AppRoles, id)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated", err.Error())
		return "", nil, false
	}
	return id, principal, true
}

func (s *Server) tenantError(w http.ResponseWriter, err error) {
	if errors.Is(err, tenancy.ErrUnknownTenant) {
		writeError(w, http.StatusNotFound, "monitoring is not enabled for this app", "")
		return
	}
	s.log.Error("could not open an app's monitor", "error", err)
	writeError(w, http.StatusInternalServerError, "the app's monitor could not be opened", "")
}

func isPlatformAdmin(p *auth.Principal) bool {
	return slices.Contains(p.Roles, auth.RolePlatformAdmin)
}

// enableApp creates an app's monitor. The app's own admins may do it, as
// may the platform admins: turning monitoring on is the first thing a
// team does, and it gives nobody access they did not already have.
func (s *Server) enableApp(w http.ResponseWriter, r *http.Request) {
	id, principal, ok := s.appCaller(w, r)
	if !ok {
		return
	}
	if !principal.Can(auth.PermAdmin) {
		writeError(w, http.StatusForbidden, principal.Acting+" may not enable monitoring for this app", "")
		return
	}
	_, err := s.Tenants.Get(id)
	created := errors.Is(err, tenancy.ErrUnknownTenant)
	if err != nil && !created {
		s.tenantError(w, err)
		return
	}
	t, err := s.Tenants.Ensure(id)
	if err != nil {
		s.tenantError(w, err)
		return
	}
	// The zero-config status, now rather than at the next listing, when
	// the platform has already told us where the app is served.
	if app, ok := s.Tenants.KnownApp(t.ID); ok {
		if changed, err := t.EnsureStatus(app); err != nil {
			s.log.Error("could not set an app's zero-config status", "app", t.ID, "error", err)
		} else if changed {
			t.Scheduler.Reload()
		}
	}
	if created {
		s.log.Info("enabled monitoring for an app", "app", t.ID, "by", principal.Sub)
		if s.TenantsChanged != nil {
			s.TenantsChanged()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": t.ID, "created": created})
}

// removeApp deletes an app's monitor and everything it held. It is the
// platform's call, made when the app itself is deleted, and only a
// platform admin may make it: an app's own team cannot erase its
// incident history.
func (s *Server) removeApp(w http.ResponseWriter, r *http.Request) {
	id, principal, ok := s.appCaller(w, r)
	if !ok {
		return
	}
	if !isPlatformAdmin(principal) {
		writeError(w, http.StatusForbidden, principal.Acting+" may not remove an app's monitor", "")
		return
	}
	if err := s.Tenants.Remove(id); err != nil {
		s.log.Error("could not remove an app's monitor", "app", id, "error", err)
		writeError(w, http.StatusInternalServerError, "the app's monitor could not be removed", "")
		return
	}
	s.log.Info("removed an app's monitor", "app", id, "by", principal.Sub)
	if s.TenantsChanged != nil {
		s.TenantsChanged()
	}
	w.WriteHeader(http.StatusNoContent)
}

// listApps lists the apps with a monitor here, for the platform admins.
func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	if s.Tenants == nil || s.AppRoles == nil {
		writeError(w, http.StatusNotFound, "this monitor does not host apps", "")
		return
	}
	// Resolved against no app: only the instance-wide roles match.
	principal, err := s.authenticate(r, s.AppRoles, "")
	if err != nil || !isPlatformAdmin(principal) {
		writeError(w, http.StatusUnauthorized, "not authenticated", "only a platform admin may list the apps")
		return
	}
	type app struct {
		App     string `json:"app"`
		Root    string `json:"root,omitempty"`
		Version uint64 `json:"version,omitempty"`
	}
	out := []app{}
	for _, t := range s.Tenants.List() {
		a := app{App: t.ID}
		if lineage, err := t.Mon.Lineage(auth.System(t.ID)); err == nil && lineage != nil {
			a.Root, a.Version = lineage.Root, lineage.Version
		}
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}
