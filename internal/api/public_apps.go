// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
	"net/http"

	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/tenancy"
)

// One app's public status surface: the same page, JSON and evidence as
// the instance's own, under /apps/{app}/ for the page and
// /api/v1/public/apps/{app}/ and /api/v2/apps/{app}/ for the data.
//
// An app answers here only once its team has made a service public.
// Until then every route is a 404, the same 404 as for an app with no
// monitor at all: whether an app is watched, and its checkpoints and
// evidence, are the team's to publish, not ours.

type publicMonKey struct{}

// pmon is the monitor a public request reads: the app's, on an app route,
// otherwise the instance's own.
func (s *Server) pmon(r *http.Request) *core.Monitor {
	if m, ok := r.Context().Value(publicMonKey{}).(*core.Monitor); ok {
		return m
	}
	return s.mon
}

// publicApp serves a public route for one app's monitor.
func (s *Server) publicApp(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mon := s.publicAppMonitor(r)
		if mon == nil {
			writeError(w, http.StatusNotFound, "no public status page for this app", "")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), publicMonKey{}, mon)))
	}
}

func (s *Server) publicAppMonitor(r *http.Request) *core.Monitor {
	if s.Tenants == nil {
		return nil
	}
	id, err := tenancy.Canonical(r.PathValue("app"))
	if err != nil {
		return nil
	}
	t, err := s.Tenants.Get(id)
	if err != nil {
		return nil
	}
	services, err := t.Mon.Services()
	if err != nil {
		return nil
	}
	for _, svc := range services {
		if svc.Visibility == model.VisibilityPublic {
			return t.Mon
		}
	}
	return nil
}

// registerPublicApps adds the per-app copies of the public routes.
func (s *Server) registerPublicApps(mux *http.ServeMux) {
	const v1 = "/api/v1/public/apps/{app}"
	mux.HandleFunc("GET "+v1+"/services", s.publicApp(s.publicServices))
	mux.HandleFunc("GET "+v1+"/status", s.publicApp(s.publicStatus))
	mux.HandleFunc("GET "+v1+"/status/{slug}", s.publicApp(s.publicStatus))
	mux.HandleFunc("GET "+v1+"/uptime/{slug}", s.publicApp(s.publicUptime))
	mux.HandleFunc("GET "+v1+"/incidents/{slug}", s.publicApp(s.publicIncidents))
	mux.HandleFunc("GET "+v1+"/evidence/bucket", s.publicApp(s.publicBucketEvidence))
	mux.HandleFunc("GET "+v1+"/checkpoints", s.publicApp(s.publicCheckpoints))
	mux.HandleFunc("GET "+v1+"/history.atom", s.publicApp(s.historyAtom))

	const v2 = "/api/v2/apps/{app}"
	mux.HandleFunc("GET "+v2+"/summary.json", s.publicApp(s.v2Summary))
	mux.HandleFunc("GET "+v2+"/status.json", s.publicApp(s.v2Status))
	mux.HandleFunc("GET "+v2+"/components.json", s.publicApp(s.v2Components))
	mux.HandleFunc("GET "+v2+"/incidents.json", s.publicApp(s.v2Incidents))
	mux.HandleFunc("GET "+v2+"/incidents/unresolved.json", s.publicApp(s.v2Unresolved))
	mux.HandleFunc("GET "+v2+"/scheduled-maintenances.json", s.publicApp(s.v2Maintenance))
}
