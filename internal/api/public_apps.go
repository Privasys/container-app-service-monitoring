// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

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
	id, ok := s.Tenants.Resolve(r.PathValue("app"))
	if !ok {
		return nil
	}
	// Under an account's address, only that account's apps answer.
	if slug := strings.TrimPrefix(r.PathValue("account"), "@"); slug != "" {
		if known, ok := s.Tenants.KnownApp(id); !ok || !strings.EqualFold(known.AccountSlug, slug) {
			return nil
		}
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
	mux.HandleFunc("GET /api/v1/public/apps", s.publicAppIndex)
	mux.HandleFunc("GET /api/v1/public/accounts/{account}/apps", s.publicAppIndex)
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

// A directory is the list of one account's apps shown on that account's
// home pages: status.privasys.org/@<account>/, and the site's own home
// page for the account that runs this monitor. An app is in it when it
// belongs to the account, its team lists it in the portal, and it has
// something public to show. Its own page answers whether listed or not.

// directoryAccount is the account a directory request names: the one in
// the address, or the account this monitor's own app belongs to.
func (s *Server) directoryAccount(r *http.Request) (tenancy.Account, bool) {
	if s.Tenants == nil {
		return tenancy.Account{}, false
	}
	if slug := strings.TrimPrefix(r.PathValue("account"), "@"); slug != "" {
		return s.Tenants.AccountBySlug(slug)
	}
	return s.Tenants.AccountOf(s.HomeApp)
}

// listedIn reports whether an app belongs in an account's directory.
func (s *Server) listedIn(account tenancy.Account, appID string) (tenancy.App, bool) {
	known, ok := s.Tenants.KnownApp(appID)
	if !ok || !known.Listed || known.AccountID == "" || known.AccountID != account.ID {
		return known, false
	}
	return known, true
}

// appPage is where an app's status page is: under its account's short
// name when the account has one, otherwise at the app's own address.
func appPage(known tenancy.App, appID string) string {
	name := known.Name
	if name == "" {
		name = appID
	}
	if known.AccountSlug != "" {
		return "/@" + known.AccountSlug + "/" + name + "/"
	}
	return "/apps/" + name + "/"
}

// accountJSON is how a directory names its account.
func accountJSON(a tenancy.Account) map[string]string {
	return map[string]string{"slug": a.Slug, "name": a.Name}
}

// publicAppIndex lists an account's listed apps that have published a
// status page, with where each is now. An unknown account is a 404, the
// same as an account with nothing listed would be to a stranger guessing.
func (s *Server) publicAppIndex(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		App       string `json:"app"`
		Service   string `json:"service"`
		Slug      string `json:"slug"`
		Indicator string `json:"indicator"`
		Headline  string `json:"headline"`
		Page      string `json:"page"`
	}
	account, found := s.directoryAccount(r)
	if !found && r.PathValue("account") != "" {
		writeError(w, http.StatusNotFound, "no such status page", "")
		return
	}
	out := []entry{}
	if found {
		now := time.Now().Unix()
		for _, t := range s.Tenants.List() {
			known, listed := s.listedIn(account, t.ID)
			if !listed {
				continue
			}
			services, err := t.Mon.Services()
			if err != nil {
				continue
			}
			for _, svc := range services {
				if svc.Visibility != model.VisibilityPublic {
					continue
				}
				e := entry{App: t.ID, Service: svc.Name, Slug: svc.Slug, Page: appPage(known, t.ID)}
				if page, err := t.Mon.Status(svc.ID, now); err == nil && page != nil {
					e.Indicator, e.Headline = page.Indicator, page.Headline
				}
				out = append(out, e)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Service) < strings.ToLower(out[j].Service) })
	body := map[string]any{"apps": out}
	if found {
		body["account"] = accountJSON(account)
	}
	writePublicJSON(w, http.StatusOK, body)
}
