// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/availability"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// The public surface.
//
// Everything here answers without a token, because a status page behind
// a login is not a status page. A service can be marked private, which
// removes it from these endpoints; marking it private is itself a
// signed transaction, so a service that disappeared from its own status
// page did not do so quietly.
//
// Two documents are served for every service: ours, which carries the
// attestation and the ledger coordinates, and the shape that existing
// status-page consumers already parse, so a customer's dashboards and
// bots keep working while gaining evidence they can check.

// resolveService finds the service a public request is about. With one
// service configured, which is the ordinary case, the slug is optional.
func (s *Server) resolveService(r *http.Request) (*model.Service, error) {
	slug := r.PathValue("slug")
	if slug == "" {
		slug = r.URL.Query().Get("service")
	}
	if slug != "" {
		svc, err := s.mon.ServiceBySlug(slug)
		if err != nil {
			return nil, err
		}
		if svc == nil {
			svc, err = s.mon.Service(slug)
			if err != nil {
				return nil, err
			}
		}
		if svc == nil || svc.Visibility != model.VisibilityPublic {
			return nil, nil
		}
		return svc, nil
	}
	services, err := s.mon.Services()
	if err != nil {
		return nil, err
	}
	for i := range services {
		if services[i].Visibility == model.VisibilityPublic {
			return &services[i], nil
		}
	}
	return nil, nil
}

func (s *Server) publicServices(w http.ResponseWriter, r *http.Request) {
	services, err := s.mon.Services()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the services", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(services))
	for _, svc := range services {
		if svc.Visibility != model.VisibilityPublic {
			continue
		}
		out = append(out, map[string]any{
			"name": svc.Name, "slug": svc.Slug, "description": svc.Description,
		})
	}
	writePublicJSON(w, http.StatusOK, map[string]any{"services": out})
}

// page builds the status document, or reports why it cannot.
func (s *Server) page(w http.ResponseWriter, r *http.Request) *core.StatusPage {
	if state, _ := s.State(); state != StateReady {
		writePublicJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error": "this monitor has not been configured yet",
		})
		return nil
	}
	svc, err := s.resolveService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the service", err.Error())
		return nil
	}
	if svc == nil {
		writePublicJSON(w, http.StatusNotFound, map[string]any{"error": "no public status page"})
		return nil
	}
	page, err := s.mon.Status(svc.ID, time.Now().Unix())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not build the status page", err.Error())
		return nil
	}
	return page
}

func (s *Server) publicStatus(w http.ResponseWriter, r *http.Request) {
	page := s.page(w, r)
	if page == nil {
		return
	}
	writePublicJSON(w, http.StatusOK, page)
}

// publicUptime serves the folded readings behind the uptime bars, so a
// reader can recompute the percentage rather than take it.
func (s *Server) publicUptime(w http.ResponseWriter, r *http.Request) {
	svc, err := s.resolveService(r)
	if err != nil || svc == nil {
		writePublicJSON(w, http.StatusNotFound, map[string]any{"error": "no public status page"})
		return
	}
	to := int64Param(r, "to")
	if to == 0 {
		to = time.Now().Unix()
	}
	from := int64Param(r, "from")
	if from == 0 {
		from = to - core.StatusDays*86400
	}
	width := int64Param(r, "width")
	if width == 0 {
		width = core.WidthHour
	}
	buckets, err := s.mon.Buckets(svc.ID, width, from, to)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the readings", err.Error())
		return
	}
	root, version := "", uint64(0)
	if lineage, err := s.mon.Lineage(auth.System(s.mon.Config().Tenant)); err == nil && lineage != nil {
		root, version = lineage.Root, lineage.Version
	}
	writePublicJSON(w, http.StatusOK, map[string]any{
		"service": svc.Slug, "width": width, "from": from, "to": to,
		"buckets": buckets, "root": root, "version": version,
	})
}

func (s *Server) publicIncidents(w http.ResponseWriter, r *http.Request) {
	svc, err := s.resolveService(r)
	if err != nil || svc == nil {
		writePublicJSON(w, http.StatusNotFound, map[string]any{"error": "no public status page"})
		return
	}
	incidents, err := s.mon.Incidents(svc.ID, int64Param(r, "from"), int64Param(r, "to"),
		intParam(r, "limit", 50))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the incidents", err.Error())
		return
	}
	writePublicJSON(w, http.StatusOK, map[string]any{"incidents": incidents})
}

// publicBucketEvidence hands a reader the proof behind one folded
// interval. This is the endpoint that turns a status page from a claim
// into something checkable: the page fetches it, recomputes the root
// from the proof, and checks the signature against a key it fetched
// once from the well-known document.
func (s *Server) publicBucketEvidence(w http.ResponseWriter, r *http.Request) {
	monitorID := r.URL.Query().Get("monitor")
	width := int64Param(r, "width")
	start := int64Param(r, "start")
	if monitorID == "" || width == 0 {
		writePublicJSON(w, http.StatusBadRequest,
			map[string]any{"error": "name the monitor, the width and the start"})
		return
	}
	// The evidence surface is anonymous by design, and it is a proof
	// about a public figure. It carries no personal data: a folded
	// interval is counts and latencies.
	p := auth.Anonymous(s.mon.Config().Tenant)
	p.Grant(auth.PermProofs, auth.PermCheckpoints)
	bundle, err := s.mon.BucketEvidence(p, monitorID, width, start)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such interval", err.Error())
		return
	}
	writePublicJSON(w, http.StatusOK, bundle)
}

func (s *Server) publicCheckpoints(w http.ResponseWriter, r *http.Request) {
	p := auth.Anonymous(s.mon.Config().Tenant)
	p.Grant(auth.PermCheckpoints)
	checkpoints, err := s.mon.Checkpoints(p, intParam(r, "limit", 50))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the checkpoints", err.Error())
		return
	}
	writePublicJSON(w, http.StatusOK, map[string]any{"checkpoints": checkpoints})
}

// -- the shape existing consumers parse ------------------------------------

func (s *Server) v2Summary(w http.ResponseWriter, r *http.Request) {
	page := s.page(w, r)
	if page == nil {
		return
	}
	writePublicJSON(w, http.StatusOK, map[string]any{
		"page":                   v2Page(page),
		"status":                 v2Status(page),
		"components":             v2Components(page),
		"incidents":              v2Incidents(page.Incidents),
		"scheduled_maintenances": v2Maintenances(page.Maintenance),
		"attestation":            page.Attestation,
	})
}

func (s *Server) v2Status(w http.ResponseWriter, r *http.Request) {
	page := s.page(w, r)
	if page == nil {
		return
	}
	writePublicJSON(w, http.StatusOK, map[string]any{
		"page": v2Page(page), "status": v2Status(page),
	})
}

func (s *Server) v2Components(w http.ResponseWriter, r *http.Request) {
	page := s.page(w, r)
	if page == nil {
		return
	}
	writePublicJSON(w, http.StatusOK, map[string]any{
		"page": v2Page(page), "components": v2Components(page),
	})
}

func (s *Server) v2Incidents(w http.ResponseWriter, r *http.Request) {
	page := s.page(w, r)
	if page == nil {
		return
	}
	all := append(append([]model.Incident{}, page.Incidents...), page.History...)
	writePublicJSON(w, http.StatusOK, map[string]any{
		"page": v2Page(page), "incidents": v2Incidents(all),
	})
}

func (s *Server) v2Unresolved(w http.ResponseWriter, r *http.Request) {
	page := s.page(w, r)
	if page == nil {
		return
	}
	writePublicJSON(w, http.StatusOK, map[string]any{
		"page": v2Page(page), "incidents": v2Incidents(page.Incidents),
	})
}

func (s *Server) v2Maintenance(w http.ResponseWriter, r *http.Request) {
	page := s.page(w, r)
	if page == nil {
		return
	}
	writePublicJSON(w, http.StatusOK, map[string]any{
		"page": v2Page(page), "scheduled_maintenances": v2Maintenances(page.Maintenance),
	})
}

func v2Page(page *core.StatusPage) map[string]any {
	return map[string]any{
		"id": page.Slug, "name": page.Service, "url": "",
		"time_zone":  page.Timezone,
		"updated_at": time.Unix(page.UpdatedAt, 0).UTC().Format(time.RFC3339),
	}
}

func v2Status(page *core.StatusPage) map[string]any {
	return map[string]any{"indicator": page.Indicator, "description": page.Headline}
}

func v2Components(page *core.StatusPage) []map[string]any {
	out := make([]map[string]any, 0, len(page.Components))
	for i, c := range page.Components {
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "description": c.Description,
			"status": c.Status, "position": i + 1,
			"group_id": c.ParentID, "showcase": true,
			// Beyond the shape everyone parses: the availability over the
			// window the page shows, as an exact integer.
			"uptime_ppm": c.UptimePPM,
		})
	}
	return out
}

func v2Incidents(incidents []model.Incident) []map[string]any {
	out := make([]map[string]any, 0, len(incidents))
	for _, inc := range incidents {
		updates := make([]map[string]any, 0, len(inc.Updates))
		for _, u := range inc.Updates {
			updates = append(updates, map[string]any{
				"id": u.ID, "status": u.Status, "body": u.Body,
				"created_at": rfc3339(u.CreatedAt),
				"author":     u.Author.Display,
				// The transaction that recorded this update, so a reader can
				// ask for it and see it was not edited afterwards.
				"txid": u.TxID,
			})
		}
		entry := map[string]any{
			"id": inc.ID, "name": inc.Title, "status": inc.Status,
			"impact": inc.Impact, "created_at": rfc3339(inc.OpenedAt),
			"updated_at":             rfc3339(inc.OpenedAt),
			"incident_updates":       updates,
			"opened_automatically":   inc.Auto,
			"affected_component_ids": inc.Components,
		}
		if inc.ResolvedAt > 0 {
			entry["resolved_at"] = rfc3339(inc.ResolvedAt)
		}
		out = append(out, entry)
	}
	return out
}

func v2Maintenances(windows []model.MaintenanceWindow) []map[string]any {
	out := make([]map[string]any, 0, len(windows))
	for _, w := range windows {
		out = append(out, map[string]any{
			"id": w.ID, "name": w.Title, "status": "scheduled",
			"scheduled_for":   rfc3339(w.StartsAt),
			"scheduled_until": rfc3339(w.EndsAt),
			"body":            w.Description,
			// Two fields no other status page carries, and the two a
			// dispute turns on: when the window was declared, and whether
			// that notice was enough to take it out of the agreed service
			// time.
			"declared_at":                rfc3339(w.DeclaredAt),
			"excluded_from_availability": w.Excluded,
		})
	}
	return out
}

func rfc3339(at int64) string {
	if at <= 0 {
		return ""
	}
	return time.Unix(at, 0).UTC().Format(time.RFC3339)
}

// -- feeds -----------------------------------------------------------------

type atomFeed struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	Title   string      `xml:"title"`
	Updated string      `xml:"updated"`
	ID      string      `xml:"id"`
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	Title   string `xml:"title"`
	ID      string `xml:"id"`
	Updated string `xml:"updated"`
	Summary string `xml:"summary"`
}

// historyAtom is the incident history as a feed, because plenty of
// people would rather subscribe than poll.
func (s *Server) historyAtom(w http.ResponseWriter, r *http.Request) {
	svc, err := s.resolveService(r)
	if err != nil || svc == nil {
		http.Error(w, "no public status page", http.StatusNotFound)
		return
	}
	now := time.Now().Unix()
	incidents, err := s.mon.Incidents(svc.ID, now-365*86400, now, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	feed := atomFeed{
		Title: svc.Name + " status history", ID: "urn:privasys:monitor:" + svc.Slug,
		Updated: time.Unix(now, 0).UTC().Format(time.RFC3339),
	}
	for _, inc := range incidents {
		summary := inc.Title
		if len(inc.Updates) > 0 {
			summary = inc.Updates[0].Body
		}
		feed.Entries = append(feed.Entries, atomEntry{
			Title: inc.Title, ID: "urn:privasys:incident:" + inc.ID,
			Updated: rfc3339(maxInt64(inc.OpenedAt, inc.ResolvedAt)),
			Summary: summary,
		})
	}
	w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(feed); err != nil {
		s.log.Error("could not write the feed", "error", err)
	}
}

func maxInt64(a, b int64) int64 {
	if b > a {
		return b
	}
	return a
}

// formatPPM is the percentage rendering the templates use.
func formatPPM(ppm int64) string {
	if ppm < 0 {
		return "no data"
	}
	return availability.FormatPPM(ppm)
}

var _ = fmt.Sprintf
