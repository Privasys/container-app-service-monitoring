// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package api is the monitor's HTTP surface: the public status page,
// the operator explorer, the REST API and the tool endpoints the
// platform's configure-then-freeze gate and MCP clients drive.
//
// Transport security is the enclave's. The platform gateway terminates
// a publicly trusted certificate so an ordinary browser reaches the
// status page, and re-establishes a verified RA-TLS connection inwards,
// so what serves the page is a build whose measurement was checked. A
// client that speaks RA-TLS directly verifies that itself. What is left
// to this package is who the caller is, what their role permits, and
// which surfaces need no caller at all.
//
// The status surface is deliberately anonymous. A status page behind a
// login is not a status page.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/clock"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/oncall"
	"github.com/Privasys/container-app-service-monitoring/internal/probe"
	"github.com/Privasys/container-app-service-monitoring/internal/tenancy"
)

// Lifecycle states, which the platform's freeze gate makes visible: the
// container serves its probe, its manifest and its configure endpoint
// until the deployer has configured it.
const (
	StateAwaitingConfiguration = "awaiting_configuration"
	StateReady                 = "ready"
	StateFailed                = "failed"
)

// Server is the HTTP surface.
type Server struct {
	log *slog.Logger

	mu      sync.RWMutex
	failure string

	mon       *core.Monitor
	verifier  auth.Verifier
	roles     *auth.Model
	scheduler *probe.Scheduler

	// Configure runs the configure tool. Returning nil is what lifts the
	// platform's freeze gate.
	Configure func(document []byte) (any, error)

	// Version is the build version reported at /version.
	Version string
	// Manifest is the app manifest served at /privasys.json and at
	// /.well-known/privasys-manifest.
	Manifest []byte
	// PackDir is where the service-model packs baked into the image live.
	PackDir string
	// Clock is the platform clock. It is present on every instance and
	// switched on only by a configure call that asks for it.
	Clock *clock.Service

	// Tenants holds one monitor per app, on the shared platform
	// instance. Nil on an instance that watches one service only.
	Tenants *tenancy.Host
	// HomeApp is this monitor's own app. Its account's directory is the
	// one the site's home pages show.
	HomeApp string
	// AppRoles is the role model app-scoped requests resolve against:
	// the portal's team roles for that app, and the platform admins.
	AppRoles *auth.Model
	// TenantsChanged runs after an app's monitor is created or removed,
	// so the process can republish the summary it attests to.
	TenantsChanged func()
	// FormAnswers verifies the answers people give to pages in their wallet.
	FormAnswers auth.Verifier
	// MailCert is the public half of the mail credential, when there is one.
	MailCert *MailCertificate
	// TicketNotice tells one person about a ticket, by the channels they chose.
	TicketNotice func(ctx context.Context, t *tenancy.Tenant, sub, subject, body string)
}

// NewServer builds the surface.
func NewServer(log *slog.Logger, mon *core.Monitor, verifier auth.Verifier,
	roles *auth.Model, scheduler *probe.Scheduler) *Server {
	return &Server{log: log, mon: mon, verifier: verifier, roles: roles, scheduler: scheduler}
}

// Fail records a configuration failure so an operator sees why the
// monitor is not watching anything.
func (s *Server) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = err.Error()
}

// State reports the lifecycle position.
func (s *Server) State() (string, string) {
	s.mu.RLock()
	failure := s.failure
	s.mu.RUnlock()
	switch {
	case failure != "":
		return StateFailed, failure
	case s.mon.Configured():
		return StateReady, ""
	default:
		return StateAwaitingConfiguration, ""
	}
}

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Always available: the probes, the manifest, the signing key and
	// the configure call itself.
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /readiness", s.readiness)
	mux.HandleFunc("GET /version", s.version)
	mux.HandleFunc("GET /privasys.json", s.manifest)
	mux.HandleFunc("GET /.well-known/privasys-manifest", s.manifest)
	mux.HandleFunc("GET /.well-known/privasys-monitor.json", s.wellKnown)
	mux.HandleFunc("POST /configure", s.configure)

	// The public status surface. No caller, no token: a status page
	// behind a login is not a status page.
	mux.HandleFunc("GET /api/v1/public/services", s.publicServices)
	mux.HandleFunc("GET /api/v1/public/status", s.publicStatus)
	mux.HandleFunc("GET /api/v1/public/status/{slug}", s.publicStatus)
	mux.HandleFunc("GET /api/v1/public/uptime/{slug}", s.publicUptime)
	mux.HandleFunc("GET /api/v1/public/incidents/{slug}", s.publicIncidents)

	// The same document in the shape existing status-page consumers
	// already parse, so a customer's dashboards and bots work unchanged.
	mux.HandleFunc("GET /api/v2/summary.json", s.v2Summary)
	mux.HandleFunc("GET /api/v2/status.json", s.v2Status)
	mux.HandleFunc("GET /api/v2/components.json", s.v2Components)
	mux.HandleFunc("GET /api/v2/incidents.json", s.v2Incidents)
	mux.HandleFunc("GET /api/v2/incidents/unresolved.json", s.v2Unresolved)
	mux.HandleFunc("GET /api/v2/scheduled-maintenances.json", s.v2Maintenance)
	mux.HandleFunc("GET /history.atom", s.historyAtom)

	// Evidence for the numbers on the page, so a reader can check them
	// without an account. The proofs are the product.
	mux.HandleFunc("GET /api/v1/public/evidence/bucket", s.publicBucketEvidence)
	mux.HandleFunc("GET /api/v1/public/checkpoints", s.publicCheckpoints)

	// The authenticated API. Every route is served twice: at its own
	// path for the instance's tenant, and under /api/v1/apps/{app}/ for
	// one app's monitor on the shared platform instance.
	authed := func(method, path string, h handler) {
		mux.HandleFunc(method+" "+path, s.wrap(h))
		mux.HandleFunc(method+" "+appPath(path), s.wrapApp(h))
	}
	mux.HandleFunc("GET /api/v1/apps", s.listApps)
	mux.HandleFunc("POST /api/v1/apps/{app}/enable", s.enableApp)
	mux.HandleFunc("POST /api/v1/apps/{app}/refresh-listing", s.refreshListing)
	mux.HandleFunc("DELETE /api/v1/apps/{app}", s.removeApp)

	authed("GET", "/api/v1/status", s.status)
	authed("GET", "/api/v1/me", s.me)
	authed("GET", "/api/v1/services", s.listServices)
	authed("POST", "/api/v1/services", s.upsertService)
	authed("GET", "/api/v1/services/{id}", s.getService)
	authed("GET", "/api/v1/services/{id}/components", s.listComponents)
	authed("POST", "/api/v1/components", s.upsertComponent)
	authed("GET", "/api/v1/monitors", s.listMonitors)
	authed("POST", "/api/v1/monitors", s.upsertMonitor)
	authed("GET", "/api/v1/monitors/{id}", s.getMonitor)
	authed("POST", "/api/v1/monitors/{id}/run", s.runMonitor)
	authed("POST", "/api/v1/monitors/{id}/enabled", s.setMonitorEnabled)
	authed("POST", "/api/v1/schedules", s.upsertSchedule)
	authed("POST", "/api/v1/objectives", s.upsertObjective)

	authed("GET", "/api/v1/samples", s.listSamples)
	authed("GET", "/api/v1/buckets", s.listBuckets)
	authed("GET", "/api/v1/captures", s.listCaptures)
	authed("GET", "/api/v1/screenshots/{digest}", s.getScreenshot)
	authed("POST", "/api/v1/monitors/{id}/baseline", s.approveBaseline)

	authed("GET", "/api/v1/incidents", s.listIncidents)
	authed("POST", "/api/v1/incidents", s.openIncident)
	authed("GET", "/api/v1/incidents/{id}", s.getIncident)
	authed("POST", "/api/v1/incidents/{id}/updates", s.updateIncident)

	authed("GET", "/api/v1/maintenance", s.listMaintenance)
	authed("POST", "/api/v1/maintenance", s.declareMaintenance)
	authed("POST", "/api/v1/maintenance/{id}/cancel", s.cancelMaintenance)

	authed("GET", "/api/v1/secrets", s.listSecrets)
	authed("POST", "/api/v1/secrets", s.putSecret)
	authed("DELETE", "/api/v1/secrets/{name}", s.destroySecret)

	authed("GET", "/api/v1/reports", s.listReports)
	authed("POST", "/api/v1/reports", s.generateReport)
	authed("GET", "/api/v1/reports/{id}", s.getReport)

	authed("GET", "/api/v1/log", s.listLog)
	authed("GET", "/api/v1/log/{txid}", s.getTransaction)
	authed("GET", "/api/v1/alerts", s.listAlerts)
	authed("GET", "/api/v1/events", s.listEvents)

	authed("GET", "/api/v1/checkpoints", s.listCheckpoints)
	authed("GET", "/api/v1/checkpoints/key", s.checkpointKey)
	authed("POST", "/api/v1/checkpoints", s.issueCheckpoint)
	authed("GET", "/api/v1/audit/lineage", s.lineage)
	authed("GET", "/api/v1/audit/roots", s.auditRoots)

	authed("GET", "/api/v1/proofs/buckets/{monitor}/{width}/{start}", s.bucketProof)
	authed("GET", "/api/v1/proofs/samples/{id}", s.sampleProof)

	authed("POST", "/api/v1/retention/prune", s.prune)

	// The manifest's tools. One surface, driven by the portal, the CLI
	// and agents alike.
	authed("POST", "/tools/status", s.toolStatus)
	authed("POST", "/tools/monitors", s.toolMonitors)
	authed("POST", "/tools/services", s.toolServices)
	authed("POST", "/tools/put_secret", s.putSecret)
	authed("POST", "/tools/upsert_monitor", s.upsertMonitor)
	authed("POST", "/tools/run_check", s.toolRunCheck)
	authed("POST", "/tools/schedule_maintenance", s.declareMaintenance)
	authed("POST", "/tools/incident_update", s.toolIncidentUpdate)
	authed("POST", "/tools/report", s.generateReport)
	authed("POST", "/tools/checkpoint", s.issueCheckpoint)
	authed("POST", "/tools/approve_baseline", s.approveBaseline)

	// The platform clock, absent unless this instance runs it.
	s.registerClock(mux)

	s.registerPublicApps(mux)
	s.registerOnCall(mux)
	s.registerTickets(mux)
	registerPages(mux, s)

	return logging(s.log, mux)
}

// -- request plumbing ------------------------------------------------------

type request struct {
	w     http.ResponseWriter
	r     *http.Request
	mon   *core.Monitor
	sched *probe.Scheduler
	p     *auth.Principal
	// oncall is the app's paging, on an app route.
	oncall *oncall.Dispatcher
}

type handler func(*request) (any, error)

// wrap authenticates the caller, resolves their role, and turns a
// handler's return value into a JSON response.
func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, failure := s.State()
		if state != StateReady && r.URL.Path != "/tools/status" {
			writeError(w, http.StatusServiceUnavailable,
				"the monitor is "+strings.ReplaceAll(state, "_", " "), failure)
			return
		}
		principal, err := s.authenticate(r, s.roles, s.mon.Config().Tenant)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not authenticated", err.Error())
			return
		}
		serve(w, h, &request{w: w, r: r, mon: s.mon, sched: s.scheduler, p: principal})
	}
}

// serve runs a handler and turns its return value into a response.
func serve(w http.ResponseWriter, h handler, req *request) {
	result, err := h(req)
	if err != nil {
		status, detail := classify(err)
		writeError(w, status, err.Error(), detail)
		return
	}
	if result == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) authenticate(r *http.Request, roles *auth.Model, tenant string) (*auth.Principal, error) {
	token, ok := bearerToken(r)
	if !ok {
		return nil, errors.New("a bearer token is required")
	}
	id, err := s.verifier.Verify(r.Context(), token)
	if err != nil {
		return nil, err
	}
	role := r.Header.Get("X-Monitoring-Role")
	if role == "" {
		role = r.URL.Query().Get("role")
	}
	return roles.Resolve(id, tenant, role)
}

// classify maps a core error onto a status code. The core returns plain
// errors; the distinctions a caller acts on are "you may not", "there
// is no such thing", and "that is not something this monitor can do".
func classify(err error) (int, string) {
	text := err.Error()
	switch {
	case strings.Contains(text, "may not"), strings.Contains(text, "not bound to that host"),
		strings.Contains(text, "owner"):
		return http.StatusForbidden, ""
	case strings.HasPrefix(text, "no "), strings.Contains(text, "no such"):
		return http.StatusNotFound, ""
	case strings.Contains(text, "already"):
		return http.StatusConflict, ""
	default:
		return http.StatusBadRequest, ""
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
}

// writePublicJSON is the status surface's writer. It allows a short
// cache and cross-origin reads, because a status page exists to be
// embedded in other people's dashboards.
func writePublicJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=30")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
}

func writeError(w http.ResponseWriter, status int, message, detail string) {
	body := map[string]any{"error": message}
	if detail != "" {
		body["detail"] = detail
	}
	writeJSON(w, status, body)
}

func decode(r *http.Request, into any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("request body: %w", err)
	}
	return nil
}

func intParam(r *http.Request, name string, fallback int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func int64Param(r *http.Request, name string) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get(name), 10, 64)
	return n
}

func boolParam(r *http.Request, name string) bool {
	switch strings.ToLower(r.URL.Query().Get(name)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// logging records one line per request. Bodies are never logged: a
// request body here may carry a credential.
func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if (r.URL.Path == "/health" || r.URL.Path == "/readiness") && rec.status == http.StatusOK {
			return
		}
		log.Info("request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(started).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// bearerToken finds the caller's platform token. A direct RA-TLS call
// carries it as "Authorization: Bearer". A call over the platform's sealed
// session cannot: there the Authorization header names the session
// ("PrivasysSession <id>"), and the client sends its token as X-App-Auth,
// which the runtime passes through to the app inside the sealed channel.
func bearerToken(r *http.Request) (string, bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer "), true
	}
	if t := strings.TrimSpace(r.Header.Get("X-App-Auth")); t != "" {
		return strings.TrimPrefix(t, "Bearer "), true
	}
	return "", false
}
