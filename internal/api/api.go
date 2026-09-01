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
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/probe"
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

	// The authenticated API.
	mux.HandleFunc("GET /api/v1/status", s.wrap(s.status))
	mux.HandleFunc("GET /api/v1/me", s.wrap(s.me))
	mux.HandleFunc("GET /api/v1/services", s.wrap(s.listServices))
	mux.HandleFunc("POST /api/v1/services", s.wrap(s.upsertService))
	mux.HandleFunc("GET /api/v1/services/{id}", s.wrap(s.getService))
	mux.HandleFunc("GET /api/v1/services/{id}/components", s.wrap(s.listComponents))
	mux.HandleFunc("POST /api/v1/components", s.wrap(s.upsertComponent))
	mux.HandleFunc("GET /api/v1/monitors", s.wrap(s.listMonitors))
	mux.HandleFunc("POST /api/v1/monitors", s.wrap(s.upsertMonitor))
	mux.HandleFunc("GET /api/v1/monitors/{id}", s.wrap(s.getMonitor))
	mux.HandleFunc("POST /api/v1/monitors/{id}/run", s.wrap(s.runMonitor))
	mux.HandleFunc("POST /api/v1/monitors/{id}/enabled", s.wrap(s.setMonitorEnabled))
	mux.HandleFunc("POST /api/v1/schedules", s.wrap(s.upsertSchedule))
	mux.HandleFunc("POST /api/v1/objectives", s.wrap(s.upsertObjective))

	mux.HandleFunc("GET /api/v1/samples", s.wrap(s.listSamples))
	mux.HandleFunc("GET /api/v1/buckets", s.wrap(s.listBuckets))
	mux.HandleFunc("GET /api/v1/captures", s.wrap(s.listCaptures))
	mux.HandleFunc("GET /api/v1/screenshots/{digest}", s.wrap(s.getScreenshot))
	mux.HandleFunc("POST /api/v1/monitors/{id}/baseline", s.wrap(s.approveBaseline))

	mux.HandleFunc("GET /api/v1/incidents", s.wrap(s.listIncidents))
	mux.HandleFunc("POST /api/v1/incidents", s.wrap(s.openIncident))
	mux.HandleFunc("GET /api/v1/incidents/{id}", s.wrap(s.getIncident))
	mux.HandleFunc("POST /api/v1/incidents/{id}/updates", s.wrap(s.updateIncident))

	mux.HandleFunc("GET /api/v1/maintenance", s.wrap(s.listMaintenance))
	mux.HandleFunc("POST /api/v1/maintenance", s.wrap(s.declareMaintenance))
	mux.HandleFunc("POST /api/v1/maintenance/{id}/cancel", s.wrap(s.cancelMaintenance))

	mux.HandleFunc("GET /api/v1/secrets", s.wrap(s.listSecrets))
	mux.HandleFunc("POST /api/v1/secrets", s.wrap(s.putSecret))
	mux.HandleFunc("DELETE /api/v1/secrets/{name}", s.wrap(s.destroySecret))

	mux.HandleFunc("GET /api/v1/reports", s.wrap(s.listReports))
	mux.HandleFunc("POST /api/v1/reports", s.wrap(s.generateReport))
	mux.HandleFunc("GET /api/v1/reports/{id}", s.wrap(s.getReport))

	mux.HandleFunc("GET /api/v1/log", s.wrap(s.listLog))
	mux.HandleFunc("GET /api/v1/log/{txid}", s.wrap(s.getTransaction))
	mux.HandleFunc("GET /api/v1/alerts", s.wrap(s.listAlerts))
	mux.HandleFunc("GET /api/v1/events", s.wrap(s.listEvents))

	mux.HandleFunc("GET /api/v1/checkpoints", s.wrap(s.listCheckpoints))
	mux.HandleFunc("GET /api/v1/checkpoints/key", s.wrap(s.checkpointKey))
	mux.HandleFunc("POST /api/v1/checkpoints", s.wrap(s.issueCheckpoint))
	mux.HandleFunc("GET /api/v1/audit/lineage", s.wrap(s.lineage))
	mux.HandleFunc("GET /api/v1/audit/roots", s.wrap(s.auditRoots))

	mux.HandleFunc("GET /api/v1/proofs/buckets/{monitor}/{width}/{start}", s.wrap(s.bucketProof))
	mux.HandleFunc("GET /api/v1/proofs/samples/{id}", s.wrap(s.sampleProof))

	mux.HandleFunc("POST /api/v1/retention/prune", s.wrap(s.prune))

	// The manifest's tools. One surface, driven by the portal, the CLI
	// and agents alike.
	mux.HandleFunc("POST /tools/status", s.wrap(s.toolStatus))
	mux.HandleFunc("POST /tools/monitors", s.wrap(s.toolMonitors))
	mux.HandleFunc("POST /tools/services", s.wrap(s.toolServices))
	mux.HandleFunc("POST /tools/put_secret", s.wrap(s.putSecret))
	mux.HandleFunc("POST /tools/upsert_monitor", s.wrap(s.upsertMonitor))
	mux.HandleFunc("POST /tools/run_check", s.wrap(s.toolRunCheck))
	mux.HandleFunc("POST /tools/schedule_maintenance", s.wrap(s.declareMaintenance))
	mux.HandleFunc("POST /tools/incident_update", s.wrap(s.toolIncidentUpdate))
	mux.HandleFunc("POST /tools/report", s.wrap(s.generateReport))
	mux.HandleFunc("POST /tools/checkpoint", s.wrap(s.issueCheckpoint))
	mux.HandleFunc("POST /tools/approve_baseline", s.wrap(s.approveBaseline))

	registerPages(mux, s)

	return logging(s.log, mux)
}

// -- request plumbing ------------------------------------------------------

type request struct {
	w   http.ResponseWriter
	r   *http.Request
	mon *core.Monitor
	p   *auth.Principal
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
		principal, err := s.authenticate(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not authenticated", err.Error())
			return
		}
		result, err := h(&request{w: w, r: r, mon: s.mon, p: principal})
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
}

func (s *Server) authenticate(r *http.Request) (*auth.Principal, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, errors.New("a bearer token is required")
	}
	id, err := s.verifier.Verify(r.Context(), strings.TrimPrefix(header, "Bearer "))
	if err != nil {
		return nil, err
	}
	role := r.Header.Get("X-Monitoring-Role")
	if role == "" {
		role = r.URL.Query().Get("role")
	}
	return s.roles.Resolve(id, s.mon.Config().Tenant, role)
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
