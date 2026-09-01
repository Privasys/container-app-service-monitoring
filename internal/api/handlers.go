// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/Privasys/container-app-service-monitoring/internal/availability"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// -- always available ------------------------------------------------------

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	state, failure := s.State()
	body := map[string]any{
		"status": "ok", "state": state, "version": s.Version,
		"configured": s.mon.Configured(),
	}
	if failure != "" {
		body["failure"] = failure
	}
	writeJSON(w, http.StatusOK, body)
}

// readiness is the platform's liveness gate. It answers 503 until the
// monitor has been configured, which is what makes the portal show
// progress instead of a bare "starting".
func (s *Server) readiness(w http.ResponseWriter, _ *http.Request) {
	state, failure := s.State()
	if state != StateReady {
		writeError(w, http.StatusServiceUnavailable, "awaiting configuration", failure)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": state})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	opts := s.mon.Options()
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.Version, "name": opts.Name, "vantage": opts.Vantage,
		"image_digest": opts.ImageDigest,
	})
}

func (s *Server) manifest(w http.ResponseWriter, _ *http.Request) {
	if len(s.Manifest) == 0 {
		writeError(w, http.StatusNotFound, "no manifest is baked into this image", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.Manifest)
}

// wellKnown publishes what a receiver needs to check anything this
// monitor signed: the key, the measurement it is bound to, and the
// authenticated state it is serving.
func (s *Server) wellKnown(w http.ResponseWriter, _ *http.Request) {
	keyID, publicKey := s.mon.VerificationKey()
	opts := s.mon.Options()
	body := map[string]any{
		"instance": opts.Name, "vantage": opts.Vantage,
		"image_digest": opts.ImageDigest,
		"signing_key": map[string]any{
			"key_id": keyID, "alg": "ed25519", "public_key": publicKey,
		},
		"attestation_oids": map[string]string{
			"image_digest": "1.3.6.1.4.1.65230.3.2",
			"signing_key":  "1.3.6.1.4.1.65230.3.5.1",
			"ledger_root":  "1.3.6.1.4.1.65230.3.5.2",
			"app_id":       "1.3.6.1.4.1.65230.3.6",
		},
		"webhook_schema": "privasys.monitor.alert/v1",
	}
	if cp, err := s.mon.LatestCheckpoint(); err == nil && cp != nil {
		body["latest_checkpoint"] = cp
	}
	writePublicJSON(w, http.StatusOK, body)
}

// configure is the platform's configure-then-freeze entry point. The
// runtime authorises the caller to the app's owners and admins before
// the request arrives here, and lifts the gate on the first success.
func (s *Server) configure(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, 4<<20)
	defer body.Close()
	document := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := body.Read(buf)
		document = append(document, buf[:n]...)
		if err != nil {
			break
		}
	}
	result, err := s.Configure(document)
	if err != nil {
		s.Fail(err)
		writeError(w, http.StatusBadRequest, "configuration refused", err.Error())
		return
	}
	s.mu.Lock()
	s.failure = ""
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, result)
}

// -- instance --------------------------------------------------------------

func (s *Server) status(req *request) (any, error) {
	return s.statusDocument(req)
}

func (s *Server) toolStatus(req *request) (any, error) {
	return s.statusDocument(req)
}

func (s *Server) statusDocument(req *request) (any, error) {
	state, failure := s.State()
	opts := req.mon.Options()
	body := map[string]any{
		"state": state, "instance": opts.Name, "vantage": opts.Vantage,
		"version": s.Version, "image_digest": opts.ImageDigest,
		"tenant": req.mon.Config().Tenant,
	}
	if failure != "" {
		body["failure"] = failure
	}
	if state != StateReady {
		return body, nil
	}
	lineage, err := req.mon.Lineage(req.p)
	if err == nil && lineage != nil {
		body["root"] = lineage.Root
		body["ledger_version"] = lineage.Version
		body["lineage_enabled"] = lineage.Enabled
	}
	services, err := req.mon.Services()
	if err != nil {
		return nil, err
	}
	summaries := make([]map[string]any, 0, len(services))
	for _, svc := range services {
		page, err := req.mon.Status(svc.ID, req.mon.Now())
		if err != nil {
			return nil, err
		}
		if page == nil {
			continue
		}
		summaries = append(summaries, map[string]any{
			"id": svc.ID, "name": svc.Name, "slug": svc.Slug,
			"indicator": page.Indicator, "headline": page.Headline,
			"components": len(page.Components), "open_incidents": len(page.Incidents),
		})
	}
	body["services"] = summaries
	if cp, err := req.mon.LatestCheckpoint(); err == nil && cp != nil {
		body["last_checkpoint"] = cp.Checkpoint
	}
	body["egress_allowlist"] = s.egressEntries()
	return body, nil
}

func (s *Server) egressEntries() []string {
	// The allowlist is a fact about what this instance may contact, and
	// an operator should be able to read it without guessing.
	return s.mon.Engine().Egress.Entries()
}

func (s *Server) me(req *request) (any, error) {
	return map[string]any{
		"sub": req.p.Sub, "display": req.p.Display, "roles": req.p.Roles,
		"acting": req.p.Acting, "permissions": req.p.Permissions(),
	}, nil
}

// -- service model ---------------------------------------------------------

func (s *Server) listServices(req *request) (any, error) {
	services, err := req.mon.Services()
	if err != nil {
		return nil, err
	}
	return map[string]any{"services": services}, nil
}

func (s *Server) getService(req *request) (any, error) {
	svc, err := req.mon.Service(req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if svc == nil {
		return nil, fmt.Errorf("no service %s", req.r.PathValue("id"))
	}
	components, err := req.mon.Components(svc.ID)
	if err != nil {
		return nil, err
	}
	objectives, err := req.mon.Objectives(svc.ID)
	if err != nil {
		return nil, err
	}
	schedule, err := req.mon.Schedule(svc.ScheduleID)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"service": svc, "components": components,
		"objectives": objectives, "schedule": schedule,
	}, nil
}

type serviceRequest struct {
	model.Service
	Message string `json:"message"`
}

func (s *Server) upsertService(req *request) (any, error) {
	var body serviceRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	svc, tr, err := req.mon.UpsertService(req.p, body.Service, body.Message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"service": svc, "txid": tr.TxID, "version": tr.VersionAfter}, nil
}

func (s *Server) listComponents(req *request) (any, error) {
	components, err := req.mon.Components(req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"components": components}, nil
}

type componentRequest struct {
	model.Component
	Message string `json:"message"`
}

func (s *Server) upsertComponent(req *request) (any, error) {
	var body componentRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	component, tr, err := req.mon.UpsertComponent(req.p, body.Component, body.Message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"component": component, "txid": tr.TxID}, nil
}

func (s *Server) listMonitors(req *request) (any, error) {
	monitors, err := req.mon.Monitors(req.r.URL.Query().Get("service_id"))
	if err != nil {
		return nil, err
	}
	states, err := req.mon.States()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(monitors))
	for _, mon := range monitors {
		entry := map[string]any{"monitor": mon}
		if st, ok := states[mon.ID]; ok {
			entry["state"] = st
		}
		out = append(out, entry)
	}
	return map[string]any{"monitors": out}, nil
}

func (s *Server) toolMonitors(req *request) (any, error) { return s.listMonitors(req) }

func (s *Server) toolServices(req *request) (any, error) { return s.listServices(req) }

func (s *Server) getMonitor(req *request) (any, error) {
	mon, err := req.mon.Monitor(req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if mon == nil {
		return nil, fmt.Errorf("no monitor %s", req.r.PathValue("id"))
	}
	return map[string]any{"monitor": mon}, nil
}

type monitorRequest struct {
	model.Monitor
	Message string `json:"message"`
}

func (s *Server) upsertMonitor(req *request) (any, error) {
	var body monitorRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	mon, tr, err := req.mon.UpsertMonitor(req.p, body.Monitor, body.Message)
	if err != nil {
		return nil, err
	}
	s.scheduler.Reload()
	return map[string]any{"monitor": mon, "txid": tr.TxID, "version": mon.Version}, nil
}

func (s *Server) setMonitorEnabled(req *request) (any, error) {
	var body struct {
		Enabled bool   `json:"enabled"`
		Message string `json:"message"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	tr, err := req.mon.SetMonitorEnabled(req.p, req.r.PathValue("id"), body.Enabled, body.Message)
	if err != nil {
		return nil, err
	}
	s.scheduler.Reload()
	return map[string]any{"txid": tr.TxID, "enabled": body.Enabled}, nil
}

// runMonitor executes a journey out of band. The reading is recorded
// and marked manual, so an operator pressing the button during an
// incident cannot change what the month's report says.
func (s *Server) runMonitor(req *request) (any, error) {
	if !req.p.Can("run") {
		return nil, fmt.Errorf("%s may not run a monitor", req.p.Acting)
	}
	sample, err := s.scheduler.RunOnce(req.r.Context(), req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"sample": sample}, nil
}

func (s *Server) toolRunCheck(req *request) (any, error) {
	var body struct {
		Monitor string `json:"monitor"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	if !req.p.Can("run") {
		return nil, fmt.Errorf("%s may not run a monitor", req.p.Acting)
	}
	sample, err := s.scheduler.RunOnce(req.r.Context(), body.Monitor)
	if err != nil {
		return nil, err
	}
	return map[string]any{"sample": sample}, nil
}

type scheduleRequest struct {
	model.Schedule
	Message string `json:"message"`
}

func (s *Server) upsertSchedule(req *request) (any, error) {
	var body scheduleRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	schedule, tr, err := req.mon.UpsertSchedule(req.p, body.Schedule, body.Message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"schedule": schedule, "txid": tr.TxID}, nil
}

type objectiveRequest struct {
	model.Objective
	Message string `json:"message"`
}

func (s *Server) upsertObjective(req *request) (any, error) {
	var body objectiveRequest
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	objective, tr, err := req.mon.UpsertObjective(req.p, body.Objective, body.Message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"objective": objective, "txid": tr.TxID}, nil
}

// -- readings --------------------------------------------------------------

func (s *Server) listSamples(req *request) (any, error) {
	samples, err := req.mon.Samples(req.p,
		req.r.URL.Query().Get("monitor_id"),
		int64Param(req.r, "from"), int64Param(req.r, "to"),
		intParam(req.r, "limit", 100))
	if err != nil {
		return nil, err
	}
	return map[string]any{"samples": samples}, nil
}

func (s *Server) listBuckets(req *request) (any, error) {
	width := int64Param(req.r, "width")
	if width == 0 {
		width = core.WidthHour
	}
	buckets, err := req.mon.Buckets(req.r.URL.Query().Get("service_id"), width,
		int64Param(req.r, "from"), int64Param(req.r, "to"))
	if err != nil {
		return nil, err
	}
	return map[string]any{"buckets": buckets, "width": width}, nil
}

// -- incidents -------------------------------------------------------------

func (s *Server) listIncidents(req *request) (any, error) {
	incidents, err := req.mon.Incidents(req.r.URL.Query().Get("service_id"),
		int64Param(req.r, "from"), int64Param(req.r, "to"), intParam(req.r, "limit", 50))
	if err != nil {
		return nil, err
	}
	return map[string]any{"incidents": incidents}, nil
}

func (s *Server) getIncident(req *request) (any, error) {
	inc, err := req.mon.Incident(req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if inc == nil {
		return nil, fmt.Errorf("no incident %s", req.r.PathValue("id"))
	}
	return map[string]any{"incident": inc}, nil
}

func (s *Server) openIncident(req *request) (any, error) {
	var body struct {
		model.Incident
		Body    string `json:"body"`
		Message string `json:"message"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	inc, tr, err := req.mon.OpenIncident(req.p, body.Incident, body.Body, body.Message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"incident": inc, "txid": tr.TxID}, nil
}

func (s *Server) updateIncident(req *request) (any, error) {
	var body struct {
		Status  string `json:"status"`
		Body    string `json:"body"`
		Message string `json:"message"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	update, tr, err := req.mon.UpdateIncident(req.p, req.r.PathValue("id"),
		body.Status, body.Body, body.Message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"update": update, "txid": tr.TxID}, nil
}

func (s *Server) toolIncidentUpdate(req *request) (any, error) {
	var body struct {
		Incident string `json:"incident"`
		Status   string `json:"status"`
		Body     string `json:"body"`
		Message  string `json:"message"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	update, tr, err := req.mon.UpdateIncident(req.p, body.Incident, body.Status, body.Body, body.Message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"update": update, "txid": tr.TxID}, nil
}

// -- maintenance -----------------------------------------------------------

func (s *Server) listMaintenance(req *request) (any, error) {
	from := int64Param(req.r, "from")
	to := int64Param(req.r, "to")
	if to == 0 {
		to = req.mon.Now() + 90*86400
	}
	windows, err := req.mon.MaintenanceBetween(req.r.URL.Query().Get("service_id"), from, to)
	if err != nil {
		return nil, err
	}
	return map[string]any{"maintenance": windows}, nil
}

func (s *Server) declareMaintenance(req *request) (any, error) {
	var body struct {
		model.MaintenanceWindow
		Message string `json:"message"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	window, tr, err := req.mon.DeclareMaintenance(req.p, body.MaintenanceWindow, body.Message)
	if err != nil {
		return nil, err
	}
	// The answer says plainly whether the window will leave the agreed
	// service time, and why. An operator finding that out from next
	// month's report is finding out too late.
	return map[string]any{
		"maintenance": window, "txid": tr.TxID,
		"excluded":       window.Excluded,
		"lead_time":      window.LeadTime,
		"lead_time_text": leadTimeText(window),
	}, nil
}

func leadTimeText(w *model.MaintenanceWindow) string {
	switch {
	case w.LeadTime < 0:
		return fmt.Sprintf("declared %s after the window began", humanDuration(-w.LeadTime))
	case w.Excluded:
		return fmt.Sprintf("declared %s ahead, so it leaves the agreed service time",
			humanDuration(w.LeadTime))
	default:
		return fmt.Sprintf("declared %s ahead, which is not enough notice to exclude it",
			humanDuration(w.LeadTime))
	}
}

func humanDuration(seconds int64) string {
	switch {
	case seconds >= 86400:
		return fmt.Sprintf("%d days", seconds/86400)
	case seconds >= 3600:
		return fmt.Sprintf("%d hours", seconds/3600)
	case seconds >= 60:
		return fmt.Sprintf("%d minutes", seconds/60)
	default:
		return fmt.Sprintf("%d seconds", seconds)
	}
}

func (s *Server) cancelMaintenance(req *request) (any, error) {
	var body struct {
		Message string `json:"message"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	tr, err := req.mon.CancelMaintenance(req.p, req.r.PathValue("id"), body.Message)
	if err != nil {
		return nil, err
	}
	return map[string]any{"txid": tr.TxID}, nil
}

// -- credentials -----------------------------------------------------------

func (s *Server) listSecrets(req *request) (any, error) {
	secrets, err := req.mon.Secrets()
	if err != nil {
		return nil, err
	}
	return map[string]any{"secrets": secrets}, nil
}

func (s *Server) putSecret(req *request) (any, error) {
	var body struct {
		Name        string   `json:"name"`
		Value       string   `json:"value"`
		Hosts       []string `json:"hosts"`
		Description string   `json:"description"`
		Message     string   `json:"message"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	if body.Message == "" {
		body.Message = "Store the " + body.Name + " credential"
	}
	meta, tr, err := req.mon.PutSecret(req.p, body.Name, body.Value, body.Hosts,
		body.Description, body.Message)
	if err != nil {
		return nil, err
	}
	// The value is never echoed, not even to the caller who just supplied
	// it. What comes back is the record: the binding and the fingerprint.
	return map[string]any{"secret": meta, "txid": tr.TxID}, nil
}

func (s *Server) destroySecret(req *request) (any, error) {
	tr, err := req.mon.DestroySecret(req.p, req.r.PathValue("name"),
		"Destroy the "+req.r.PathValue("name")+" credential")
	if err != nil {
		return nil, err
	}
	return map[string]any{"txid": tr.TxID, "destroyed": true}, nil
}

// -- reports ---------------------------------------------------------------

func (s *Server) listReports(req *request) (any, error) {
	reports, err := req.mon.Reports(req.p, req.r.URL.Query().Get("service_id"),
		intParam(req.r, "limit", 25))
	if err != nil {
		return nil, err
	}
	return map[string]any{"reports": reports}, nil
}

func (s *Server) generateReport(req *request) (any, error) {
	var body struct {
		Service       string `json:"service"`
		ServiceID     string `json:"service_id"`
		Window        string `json:"window"`
		Previous      bool   `json:"previous"`
		From          int64  `json:"from"`
		To            int64  `json:"to"`
		IncludeProofs bool   `json:"include_proofs"`
	}
	if err := decode(req.r, &body); err != nil {
		return nil, err
	}
	serviceID := body.ServiceID
	if serviceID == "" {
		serviceID = body.Service
	}
	if serviceID == "" {
		services, err := req.mon.Services()
		if err != nil {
			return nil, err
		}
		if len(services) == 1 {
			serviceID = services[0].ID
		}
	}
	report, err := req.mon.GenerateReport(req.p, core.ReportRequest{
		ServiceID: serviceID, Window: body.Window, Previous: body.Previous,
		From: body.From, To: body.To, IncludeProofs: body.IncludeProofs,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"report":  report,
		"summary": reportSummary(report),
	}, nil
}

// reportSummary is the human sentence a portal or an agent shows
// without reading the whole document.
func reportSummary(r *model.Report) string {
	line := fmt.Sprintf("%s was %s available over %s, with %s of downtime across %d outages",
		r.ServiceName, availability.FormatPPM(r.Results.AvailabilityPPM), r.Period.Label,
		humanDuration(r.Downtime.Seconds), r.Downtime.Outages)
	for _, o := range r.Objectives {
		switch o.Result {
		case model.ObjectiveBreached:
			line += fmt.Sprintf("; %s was breached (target %s)", o.Name,
				availability.FormatPPM(o.TargetPPM))
		case model.ObjectiveIndeterminate:
			line += fmt.Sprintf("; %s is indeterminate because %s", o.Name, o.Reason)
		}
	}
	return line
}

func (s *Server) getReport(req *request) (any, error) {
	report, err := req.mon.Report(req.p, req.r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if report == nil {
		return nil, fmt.Errorf("no report %s", req.r.PathValue("id"))
	}
	return map[string]any{"report": report}, nil
}

// -- the record ------------------------------------------------------------

func (s *Server) listLog(req *request) (any, error) {
	entries, err := req.mon.Log(req.p, req.r.URL.Query().Get("kind"), intParam(req.r, "limit", 100))
	if err != nil {
		return nil, err
	}
	return map[string]any{"log": entries}, nil
}

func (s *Server) getTransaction(req *request) (any, error) {
	entry, err := req.mon.Transaction(req.p, req.r.PathValue("txid"))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("no transaction %s", req.r.PathValue("txid"))
	}
	return map[string]any{"transaction": entry}, nil
}

func (s *Server) listAlerts(req *request) (any, error) {
	alerts, err := req.mon.Alerts(req.p, req.r.URL.Query().Get("service_id"),
		intParam(req.r, "limit", 50))
	if err != nil {
		return nil, err
	}
	return map[string]any{"alerts": alerts}, nil
}

func (s *Server) listEvents(req *request) (any, error) {
	events, err := req.mon.RuntimeEvents(intParam(req.r, "limit", 50))
	if err != nil {
		return nil, err
	}
	return map[string]any{"events": events}, nil
}

// -- anchors and proofs ----------------------------------------------------

func (s *Server) listCheckpoints(req *request) (any, error) {
	checkpoints, err := req.mon.Checkpoints(req.p, intParam(req.r, "limit", 100))
	if err != nil {
		return nil, err
	}
	return map[string]any{"checkpoints": checkpoints}, nil
}

func (s *Server) checkpointKey(req *request) (any, error) {
	keyID, publicKey := req.mon.VerificationKey()
	return map[string]any{"key_id": keyID, "alg": "ed25519", "public_key": publicKey}, nil
}

func (s *Server) issueCheckpoint(req *request) (any, error) {
	var body struct {
		Reason string `json:"reason"`
	}
	_ = decode(req.r, &body)
	if !req.p.Can("checkpoints") {
		return nil, fmt.Errorf("%s may not issue checkpoints", req.p.Acting)
	}
	reason := body.Reason
	if reason == "" {
		reason = core.ReasonManual
	}
	cp, err := req.mon.IssueCheckpoint(reason)
	if err != nil {
		return nil, err
	}
	return map[string]any{"checkpoint": cp}, nil
}

func (s *Server) lineage(req *request) (any, error) {
	return req.mon.Lineage(req.p)
}

func (s *Server) auditRoots(req *request) (any, error) {
	from := uint64(int64Param(req.r, "from"))
	to := uint64(int64Param(req.r, "to"))
	roots, err := req.mon.RootsBetween(req.p, from, to)
	if err != nil {
		return nil, err
	}
	return map[string]any{"roots": roots}, nil
}

func (s *Server) bucketProof(req *request) (any, error) {
	width, err := strconv.ParseInt(req.r.PathValue("width"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("the interval width is not a number")
	}
	start, err := strconv.ParseInt(req.r.PathValue("start"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("the interval start is not a number")
	}
	return req.mon.BucketEvidence(req.p, req.r.PathValue("monitor"), width, start)
}

func (s *Server) sampleProof(req *request) (any, error) {
	return req.mon.SampleEvidence(req.p, req.r.PathValue("id"))
}

func (s *Server) prune(req *request) (any, error) {
	var body struct {
		Before int64 `json:"before"`
	}
	_ = decode(req.r, &body)
	return req.mon.PruneSamples(req.p, body.Before)
}
