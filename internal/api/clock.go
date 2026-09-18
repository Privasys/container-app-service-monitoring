// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/clock"
	"github.com/Privasys/container-app-service-monitoring/internal/platform"
)

// The platform clock's surface.
//
// Two endpoints need no caller. The key, because the platform reads it
// to hand it to the runtimes and anyone may check it against the
// certificate extension. The incident endpoint, because the runtimes
// post to it without credentials: the receipt's signature is what they
// check, and the monitor never acts on a report without polling first.
// Everything else is the operator's, behind the usual roles.

func (s *Server) registerClock(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/clock/key", s.clockKey)
	mux.HandleFunc("POST /api/v1/clock/incidents", s.clockIncident)

	mux.HandleFunc("GET /api/v1/clock/fleet", s.wrap(s.clockFleet))
	mux.HandleFunc("GET /api/v1/clock/readings", s.wrap(s.clockReadings))
	mux.HandleFunc("GET /api/v1/clock/incidents", s.wrap(s.clockIncidents))
	mux.HandleFunc("GET /api/v1/clock/actions", s.wrap(s.clockActions))
	mux.HandleFunc("POST /api/v1/clock/enclaves/{id}/poll", s.wrap(s.clockPoll))
}

// clockOn reports whether this instance runs the platform clock. On any
// other instance every clock endpoint is absent.
func (s *Server) clockOn() bool { return s.Clock != nil && s.Clock.Enabled() }

var errClockOff = errors.New("no such endpoint: this instance does not run the platform clock")

// clockKey publishes the key the runtimes pin.
func (s *Server) clockKey(w http.ResponseWriter, _ *http.Request) {
	if !s.clockOn() {
		writeError(w, http.StatusNotFound, errClockOff.Error(), "")
		return
	}
	signer := s.Clock.Signer()
	sum := sha256.Sum256(signer.PublicKey())
	writePublicJSON(w, http.StatusOK, map[string]any{
		"alg":        "ed25519",
		"public_key": signer.EncodedPublicKey(),
		"key_id":     signer.KeyID(),
		// The certificate extension carries SHA-256 of the raw key, so a
		// reader can match this document against the attested leaf.
		"sha256":          hex.EncodeToString(sum[:]),
		"attestation_oid": platform.OIDClockKey,
		"floor_domain":    clock.FloorDomain,
		"receipt_domain":  clock.ReceiptDomain,
	})
}

// clockIncident receives a runtime's incident report and answers it
// with a signed receipt.
func (s *Server) clockIncident(w http.ResponseWriter, r *http.Request) {
	if !s.clockOn() {
		writeError(w, http.StatusNotFound, errClockOff.Error(), "")
		return
	}
	var report clock.IncidentReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "the report did not parse", err.Error())
		return
	}
	receipt, err := s.Clock.Incident(r.Context(), report, remoteHost(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func remoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) clockFleet(req *request) (any, error) {
	if !s.clockOn() {
		return nil, errClockOff
	}
	if !req.p.Can(auth.PermExplorer) {
		return nil, errors.New("this role may not read the fleet view")
	}
	return s.Clock.Fleet()
}

func (s *Server) clockReadings(req *request) (any, error) {
	if !s.clockOn() {
		return nil, errClockOff
	}
	if !req.p.Can(auth.PermExplorer) {
		return nil, errors.New("this role may not read the clock readings")
	}
	readings, err := req.mon.ClockReadings(req.r.URL.Query().Get("enclave"), intParam(req.r, "limit", 100))
	if err != nil {
		return nil, err
	}
	return map[string]any{"readings": readings}, nil
}

func (s *Server) clockIncidents(req *request) (any, error) {
	if !s.clockOn() {
		return nil, errClockOff
	}
	if !req.p.Can(auth.PermExplorer) {
		return nil, errors.New("this role may not read the clock incidents")
	}
	incidents, err := req.mon.ClockIncidents(intParam(req.r, "limit", 100))
	if err != nil {
		return nil, err
	}
	return map[string]any{"incidents": incidents}, nil
}

func (s *Server) clockActions(req *request) (any, error) {
	if !s.clockOn() {
		return nil, errClockOff
	}
	if !req.p.Can(auth.PermExplorer) {
		return nil, errors.New("this role may not read the clock actions")
	}
	actions, err := req.mon.ClockActions(intParam(req.r, "limit", 100))
	if err != nil {
		return nil, err
	}
	return map[string]any{"actions": actions}, nil
}

func (s *Server) clockPoll(req *request) (any, error) {
	if !s.clockOn() {
		return nil, errClockOff
	}
	if !req.p.Can(auth.PermRun) {
		return nil, errors.New("this role may not poll an enclave")
	}
	return s.Clock.PollNow(req.r.Context(), req.r.PathValue("id"))
}
