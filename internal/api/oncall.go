// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/oncall"
	"github.com/Privasys/container-app-service-monitoring/internal/tenancy"
)

// MailCertificate is the public half of the monitor's mail credential.
type MailCertificate struct {
	Certificate string `json:"certificate"`
	Thumbprint  string `json:"thumbprint"`
	NotAfter    string `json:"not_after"`
}

// registerOnCall adds the on-call routes, which exist for apps only.
func (s *Server) registerOnCall(mux *http.ServeMux) {
	const base = "/api/v1/apps/{app}/oncall"
	mux.HandleFunc("GET "+base, s.wrapApp(s.onCallOverview))
	mux.HandleFunc("POST "+base+"/plan", s.wrapApp(s.onCallSetPlan))
	mux.HandleFunc("POST "+base+"/me", s.wrapApp(s.onCallSetMine))
	mux.HandleFunc("DELETE "+base+"/me", s.wrapApp(s.onCallForgetMine))
	mux.HandleFunc("POST "+base+"/test", s.wrapApp(s.onCallTest))
	mux.HandleFunc("POST "+base+"/pages/{page}/take", s.wrapApp(s.onCallTake))
	// The wallet's answer carries its own proof of who answered.
	mux.HandleFunc("POST "+base+"/answer", s.onCallAnswer)
	mux.HandleFunc("GET /api/v1/public/mail-certificate", s.mailCertificate)
	mux.HandleFunc("GET /.well-known/privasys/app-form", s.appFormOpen)
}

func dispatcher(req *request) (*oncall.Dispatcher, error) {
	if req.oncall == nil {
		return nil, errors.New("no on-call service on this monitor")
	}
	return req.oncall, nil
}

func (s *Server) onCallOverview(req *request) (any, error) {
	d, err := dispatcher(req)
	if err != nil {
		return nil, err
	}
	plan := d.Store.Plan()
	body := map[string]any{
		"plan": plan, "on_call": plan.OnCall(time.Now()),
		"me": d.Store.Preference(req.p.Sub), "sub": req.p.Sub,
		"can_manage": req.p.Can(auth.PermAdmin),
		"pages":      d.Store.Pages(20),
	}
	// The rota is still useful when the team list cannot be read.
	if team, err := d.Team(req.r.Context()); err == nil {
		body["team"] = team
	} else {
		body["team_error"] = "the team could not be read just now"
	}
	return body, nil
}

func (s *Server) onCallSetPlan(req *request) (any, error) {
	if !req.p.Can(auth.PermAdmin) {
		return nil, fmt.Errorf("%s may not change the on-call plan", req.p.Acting)
	}
	d, err := dispatcher(req)
	if err != nil {
		return nil, err
	}
	var plan oncall.Plan
	if err := decode(req.r, &plan); err != nil {
		return nil, err
	}
	if err := d.Store.SetPlan(plan); err != nil {
		return nil, err
	}
	return map[string]any{"plan": plan}, nil
}

func (s *Server) onCallSetMine(req *request) (any, error) {
	d, err := dispatcher(req)
	if err != nil {
		return nil, err
	}
	var pref oncall.Preference
	if err := decode(req.r, &pref); err != nil {
		return nil, err
	}
	// Each person sets their own, and only their own.
	pref.Sub = req.p.Sub
	saved, err := d.Store.SetPreference(pref, time.Now())
	if err != nil {
		return nil, err
	}
	return map[string]any{"me": saved}, nil
}

func (s *Server) onCallForgetMine(req *request) (any, error) {
	d, err := dispatcher(req)
	if err != nil {
		return nil, err
	}
	if err := d.Store.ForgetPreference(req.p.Sub); err != nil {
		return nil, err
	}
	return map[string]any{"me": d.Store.Preference(req.p.Sub)}, nil
}

func (s *Server) onCallTest(req *request) (any, error) {
	d, err := dispatcher(req)
	if err != nil {
		return nil, err
	}
	return map[string]any{"results": d.Test(req.r.Context(), req.p.Sub)}, nil
}

func (s *Server) onCallTake(req *request) (any, error) {
	if !req.p.Can(auth.PermRespond) {
		return nil, fmt.Errorf("%s may not take an incident", req.p.Acting)
	}
	d, err := dispatcher(req)
	if err != nil {
		return nil, err
	}
	if err := d.Take(req.r.PathValue("page"), req.p.Sub); err != nil {
		return nil, err
	}
	return map[string]any{"taken": true}, nil
}

// onCallAnswer takes the wallet's answer to a page. The answer is a token
// the identity provider signed once the person approved it with their
// passkey: it names who answered, the form and the action, so no session
// is needed here and nothing in the request is taken on trust.
func (s *Server) onCallAnswer(w http.ResponseWriter, r *http.Request) {
	if s.Tenants == nil || s.FormAnswers == nil {
		writeError(w, http.StatusNotFound, "this monitor does not take answers", "")
		return
	}
	id, err := tenancy.Canonical(r.PathValue("app"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "not an app id", "")
		return
	}
	var body struct {
		FormID string `json:"form_id"`
		Action string `json:"action"`
		Answer string `json:"answer"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "the answer could not be read", "")
		return
	}
	if !isFormAnswer(body.Answer) {
		writeError(w, http.StatusUnauthorized, "not a form answer", "")
		return
	}
	identity, err := s.FormAnswers.Verify(r.Context(), body.Answer)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "the answer could not be verified", "")
		return
	}
	formID, _ := identity.Claims["form_id"].(string)
	digest, _ := identity.Claims["form_digest"].(string)
	action, _ := identity.Claims["action"].(string)
	if formID == "" || formID != body.FormID || action != body.Action {
		writeError(w, http.StatusUnauthorized, "the answer is for something else", "")
		return
	}
	t, err := s.Tenants.Get(id)
	if err != nil || t.OnCall == nil {
		writeError(w, http.StatusNotFound, "no such form", "")
		return
	}
	if err := t.OnCall.Answer(r.Context(), formID, identity.Sub, digest, action); err != nil {
		writeError(w, http.StatusNotFound, "no such form", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "recorded"})
}

// isFormAnswer checks the token's declared type. An ordinary access token
// from the same issuer must never pass for a person's answer.
func isFormAnswer(token string) bool {
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return false
	}
	var h struct {
		Typ string `json:"typ"`
	}
	return json.Unmarshal(raw, &h) == nil && h.Typ == "app-form-answer+jwt"
}

// mailCertificate serves the public certificate an operator uploads to the
// mail app registration. It is public by nature: it holds no key.
func (s *Server) mailCertificate(w http.ResponseWriter, _ *http.Request) {
	if s.MailCert == nil {
		writeError(w, http.StatusNotFound, "this monitor sends no mail", "")
		return
	}
	writePublicJSON(w, http.StatusOK, s.MailCert)
}

// appFormOpen answers the wallet's question: is this exact form one this
// app sent and is still waiting on? A form's id is random and unguessable,
// and the answer says nothing beyond yes or no.
func (s *Server) appFormOpen(w http.ResponseWriter, r *http.Request) {
	id, digest := r.URL.Query().Get("id"), r.URL.Query().Get("digest")
	if s.Tenants != nil && id != "" && digest != "" {
		for _, t := range s.Tenants.List() {
			if t.OnCall != nil && t.OnCall.FormOpen(id, digest) {
				writeJSON(w, http.StatusOK, map[string]any{"open": true, "form_id": id, "form_digest": digest})
				return
			}
		}
	}
	writeError(w, http.StatusNotFound, "this app is not waiting on that form", "")
}
