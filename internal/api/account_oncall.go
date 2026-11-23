// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

// The account's rota, for every app of the account that has none of its
// own (oncall/account.go). Its admins change it; its members see it, and
// every member sets their own account-wide alert channels here. Who holds
// what in the account comes from the account role their platform token
// carries; an account the platform's app list does not name is a 404.

import (
	"net/http"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/oncall"
)

func (s *Server) registerAccountOnCall(mux *http.ServeMux) {
	const base = "/api/v1/accounts/{account}/oncall"
	mux.HandleFunc("GET "+base, s.accountOnCallOverview)
	mux.HandleFunc("POST "+base+"/plan", s.accountOnCallSetPlan)
	mux.HandleFunc("POST "+base+"/me", s.accountOnCallSetMine)
	mux.HandleFunc("DELETE "+base+"/me", s.accountOnCallForgetMine)
}

// accountCaller resolves the account, the caller, and whether they manage
// it, and opens the account's rota. It writes the refusal itself.
func (s *Server) accountCaller(w http.ResponseWriter, r *http.Request) (store *oncall.Store, accountID, sub string, manage bool, ok bool) {
	if s.OnCallAccounts == nil {
		writeError(w, http.StatusNotFound, "this monitor does not host accounts", "")
		return nil, "", "", false, false
	}
	accountID, sub, manage, ok = s.accountAccess(w, r)
	if !ok {
		return nil, "", "", false, false
	}
	store, err := s.OnCallAccounts.Get(accountID)
	if err != nil || store == nil {
		writeError(w, http.StatusInternalServerError, "the account's on-call data could not be opened", "")
		return nil, "", "", false, false
	}
	return store, accountID, sub, manage, true
}

// accountAccess resolves the account in the address and the caller: its
// admins manage it, its members see it, and anyone else learns nothing.
func (s *Server) accountAccess(w http.ResponseWriter, r *http.Request) (accountID, sub string, manage bool, ok bool) {
	if s.Tenants == nil {
		writeError(w, http.StatusNotFound, "this monitor does not host accounts", "")
		return "", "", false, false
	}
	token, has := bearerToken(r)
	if !has {
		writeError(w, http.StatusUnauthorized, "not authenticated", "a bearer token is required")
		return "", "", false, false
	}
	id, err := s.verifier.Verify(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated", err.Error())
		return "", "", false, false
	}
	acc, known := s.Tenants.AccountByID(r.PathValue("account"))
	if !known {
		writeError(w, http.StatusNotFound, "no such account", "")
		return "", "", false, false
	}
	key := auth.AppKey(acc.ID)
	admin, member := false, false
	for _, role := range id.Roles {
		switch {
		case role == auth.OIDCPlatformAdmin:
			admin = true
		case role == auth.PlatformNamespace+":account:"+key+":admin":
			admin = true
		case role == auth.PlatformNamespace+":account:"+key+":member":
			member = true
		}
	}
	if !admin && !member {
		writeError(w, http.StatusNotFound, "no such account", "")
		return "", "", false, false
	}
	return acc.ID, id.Sub, admin, true
}

func (s *Server) accountOnCallOverview(w http.ResponseWriter, r *http.Request) {
	store, accountID, sub, manage, ok := s.accountCaller(w, r)
	if !ok {
		return
	}
	plan := store.Plan()
	writeJSON(w, http.StatusOK, map[string]any{
		"account": accountID, "plan": plan, "on_call": plan.OnCall(time.Now()),
		"me": store.Preference(sub), "sub": sub, "can_manage": manage,
	})
}

func (s *Server) accountOnCallSetPlan(w http.ResponseWriter, r *http.Request) {
	store, _, _, manage, ok := s.accountCaller(w, r)
	if !ok {
		return
	}
	if !manage {
		writeError(w, http.StatusForbidden, "only the account's admins change its rota", "")
		return
	}
	var plan oncall.Plan
	if err := decode(r, &plan); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	if err := store.SetPlan(plan); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": plan})
}

func (s *Server) accountOnCallSetMine(w http.ResponseWriter, r *http.Request) {
	store, _, sub, _, ok := s.accountCaller(w, r)
	if !ok {
		return
	}
	var pref oncall.Preference
	if err := decode(r, &pref); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	// Each person sets their own, and only their own.
	pref.Sub = sub
	saved, err := store.SetPreference(pref, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"me": saved})
}

func (s *Server) accountOnCallForgetMine(w http.ResponseWriter, r *http.Request) {
	store, _, sub, _, ok := s.accountCaller(w, r)
	if !ok {
		return
	}
	if err := store.ForgetPreference(sub); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"me": store.Preference(sub)})
}
