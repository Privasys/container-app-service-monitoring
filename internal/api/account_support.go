// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

// The account's desk defaults, for every app of the account whose team set
// no support settings of its own (tickets/account.go). Its admins change
// them; its members see them. Access is as for the account's rota.

import (
	"net/http"

	"github.com/Privasys/container-app-service-monitoring/internal/tickets"
)

func (s *Server) registerAccountSupport(mux *http.ServeMux) {
	const path = "/api/v1/accounts/{account}/support/settings"
	mux.HandleFunc("GET "+path, s.accountSupportSettings)
	mux.HandleFunc("POST "+path, s.setAccountSupportSettings)
}

func (s *Server) accountDefaults(w http.ResponseWriter, r *http.Request) (*tickets.Defaults, bool, bool) {
	if s.SupportAccounts == nil {
		writeError(w, http.StatusNotFound, "this monitor does not host accounts", "")
		return nil, false, false
	}
	accountID, _, manage, ok := s.accountAccess(w, r)
	if !ok {
		return nil, false, false
	}
	d, err := s.SupportAccounts.Get(accountID)
	if err != nil || d == nil {
		writeError(w, http.StatusInternalServerError, "the account's support settings could not be opened", "")
		return nil, false, false
	}
	return d, manage, true
}

func (s *Server) accountSupportSettings(w http.ResponseWriter, r *http.Request) {
	d, manage, ok := s.accountDefaults(w, r)
	if !ok {
		return
	}
	cfg, set := d.Get()
	writeJSON(w, http.StatusOK, map[string]any{"settings": cfg, "set": set, "can_manage": manage})
}

func (s *Server) setAccountSupportSettings(w http.ResponseWriter, r *http.Request) {
	d, manage, ok := s.accountDefaults(w, r)
	if !ok {
		return
	}
	if !manage {
		writeError(w, http.StatusForbidden, "only the account's admins change its support settings", "")
		return
	}
	var in tickets.Settings
	if err := decode(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	if err := d.Set(in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": in, "set": true})
}
