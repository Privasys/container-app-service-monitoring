// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import "net/http"

// SignIn is how this site's pages sign a person in to the platform the
// monitor serves: the control plane they talk to, and the client and
// token audience they ask privasys.id for. Each platform has its own
// client so the sign-in frame keeps its sessions apart.
type SignIn struct {
	APIBase  string `json:"api_base"`
	ClientID string `json:"client_id"`
	Audience string `json:"audience,omitempty"`
}

// ProductionSignIn is the production platform's sign-in, and what a
// page uses when the monitor does not say otherwise.
var ProductionSignIn = SignIn{APIBase: "https://api.developer.privasys.org", ClientID: "privasys-platform"}

// publicSignIn tells the site's pages which platform to sign in to. It
// is read off the monitor's own configuration, never off the address
// the page was reached at.
func (s *Server) publicSignIn(w http.ResponseWriter, _ *http.Request) {
	in := ProductionSignIn
	if s.SignIn != nil {
		in = s.SignIn()
	}
	writeJSON(w, http.StatusOK, in)
}
