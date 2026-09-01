// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed web/*
var webFS embed.FS

// registerPages serves the status page and the operator explorer.
//
// Both are served from inside the measured image, which is the point:
// the pages a reader runs come from the same build whose measurement is
// in the certificate, so an unattested web host never gets a chance to
// alter what they see. A vanity domain in front of this is a redirect,
// never a proxy.
func registerPages(mux *http.ServeMux, s *Server) {
	assets, err := fs.Sub(webFS, "web")
	if err != nil {
		panic("api: page assets: " + err.Error())
	}
	files := http.FileServer(http.FS(assets))

	serve := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, err := fs.ReadFile(assets, name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			// The page loads its own scripts and talks only to this
			// origin. Saying so keeps an injected script from having
			// anywhere to send what it reads.
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			_, _ = w.Write(body)
		}
	}

	statusPage := serve("index.html")
	mux.HandleFunc("GET /status", statusPage)
	mux.HandleFunc("GET /status/{slug}", statusPage)
	mux.HandleFunc("GET /explorer", serve("explorer.html"))

	// The scripts and stylesheets, served at the root so both pages can
	// reference them the same way.
	for _, asset := range []string{"status.css", "status.js", "explorer.css", "explorer.js", "verify.js"} {
		name := asset
		mux.HandleFunc("GET /"+name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=300")
			r.URL.Path = "/" + name
			files.ServeHTTP(w, r)
		})
	}
	// The status page under a slug loads its assets relative to itself.
	mux.HandleFunc("GET /status/{slug}/{asset}", func(w http.ResponseWriter, r *http.Request) {
		asset := r.PathValue("asset")
		if !strings.HasSuffix(asset, ".js") && !strings.HasSuffix(asset, ".css") {
			http.NotFound(w, r)
			return
		}
		r.URL.Path = "/" + asset
		files.ServeHTTP(w, r)
	})

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/status", http.StatusFound)
	})
}
