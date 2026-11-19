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

	// The page loads its own scripts and talks only to this origin. Saying
	// so keeps an injected script from having anywhere to send what it reads.
	const ownOrigin = "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
	// The support page also signs people in, so it may frame the identity
	// provider and reach the wallet's relay, and nothing else.
	const signIn = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://privasys.id; " +
		"frame-src https://privasys.id; connect-src 'self' https://privasys.id https://api.developer.privasys.org " +
		"https://api.developer.test.privasys.org wss://relay.privasys.org"

	servePage := func(name, policy string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, err := fs.ReadFile(assets, name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Content-Security-Policy", policy)
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			_, _ = w.Write(body)
		}
	}

	serve := func(name string) http.HandlerFunc { return servePage(name, ownOrigin) }
	supportPage := servePage("support.html", signIn)
	// The support site is the same app under another name: its address
	// decides which page an app's path shows.
	onSupportHost := func(r *http.Request) bool { return strings.HasPrefix(r.Host, "support.") }

	mux.HandleFunc("GET /support/{$}", supportPage)
	mux.HandleFunc("GET /support/{app}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /support/{app}/{$}", supportPage)

	statusPage := serve("index.html")
	mux.HandleFunc("GET /status", statusPage)
	mux.HandleFunc("GET /status/{slug}", statusPage)
	mux.HandleFunc("GET /explorer", serve("explorer.html"))

	// The scripts and stylesheets, served at the root so both pages can
	// reference them the same way.
	for _, asset := range []string{"status.css", "status.js", "explorer.css", "explorer.js", "verify.js", "home.js", "support.js", "support.css", "privasys-auth-client.iife.js"} {
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

	// One app's status page, at /apps/{app}/ so its relative assets
	// resolve under the same prefix. Like the app's data, it is a 404
	// until the app's team makes a service public.
	mux.HandleFunc("GET /apps/{app}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
	})
	publicStatus := s.publicApp(statusPage)
	mux.HandleFunc("GET /apps/{app}/{$}", func(w http.ResponseWriter, r *http.Request) {
		if onSupportHost(r) {
			supportPage(w, r)
			return
		}
		publicStatus(w, r)
	})
	mux.HandleFunc("GET /apps/{app}/{asset}", s.publicApp(func(w http.ResponseWriter, r *http.Request) {
		asset := r.PathValue("asset")
		if !strings.HasSuffix(asset, ".js") && !strings.HasSuffix(asset, ".css") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=300")
		r.URL.Path = "/" + asset
		files.ServeHTTP(w, r)
	}))

	// The landing page: the apps whose teams publish their status.
	home := serve("home.html")
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if onSupportHost(r) {
			supportPage(w, r)
			return
		}
		home(w, r)
	})
}
