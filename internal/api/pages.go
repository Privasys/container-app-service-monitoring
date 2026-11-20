// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"embed"
	"github.com/Privasys/container-app-service-monitoring/internal/tickets"
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
	// decides which page an app's path shows. Under its own domain the
	// runtime hands the app its platform hostname and the name the reader
	// typed in X-Forwarded-Host. Either way, the choice is only between two
	// public pages.
	onSupportHost := func(r *http.Request) bool {
		return strings.HasPrefix(r.Host, "support.") || strings.HasPrefix(r.Header.Get("X-Forwarded-Host"), "support.")
	}

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
	for _, asset := range []string{"status.css", "status.js", "explorer.css", "explorer.js", "verify.js", "home.js", "support.js", "support.css", "status-nav.js", "privasys-auth-client.iife.js"} {
		name := asset
		mux.HandleFunc("GET /"+name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=300")
			r.URL.Path = "/" + name
			files.ServeHTTP(w, r)
		})
	}
	// The Privasys icon set, the same files every Privasys site serves at
	// /favicon/, with the icon also at the root where browsers and link
	// previews ask for it unprompted.
	icons, err := fs.Sub(assets, "favicon")
	if err != nil {
		panic("api: icon assets: " + err.Error())
	}
	iconFiles := http.FileServer(http.FS(icons))
	serveIcon := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, err := fs.Stat(icons, name); err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "public, max-age=86400")
			r.URL.Path = "/" + name
			iconFiles.ServeHTTP(w, r)
		}
	}
	mux.HandleFunc("GET /favicon/{file}", func(w http.ResponseWriter, r *http.Request) {
		serveIcon(r.PathValue("file"))(w, r)
	})
	mux.HandleFunc("GET /favicon.svg", serveIcon("favicon.svg"))
	mux.HandleFunc("GET /favicon.ico", serveIcon("favicon.ico"))

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
		// An app whose account has a short name lives under it now; its
		// old address, already shared in links, takes the reader there.
		// Only once the app has a public page here: the redirect names the
		// account, which an unpublished app keeps to itself.
		if s.Tenants != nil && s.hasPublicPage(r, onSupportHost(r)) {
			if id, ok := s.Tenants.Resolve(r.PathValue("app")); ok {
				if known, ok := s.Tenants.KnownApp(id); ok && known.AccountSlug != "" {
					target := appPage(known, id)
					if r.URL.RawQuery != "" {
						target += "?" + r.URL.RawQuery
					}
					http.Redirect(w, r, target, http.StatusMovedPermanently)
					return
				}
			}
		}
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

	// An account's pages, under its short name: /@<account>/ lists the
	// apps it lists, and /@<account>/<app>/ is one app's page. The status
	// site shows status there and the support site support. A first path
	// segment without the @ is not an account, so the site's own paths
	// can never be taken by one.
	isAccount := func(r *http.Request) bool {
		a := r.PathValue("account")
		return len(a) > 1 && a[0] == '@'
	}
	mux.HandleFunc("GET /{account}", func(w http.ResponseWriter, r *http.Request) {
		if !isAccount(r) {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /{account}/{$}", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !isAccount(r):
			http.NotFound(w, r)
		case onSupportHost(r):
			supportPage(w, r)
		default:
			home(w, r)
		}
	})
	mux.HandleFunc("GET /{account}/{app}", func(w http.ResponseWriter, r *http.Request) {
		if !isAccount(r) {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
	})
	accountStatus := s.publicApp(statusPage)
	mux.HandleFunc("GET /{account}/{app}/{$}", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !isAccount(r):
			http.NotFound(w, r)
		case onSupportHost(r):
			supportPage(w, r)
		default:
			accountStatus(w, r)
		}
	})
}

// hasPublicPage reports whether the app a page address names shows
// anything public there: a published status page, or on the support site,
// a desk open to the public.
func (s *Server) hasPublicPage(r *http.Request, support bool) bool {
	if !support {
		return s.publicAppMonitor(r) != nil
	}
	id, ok := s.Tenants.Resolve(r.PathValue("app"))
	if !ok {
		return false
	}
	t, err := s.Tenants.Get(id)
	return err == nil && t.Tickets != nil && t.Tickets.Settings().Intake == tickets.IntakePublic
}
