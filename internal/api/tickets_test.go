// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/tenancy"
	"github.com/Privasys/container-app-service-monitoring/internal/tickets"
)

func TestTheSupportDesk(t *testing.T) {
	srv, host, _ := newAppServer(t)
	a, err := host.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	host.Sync(nil, false)
	base := "/api/v1/apps/" + appA
	owner := token("ada", "privasys-platform:app:"+keyA+":owner")
	member := token("bo", "privasys-platform:app:"+keyA+":support-member")
	viewer := token("vi", "privasys-platform:app:"+keyA+":support-viewer")
	alice := token("alice")
	mallory := token("mallory")
	otherOwner := token("cy", "privasys-platform:app:"+keyB+":owner")
	ticket := map[string]any{"subject": "Cannot sign in", "body": "It fails on my phone."}

	// Nobody signed in gets nowhere, and learns nothing.
	if code, _ := send(t, srv, "POST", base+"/tickets", "", ticket); code != http.StatusUnauthorized {
		t.Fatalf("an anonymous ticket: %d", code)
	}

	// A new desk is closed: the public cannot file, and the page says nothing.
	if code, _ := send(t, srv, "POST", base+"/tickets", alice, ticket); code != http.StatusForbidden {
		t.Fatalf("a ticket on a closed desk: %d", code)
	}
	if code, _ := send(t, srv, "GET", "/api/v1/public/apps/"+appA+"/support", "", nil); code != http.StatusNotFound {
		t.Fatalf("a closed desk advertised itself: %d", code)
	}

	// Only the leads open it.
	cfg := tickets.DefaultSettings()
	cfg.Intake = tickets.IntakeTeam
	if code, _ := send(t, srv, "POST", base+"/support/settings", member, cfg); code != http.StatusForbidden {
		t.Fatalf("a member changed the settings: %d", code)
	}
	if code, _ := send(t, srv, "POST", base+"/support/settings", owner, cfg); code != http.StatusOK {
		t.Fatalf("the owner could not: %d", code)
	}
	if code, _ := send(t, srv, "POST", base+"/tickets", alice, ticket); code != http.StatusForbidden {
		t.Fatalf("the public filed on a team-only desk: %d", code)
	}
	if code, _ := send(t, srv, "POST", base+"/tickets", member, ticket); code != http.StatusOK {
		t.Fatalf("the team could not file on its own desk: %d", code)
	}

	cfg.Intake = tickets.IntakePublic
	if code, _ := send(t, srv, "POST", base+"/support/settings", owner, cfg); code != http.StatusOK {
		t.Fatal("could not open the desk")
	}
	if code, body := send(t, srv, "GET", "/api/v1/public/apps/"+appA+"/support", "", nil); code != http.StatusOK || body["intake"] != "public" {
		t.Fatalf("public support: %d %v", code, body)
	}

	// Alice files one. A requester cannot set its priority.
	code, body := send(t, srv, "POST", base+"/tickets", alice, map[string]any{"subject": "Help", "body": "Please."})
	if code != http.StatusOK {
		t.Fatalf("open: %d %v", code, body)
	}
	if code, _ := send(t, srv, "POST", base+"/tickets", alice, map[string]any{"subject": "x", "body": "y", "priority": "urgent"}); code != http.StatusBadRequest {
		t.Fatalf("a requester set a priority: %d", code)
	}
	path := base + "/tickets/2"

	// Strangers cannot see it, and neither can another app's team.
	for name, who := range map[string]string{"another requester": mallory, "another app's owner": otherOwner} {
		if code, _ := send(t, srv, "GET", path, who, nil); code != http.StatusNotFound {
			t.Fatalf("%s read the ticket: %d", name, code)
		}
		if code, _ := send(t, srv, "POST", path+"/comments", who, map[string]any{"body": "hello"}); code != http.StatusNotFound {
			t.Fatalf("%s commented: %d", name, code)
		}
		if code, _ := send(t, srv, "DELETE", path, who, nil); code != http.StatusNotFound {
			t.Fatalf("%s deleted: %d", name, code)
		}
	}
	if code, list := send(t, srv, "GET", base+"/tickets", mallory, nil); code != http.StatusOK || len(list["tickets"].([]any)) != 0 {
		t.Fatalf("another requester's list: %d %v", code, list)
	}

	// The team works it. A viewer reads but does not act; a requester does neither.
	if code, list := send(t, srv, "GET", base+"/tickets", viewer, nil); code != http.StatusOK || len(list["tickets"].([]any)) != 2 {
		t.Fatalf("the viewer's queue: %d %v", code, list)
	}
	assign := map[string]any{"assignee": "bo", "priority": "high"}
	if code, _ := send(t, srv, "POST", path+"/update", viewer, assign); code != http.StatusForbidden {
		t.Fatalf("a viewer worked a ticket: %d", code)
	}
	if code, _ := send(t, srv, "POST", path+"/update", alice, assign); code != http.StatusForbidden {
		t.Fatalf("the requester worked their own ticket: %d", code)
	}
	if code, _ := send(t, srv, "POST", path+"/comments", viewer, map[string]any{"body": "hi"}); code != http.StatusForbidden {
		t.Fatalf("a viewer answered: %d", code)
	}
	if code, out := send(t, srv, "POST", path+"/update", member, assign); code != http.StatusOK || out["due"] == nil {
		t.Fatalf("assign: %d %v", code, out)
	}
	if code, _ := send(t, srv, "POST", path+"/comments", member, map[string]any{"body": "TEAM-NOTE-ONLY", "internal": true}); code != http.StatusOK {
		t.Fatal("internal note")
	}
	if code, _ := send(t, srv, "POST", path+"/comments", member, map[string]any{"body": "Which phone?"}); code != http.StatusOK {
		t.Fatal("reply")
	}
	if code, _ := send(t, srv, "POST", path+"/comments", alice, map[string]any{"body": "note", "internal": true}); code != http.StatusBadRequest {
		t.Fatalf("a requester wrote an internal note: %d", code)
	}

	// Alice sees the reply and nothing of how the team works.
	code, mine := send(t, srv, "GET", path, alice, nil)
	if code != http.StatusOK {
		t.Fatalf("her ticket: %d", code)
	}
	tk := mine["ticket"].(map[string]any)
	if len(tk["comments"].([]any)) != 1 || tk["assignee"] != nil || tk["events"] != nil || mine["due"] != nil {
		t.Fatalf("the requester's view leaks: %v", mine)
	}
	_, list := send(t, srv, "GET", base+"/tickets", alice, nil)
	row := list["tickets"].([]any)[0].(map[string]any)
	if row["comments"] != float64(1) || row["due"] != nil {
		t.Fatalf("the requester's list leaks: %v", row)
	}

	// The tools reach the same desk, by the app's id.
	code, out := send(t, srv, "POST", "/tools/open_ticket", alice, map[string]any{"app": appA, "subject": "From the CLI", "body": "Filed by an agent."})
	if code != http.StatusOK || out["ticket"].(map[string]any)["number"] != float64(3) {
		t.Fatalf("open_ticket: %d %v", code, out)
	}
	if code, _ := send(t, srv, "POST", "/tools/comment", alice, map[string]any{"app": appA, "ticket": "T-3", "body": "More detail."}); code != http.StatusOK {
		t.Fatalf("comment tool: %d", code)
	}
	if code, out := send(t, srv, "POST", "/tools/list_tickets", alice, map[string]any{"app": appA}); code != http.StatusOK || len(out["tickets"].([]any)) != 2 {
		t.Fatalf("list tool: %d %v", code, out)
	}
	if code, _ := send(t, srv, "POST", "/tools/open_ticket", "", map[string]any{"app": appA, "subject": "x", "body": "y"}); code != http.StatusUnauthorized {
		t.Fatalf("an anonymous tool call: %d", code)
	}

	// A member cannot delete someone else's ticket; the author can delete
	// their own, and it is gone from disk with it.
	if code, _ := send(t, srv, "DELETE", path, member, nil); code != http.StatusForbidden {
		t.Fatalf("a member deleted: %d", code)
	}
	if code, _ := send(t, srv, "DELETE", path, alice, nil); code != http.StatusOK {
		t.Fatalf("the author could not delete: %d", code)
	}
	if code, _ := send(t, srv, "GET", path, owner, nil); code != http.StatusNotFound {
		t.Fatalf("a deleted ticket answered: %d", code)
	}
	for _, tk := range a.Tickets.List(tickets.Filter{}) {
		if strings.Contains(tk.Body, "TEAM-NOTE-ONLY") {
			t.Fatal("deleted content survived")
		}
	}
}

func TestTheSupportSite(t *testing.T) {
	srv, host, _ := newAppServer(t)
	a, err := host.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	host.Sync([]tenancy.App{{ID: appA, Name: "checkout", DisplayName: "Checkout", Hostname: "checkout.apps.example"}}, true)
	page := func(path, hostname string) (int, string, string) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Host = hostname
		res, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(raw), res.Header.Get("Content-Security-Policy")
	}
	const support, status = "support.privasys.org", "status.privasys.org"

	// The address decides the page: the support site's root and an app's
	// path show support; the status site keeps its own pages.
	for _, c := range []struct{ path, hostname string }{
		{"/", support}, {"/apps/checkout/", support}, {"/support/", status}, {"/support/checkout/", status},
	} {
		code, body, policy := page(c.path, c.hostname)
		if code != http.StatusOK || !strings.Contains(body, "/support.js") {
			t.Fatalf("%s on %s: %d", c.path, c.hostname, code)
		}
		if !strings.Contains(policy, "frame-src https://privasys.id") {
			t.Fatalf("%s on %s: policy %q", c.path, c.hostname, policy)
		}
	}
	if _, body, policy := page("/", status); strings.Contains(body, "/support.js") || strings.Contains(policy, "frame-src") {
		t.Fatal("the status site's home became the support page")
	}
	if code, _, _ := page("/apps/checkout/", status); code != http.StatusNotFound {
		t.Fatalf("an unpublished status page answered %d", code)
	}
	for _, asset := range []string{"/support.js", "/support.css", "/privasys-auth-client.iife.js"} {
		if code, _, _ := page(asset, support); code != http.StatusOK {
			t.Fatalf("%s: %d", asset, code)
		}
	}

	// Only an app open to the public is listed.
	_, list := send(t, srv, "GET", "/api/v1/public/support", "", nil)
	if n := len(list["apps"].([]any)); n != 0 {
		t.Fatalf("a closed desk was listed: %d", n)
	}
	cfg := tickets.DefaultSettings()
	cfg.Intake = tickets.IntakePublic
	if err := a.Tickets.SetSettings(cfg); err != nil {
		t.Fatal(err)
	}
	_, list = send(t, srv, "GET", "/api/v1/public/support", "", nil)
	entry := list["apps"].([]any)[0].(map[string]any)
	if entry["name"] != "checkout" || entry["display_name"] != "Checkout" {
		t.Fatalf("index: %v", entry)
	}
}

// The runtime removes a Content-Security-Policy header from a public page, so
// each page must carry its policy in its own markup.
func TestPublicPagesCarryTheirPolicyInTheMarkup(t *testing.T) {
	for name, want := range map[string]string{
		"web/index.html":   "script-src 'self'",
		"web/home.html":    "script-src 'self'",
		"web/support.html": "frame-src https://privasys.id",
	} {
		raw, err := webFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		page := string(raw)
		tag := strings.Index(page, `<meta http-equiv="Content-Security-Policy"`)
		script := strings.Index(page, "<script")
		if tag < 0 || script < tag || !strings.Contains(page, want) {
			t.Errorf("%s does not declare its policy ahead of its scripts", name)
		}
	}
}

func TestTicketLimitsAnswerTooManyRequests(t *testing.T) {
	srv, host, _ := newAppServer(t)
	a, err := host.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	cfg := tickets.DefaultSettings()
	cfg.Intake, cfg.TicketsPerHour, cfg.TicketsPerDay = tickets.IntakePublic, 1, 1
	if err := a.Tickets.SetSettings(cfg); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/apps/" + appA + "/tickets"
	ticket := map[string]any{"subject": "x", "body": "y"}
	alice := token("alice")
	if code, _ := send(t, srv, "POST", path, alice, ticket); code != http.StatusOK {
		t.Fatalf("first: %d", code)
	}
	if code, _ := send(t, srv, "POST", path, alice, ticket); code != http.StatusTooManyRequests {
		t.Fatalf("second: %d", code)
	}
	// The platform's operators are not limited.
	admin := token("op", "privasys-platform:admin")
	for range 3 {
		if code, _ := send(t, srv, "POST", path, admin, ticket); code != http.StatusOK {
			t.Fatalf("an operator was limited: %d", code)
		}
	}
}

func TestEveryPageCarriesThePrivasysIcon(t *testing.T) {
	srv, _, _ := newAppServer(t)
	for _, name := range []string{"web/index.html", "web/home.html", "web/support.html", "web/explorer.html"} {
		raw, err := webFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `href="/favicon/favicon.svg"`) {
			t.Errorf("%s does not link the icon", name)
		}
	}
	for path, kind := range map[string]string{
		"/favicon/favicon.svg":          "image/svg+xml",
		"/favicon/apple-touch-icon.png": "image/png",
		"/favicon.svg":                  "image/svg+xml",
		"/favicon.ico":                  "",
	} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), kind) {
			t.Errorf("%s: %d %s", path, res.StatusCode, res.Header.Get("Content-Type"))
		}
	}
	if res, err := http.Get(srv.URL + "/favicon/nothing.png"); err != nil || res.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown icon was answered")
	}
}
