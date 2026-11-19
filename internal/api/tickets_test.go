// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"net/http"
	"strings"
	"testing"

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
