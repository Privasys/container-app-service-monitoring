// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/oncall"
	"github.com/Privasys/container-app-service-monitoring/internal/tenancy"
	"github.com/Privasys/container-app-service-monitoring/internal/tickets"
)

// An app's support desk. Anyone signed in may be a requester; what they
// see is their own tickets. The app's team, read from the same token, works
// the queue.

// registerTickets adds the desk's routes.
func (s *Server) registerTickets(mux *http.ServeMux) {
	const base = "/api/v1/apps/{app}/tickets"
	mux.HandleFunc("GET "+base, s.ticketRoute(s.listTickets))
	mux.HandleFunc("POST "+base, s.ticketRoute(s.openTicket))
	mux.HandleFunc("GET "+base+"/{number}", s.ticketRoute(s.getTicket))
	mux.HandleFunc("POST "+base+"/{number}/comments", s.ticketRoute(s.commentTicket))
	mux.HandleFunc("POST "+base+"/{number}/update", s.ticketRoute(s.updateTicket))
	mux.HandleFunc("POST "+base+"/{number}/close", s.ticketRoute(s.closeTicket))
	mux.HandleFunc("DELETE "+base+"/{number}", s.ticketRoute(s.deleteTicket))
	mux.HandleFunc("GET /api/v1/apps/{app}/support/settings", s.ticketRoute(s.supportSettings))
	mux.HandleFunc("POST /api/v1/apps/{app}/support/settings", s.ticketRoute(s.setSupportSettings))

	// What a support page needs before anyone has signed in.
	mux.HandleFunc("GET /api/v1/public/apps/{app}/support", s.publicSupport)

	// The same desk as tools, for the CLI, MCP clients and agents. The app
	// is named in the body, by its id or its platform name.
	mux.HandleFunc("POST /tools/open_ticket", s.ticketTool(s.toolOpenTicket))
	mux.HandleFunc("POST /tools/comment", s.ticketTool(s.toolComment))
	mux.HandleFunc("POST /tools/list_tickets", s.ticketTool(s.toolListTickets))
}

// ticketCall is one authenticated request to an app's desk.
type ticketCall struct {
	w http.ResponseWriter
	r *http.Request
	t *tenancy.Tenant
	// id is who is asking; p is their role on the app, nil for a requester.
	id *auth.Identity
	p  *auth.Principal
}

func (c *ticketCall) can(perm string) bool { return c.p != nil && c.p.Can(perm) }

// unlimited lifts the rate limits for the platform's operators.
func (c *ticketCall) unlimited() bool {
	return c.p != nil && slices.Contains(c.p.Roles, auth.RolePlatformAdmin)
}

func (c *ticketCall) name() string {
	if c.id.Display != "" {
		return c.id.Display
	}
	return c.id.Sub
}

// ticketCaller authenticates the caller before saying anything about the
// app, so a stranger learns nothing about which apps run a desk.
func (s *Server) ticketCaller(w http.ResponseWriter, r *http.Request, app string) (*ticketCall, bool) {
	if s.Tenants == nil || s.AppRoles == nil {
		writeError(w, http.StatusNotFound, "this monitor does not host apps", "")
		return nil, false
	}
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated", "sign in with the Privasys Wallet")
		return nil, false
	}
	identity, err := s.verifier.Verify(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not authenticated", err.Error())
		return nil, false
	}
	id, ok := s.Tenants.Resolve(app)
	if !ok {
		writeError(w, http.StatusNotFound, "support is not available for this app", "")
		return nil, false
	}
	t, err := s.Tenants.Get(id)
	if err != nil || t.Tickets == nil {
		writeError(w, http.StatusNotFound, "support is not available for this app", "")
		return nil, false
	}
	// No role on the app is not a refusal here: it makes the caller a requester.
	p, err := s.AppRoles.Resolve(identity, id, "")
	if err != nil {
		p = nil
	}
	return &ticketCall{w: w, r: r, t: t, id: identity, p: p}, true
}

type ticketHandler func(*ticketCall) (any, error)

func (s *Server) ticketRoute(h ticketHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.ticketCaller(w, r, r.PathValue("app"))
		if !ok {
			return
		}
		respondTicket(w, h, c)
	}
}

func respondTicket(w http.ResponseWriter, h ticketHandler, c *ticketCall) {
	out, err := h(c)
	if err != nil {
		var bad tickets.InvalidError
		var refused refusal
		switch {
		case errors.Is(err, tickets.ErrNotFound):
			writeError(w, http.StatusNotFound, err.Error(), "")
		case errors.Is(err, tickets.ErrLimited):
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, err.Error(), "")
		case errors.As(err, &bad):
			writeError(w, http.StatusBadRequest, err.Error(), "")
		case errors.As(err, &refused):
			writeError(w, http.StatusForbidden, err.Error(), "")
		default:
			writeError(w, http.StatusBadRequest, err.Error(), "")
		}
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// refusal is something the caller's standing does not allow.
type refusal string

func (r refusal) Error() string { return string(r) }

func ticketNumber(s string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "T-"), 10, 64)
	if err != nil || n < 1 {
		return 0, tickets.ErrNotFound
	}
	return n, nil
}

// visible returns the ticket as this caller may see it. Someone else's
// ticket is simply not there.
func (c *ticketCall) visible(number int64) (tickets.Ticket, error) {
	t, err := c.t.Tickets.Get(number)
	if err != nil {
		return t, err
	}
	if c.can(auth.PermExplorer) {
		return t, nil
	}
	if t.Requester != c.id.Sub {
		return tickets.Ticket{}, tickets.ErrNotFound
	}
	return t.ForRequester(), nil
}

// view adds what the team tracks to a ticket they are looking at.
func (c *ticketCall) view(t tickets.Ticket) map[string]any {
	out := map[string]any{"ticket": t}
	if c.can(auth.PermExplorer) {
		out["due"] = c.t.Tickets.Settings().DueOf(t, time.Now().Unix())
	}
	return out
}

func (s *Server) listTickets(c *ticketCall) (any, error) {
	q := c.r.URL.Query()
	return s.ticketList(c, q.Get("status"), q.Get("assignee"), boolParam(c.r, "mine"), intParam(c.r, "limit", 200))
}

func (s *Server) ticketList(c *ticketCall, status, assignee string, mine bool, limit int) (any, error) {
	f := tickets.Filter{Status: status, Assignee: assignee, Limit: limit}
	team := c.can(auth.PermExplorer) && !mine
	if !team {
		f.Requester, f.Assignee = c.id.Sub, ""
	}
	list := c.t.Tickets.List(f)
	settings := c.t.Tickets.Settings()
	now := time.Now().Unix()
	out := make([]map[string]any, 0, len(list))
	for _, t := range list {
		// A listing carries no conversation: that is what opening one is for.
		n := len(t.Comments)
		t.Comments, t.Events, t.Body = nil, nil, ""
		row := map[string]any{"ticket": t, "comments": n}
		if team {
			row["due"] = settings.DueOf(t, now)
		} else {
			t.Assignee, t.IncidentID = "", ""
			row["ticket"] = t
			row["comments"] = len(c.mustRequesterComments(t.Number))
		}
		out = append(out, row)
	}
	return map[string]any{"tickets": out, "team": team}, nil
}

func (c *ticketCall) mustRequesterComments(number int64) []tickets.Comment {
	t, err := c.t.Tickets.Get(number)
	if err != nil {
		return nil
	}
	return t.ForRequester().Comments
}

type openRequest struct {
	Subject  string `json:"subject"`
	Body     string `json:"body"`
	Category string `json:"category"`
}

func (s *Server) openTicket(c *ticketCall) (any, error) {
	var in openRequest
	if err := decode(c.r, &in); err != nil {
		return nil, tickets.InvalidError{Reason: err.Error()}
	}
	return s.open(c, in)
}

func (s *Server) open(c *ticketCall, in openRequest) (any, error) {
	switch c.t.Tickets.Settings().Intake {
	case tickets.IntakePublic:
	case tickets.IntakeTeam:
		if c.p == nil {
			return nil, refusal("this app takes support requests from its own team only")
		}
	default:
		if c.p == nil {
			return nil, refusal("this app is not taking support requests")
		}
	}
	t, err := c.t.Tickets.Create(tickets.New{
		Subject: in.Subject, Body: in.Body, Category: in.Category,
		Requester: c.id.Sub, RequesterName: c.name(), Unlimited: c.unlimited(),
	}, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	s.noticeNewTicket(c.t, t)
	return c.view(forCaller(c, t)), nil
}

func forCaller(c *ticketCall, t tickets.Ticket) tickets.Ticket {
	if c.can(auth.PermExplorer) {
		return t
	}
	return t.ForRequester()
}

func (s *Server) getTicket(c *ticketCall) (any, error) {
	n, err := ticketNumber(c.r.PathValue("number"))
	if err != nil {
		return nil, err
	}
	t, err := c.visible(n)
	if err != nil {
		return nil, err
	}
	return c.view(t), nil
}

type commentRequest struct {
	Body     string `json:"body"`
	Internal bool   `json:"internal"`
}

func (s *Server) commentTicket(c *ticketCall) (any, error) {
	n, err := ticketNumber(c.r.PathValue("number"))
	if err != nil {
		return nil, err
	}
	var in commentRequest
	if err := decode(c.r, &in); err != nil {
		return nil, tickets.InvalidError{Reason: err.Error()}
	}
	return s.comment(c, n, in)
}

func (s *Server) comment(c *ticketCall, n int64, in commentRequest) (any, error) {
	if _, err := c.visible(n); err != nil {
		return nil, err
	}
	team := c.can(auth.PermRespond)
	if c.p != nil && !team {
		// A viewer on the team may still reply to their own ticket.
		if t, err := c.t.Tickets.Get(n); err != nil || t.Requester != c.id.Sub {
			return nil, refusal("your role on this app does not include answering tickets")
		}
	}
	t, err := c.t.Tickets.AddComment(n, tickets.Reply{
		Author: c.id.Sub, AuthorName: c.name(), Team: team, Internal: in.Internal,
		Body: in.Body, Unlimited: c.unlimited(),
	}, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	switch {
	case in.Internal:
	case team && t.Requester != c.id.Sub:
		s.ticketNotice(c.t, t.Requester, t, "New reply on your support request")
	case t.Assignee != "" && t.Assignee != c.id.Sub:
		s.ticketNotice(c.t, t.Assignee, t, "New reply on a ticket assigned to you")
	}
	return c.view(forCaller(c, t)), nil
}

type updateRequest struct {
	Status     *string `json:"status"`
	Priority   *string `json:"priority"`
	Category   *string `json:"category"`
	Assignee   *string `json:"assignee"`
	IncidentID *string `json:"incident_id"`
}

func (s *Server) updateTicket(c *ticketCall) (any, error) {
	if !c.can(auth.PermRespond) {
		return nil, refusal("your role on this app does not include working tickets")
	}
	n, err := ticketNumber(c.r.PathValue("number"))
	if err != nil {
		return nil, err
	}
	var in updateRequest
	if err := decode(c.r, &in); err != nil {
		return nil, tickets.InvalidError{Reason: err.Error()}
	}
	before, err := c.t.Tickets.Get(n)
	if err != nil {
		return nil, err
	}
	t, err := c.t.Tickets.Update(n, c.id.Sub, tickets.Change{
		Status: in.Status, Priority: in.Priority, Category: in.Category,
		Assignee: in.Assignee, IncidentID: in.IncidentID,
	}, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if t.Assignee != "" && t.Assignee != before.Assignee && t.Assignee != c.id.Sub {
		s.ticketNotice(c.t, t.Assignee, t, "A ticket was assigned to you")
	}
	if t.Status != before.Status && t.Requester != c.id.Sub &&
		(t.Status == tickets.StatusResolved || t.Status == tickets.StatusWaiting) {
		s.ticketNotice(c.t, t.Requester, t, "Your support request was updated")
	}
	return c.view(t), nil
}

func (s *Server) closeTicket(c *ticketCall) (any, error) {
	n, err := ticketNumber(c.r.PathValue("number"))
	if err != nil {
		return nil, err
	}
	t, err := c.t.Tickets.CloseByRequester(n, c.id.Sub, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return c.view(forCaller(c, t)), nil
}

// deleteTicket removes a ticket: the app's admins may, and so may the
// person who wrote it, since what they wrote is theirs.
func (s *Server) deleteTicket(c *ticketCall) (any, error) {
	n, err := ticketNumber(c.r.PathValue("number"))
	if err != nil {
		return nil, err
	}
	t, err := c.t.Tickets.Get(n)
	if err != nil {
		return nil, err
	}
	if !c.can(auth.PermAdmin) && t.Requester != c.id.Sub {
		if c.p == nil {
			return nil, tickets.ErrNotFound
		}
		return nil, refusal("your role on this app does not include deleting tickets")
	}
	if err := c.t.Tickets.Delete(n); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": n}, nil
}

func (s *Server) supportSettings(c *ticketCall) (any, error) {
	if c.p == nil {
		return nil, refusal("only the app's team reads its support settings")
	}
	return map[string]any{"settings": c.t.Tickets.Settings(), "can_manage": c.can(auth.PermAdmin), "can_respond": c.can(auth.PermRespond)}, nil
}

func (s *Server) setSupportSettings(c *ticketCall) (any, error) {
	if !c.can(auth.PermAdmin) {
		return nil, refusal("only the app's owners, admins and support admins change its support settings")
	}
	var in tickets.Settings
	if err := decode(c.r, &in); err != nil {
		return nil, tickets.InvalidError{Reason: err.Error()}
	}
	if err := c.t.Tickets.SetSettings(in); err != nil {
		return nil, err
	}
	return map[string]any{"settings": in}, nil
}

// publicSupport says whether an app takes support requests, and how. An app
// that does not answers exactly as an app with no desk at all.
func (s *Server) publicSupport(w http.ResponseWriter, r *http.Request) {
	notAvailable := func() { writeError(w, http.StatusNotFound, "support is not available for this app", "") }
	if s.Tenants == nil {
		notAvailable()
		return
	}
	id, ok := s.Tenants.Resolve(r.PathValue("app"))
	if !ok {
		notAvailable()
		return
	}
	t, err := s.Tenants.Get(id)
	if err != nil || t.Tickets == nil {
		notAvailable()
		return
	}
	cfg := t.Tickets.Settings()
	if cfg.Intake != tickets.IntakePublic {
		notAvailable()
		return
	}
	body := map[string]any{"app": id, "intake": cfg.Intake, "categories": cfg.Categories}
	if known, ok := s.Tenants.KnownApp(id); ok {
		body["name"], body["display_name"] = known.Name, known.DisplayName
	}
	writePublicJSON(w, http.StatusOK, body)
}

// -- tools ---------------------------------------------------------------

// ticketTool reads the app a tool call names, then the rest of its body.
func (s *Server) ticketTool(h func(*ticketCall, toolRequest) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in toolRequest
		if err := decode(r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "the request could not be read", err.Error())
			return
		}
		if in.App == "" {
			writeError(w, http.StatusBadRequest, "name the app, by its id or its platform name", "")
			return
		}
		c, ok := s.ticketCaller(w, r, in.App)
		if !ok {
			return
		}
		respondTicket(w, func(c *ticketCall) (any, error) { return h(c, in) }, c)
	}
}

type toolRequest struct {
	App      string `json:"app"`
	Subject  string `json:"subject"`
	Body     string `json:"body"`
	Category string `json:"category"`
	Ticket   string `json:"ticket"`
	Internal bool   `json:"internal"`
	Status   string `json:"status"`
	Mine     bool   `json:"mine"`
}

func (s *Server) toolOpenTicket(c *ticketCall, in toolRequest) (any, error) {
	return s.open(c, openRequest{Subject: in.Subject, Body: in.Body, Category: in.Category})
}

func (s *Server) toolComment(c *ticketCall, in toolRequest) (any, error) {
	n, err := ticketNumber(in.Ticket)
	if err != nil {
		return nil, err
	}
	return s.comment(c, n, commentRequest{Body: in.Body, Internal: in.Internal})
}

func (s *Server) toolListTickets(c *ticketCall, in toolRequest) (any, error) {
	return s.ticketList(c, in.Status, "", in.Mine, 200)
}

// -- notices -------------------------------------------------------------

// ticketNotice tells one person about a ticket, in the background: nobody's
// request waits on a phone or a mail server.
func (s *Server) ticketNotice(t *tenancy.Tenant, sub string, tk tickets.Ticket, headline string) {
	if s.TicketNotice == nil {
		return
	}
	subject := fmt.Sprintf("%s: T-%d", headline, tk.Number)
	body := fmt.Sprintf("%s\n\nT-%d: %s", headline, tk.Number, tk.Subject)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		s.TicketNotice(ctx, t, sub, subject, body)
	}()
}

// noticeNewTicket tells whoever is on call, or else the app's leads, that a
// ticket arrived. A burst of tickets makes one notice, not one each.
func (s *Server) noticeNewTicket(t *tenancy.Tenant, tk tickets.Ticket) {
	if s.TicketNotice == nil || t.OnCall == nil || !t.Tickets.NoticeDue(time.Now().Unix()) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		team, err := t.OnCall.Team(ctx)
		if err != nil {
			s.log.Error("could not read who to tell about a new ticket", "app", t.ID, "error", err)
			return
		}
		onCall := t.OnCall.Store.Plan().OnCall(time.Now())
		var people []oncall.Member
		for _, m := range team {
			if m.Sub == onCall {
				people = []oncall.Member{m}
				break
			}
			if m.Lead() {
				people = append(people, m)
			}
		}
		subject := fmt.Sprintf("New support request: T-%d", tk.Number)
		body := fmt.Sprintf("A new support request arrived.\n\nT-%d: %s", tk.Number, tk.Subject)
		for _, m := range people {
			s.TicketNotice(ctx, t, m.Sub, subject, body)
		}
	}()
}
