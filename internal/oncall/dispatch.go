// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package oncall

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/core"
)

// Wallet puts things in front of a person through the platform.
type Wallet interface {
	// Form sends a decision the person answers in their wallet.
	Form(ctx context.Context, sub, form string) (status string, err error)
	// Message sends a notice that needs no answer.
	Message(ctx context.Context, sub, title, body string) (status string, err error)
}

// Mailer sends one plain-text email.
type Mailer func(ctx context.Context, to, subject, body string) error

// TeamSource lists the app's team as the control plane knows it.
type TeamSource func(ctx context.Context) ([]Member, error)

// Dispatcher runs one app's paging.
type Dispatcher struct {
	Store   *Store
	AppID   string
	AppName func() string
	Team    TeamSource
	// Platform lists the platform operators' team, the last level of a page.
	Platform TeamSource
	// Account is the store of the account the app belongs to (account.go):
	// its rota when the app has none, and people's account-wide channels.
	Account func() *Store
	Wallet   Wallet
	Mail     Mailer
	// Callback is the path on the monitor's host a form's answer comes to.
	Callback string
	// ConsoleURL is where a person can see the incident.
	ConsoleURL string
	Log        *slog.Logger
	Now        func() time.Time

	alerts chan core.Alert
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Dispatcher) name() string {
	if d.AppName != nil {
		if n := d.AppName(); n != "" {
			return n
		}
	}
	return "Your app"
}

// HandleAlert takes an alert from the monitor. It never blocks: the
// scheduler that raised it has readings to take.
func (d *Dispatcher) HandleAlert(a core.Alert) {
	if a.Event != core.EventComponentDown && a.Event != core.EventComponentUp {
		return
	}
	select {
	case d.queue() <- a:
	default:
		d.Log.Error("the paging queue is full; an alert was not paged", "alert", a.ID)
	}
}

func (d *Dispatcher) queue() chan core.Alert {
	if d.alerts == nil {
		d.alerts = make(chan core.Alert, 64)
	}
	return d.alerts
}

// Prepare readies the dispatcher before alerts can arrive.
func (d *Dispatcher) Prepare() { d.queue() }

// tickEvery is how often unanswered pages are looked at.
const tickEvery = 30 * time.Second

// Run pages until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	tick := time.NewTicker(tickEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-d.queue():
			d.process(ctx, a)
		case <-tick.C:
			d.Tick(ctx)
		}
	}
}

func (d *Dispatcher) process(ctx context.Context, a core.Alert) {
	str := func(k string) string { s, _ := a.Payload[k].(string); return s }
	if a.Event == core.EventComponentDown {
		d.Open(ctx, str("incident_id"), str("component_id"), str("component"), str("detail"))
		return
	}
	d.Resolve(ctx, str("component_id"))
}

// Open starts paging for an outage, unless one is already open for the
// component.
func (d *Dispatcher) Open(ctx context.Context, incidentID, componentID, component, detail string) {
	now := d.now()
	d.Store.mu.Lock()
	for _, p := range d.Store.st.Pages {
		if p.ComponentID == componentID && (p.State == PageOpen || p.State == PageTaken) {
			d.Store.mu.Unlock()
			return
		}
	}
	id, err := newID()
	if err != nil {
		d.Store.mu.Unlock()
		d.Log.Error("could not open a page", "error", err)
		return
	}
	page := &Page{
		ID: id, IncidentID: incidentID, ComponentID: componentID, Component: component,
		Detail: detail, State: PageOpen, Level: LevelOnCall,
		OpenedAt: now.Unix(), LevelAt: now.Unix(), Forms: map[string]Sent{},
	}
	page.log(now.Unix(), "opened", "", detail)
	d.Store.st.Pages = append(d.Store.st.Pages, page)
	d.Store.pruneLocked()
	d.saveOrLog()
	d.Store.mu.Unlock()
	d.sendLevel(ctx, id)
}

// saveOrLog must be called with the store locked.
func (d *Dispatcher) saveOrLog() {
	if err := d.Store.saveLocked(); err != nil {
		d.Log.Error("could not save the on-call state", "error", err)
	}
}

func (d *Dispatcher) pageLocked(id string) *Page {
	for _, p := range d.Store.st.Pages {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// sendLevel puts the page in front of its current level. A level that
// reaches nobody moves straight on: nobody to tell is not a reason to wait.
func (d *Dispatcher) sendLevel(ctx context.Context, pageID string) {
	team, err := d.Team(ctx)
	if err != nil {
		// Without the list nobody can be told. The next tick tries again,
		// and the attempt is on the page's record.
		d.Store.mu.Lock()
		if p := d.pageLocked(pageID); p != nil {
			p.log(d.now().Unix(), "team_unavailable", "", err.Error())
			d.saveOrLog()
		}
		d.Store.mu.Unlock()
		d.Log.Error("could not read the app's team", "app", d.AppID, "error", err)
		return
	}
	for {
		now := d.now()
		d.Store.mu.Lock()
		p := d.pageLocked(pageID)
		if p == nil || p.State != PageOpen {
			d.Store.mu.Unlock()
			return
		}
		level, snapshot := p.Level, *p
		prefs := d.Store.prefsLocked()
		plan := d.Store.st.Plan
		d.Store.mu.Unlock()
		plan, prefs = Effective(plan, prefs, d.accountStore())

		people := Recipients(level, team, plan, prefs, now)
		if level == LevelPlatform {
			people = d.platformLeads(ctx, pageID)
		}
		delivered := 0
		for _, m := range people {
			pref, ok := prefs[m.Sub]
			if !ok {
				pref = DefaultPreference(m.Sub)
			}
			if d.deliver(ctx, &snapshot, m, pref, level) {
				delivered++
			}
		}
		if delivered > 0 {
			return
		}
		if !d.advance(pageID, "nobody_reached") {
			return
		}
	}
}

// platformLeads is who the last level reaches. Without them the page ends
// as exhausted, and its record says why.
func (d *Dispatcher) platformLeads(ctx context.Context, pageID string) []Member {
	if d.Platform == nil {
		return nil
	}
	team, err := d.Platform(ctx)
	if err != nil {
		d.note(pageID, "team_unavailable", "", err.Error())
		return nil
	}
	var out []Member
	for _, m := range team {
		if m.Lead() {
			out = append(out, m)
		}
	}
	return out
}

// deliver sends the page to one person by each channel they chose and
// reports whether any of them went.
func (d *Dispatcher) deliver(ctx context.Context, p *Page, m Member, pref Preference, level int) bool {
	ok := false
	if pref.Wallet && d.Wallet != nil {
		formID, err := newID()
		if err == nil {
			var form string
			form, err = d.buildForm(formID, p)
			if err == nil {
				var status string
				status, err = d.Wallet.Form(ctx, m.Sub, form)
				if err == nil && status != "sent" {
					err = fmt.Errorf("the platform answered %q", status)
				}
			}
			if err == nil {
				sum := sha256.Sum256([]byte(form))
				d.record(p.ID, func(pg *Page) {
					pg.Forms[formID] = Sent{Sub: m.Sub, Level: level, Digest: hex.EncodeToString(sum[:])}
				})
				d.note(p.ID, "wallet_sent", m.Sub, "")
				ok = true
			}
		}
		if err != nil {
			d.note(p.ID, "wallet_failed", m.Sub, err.Error())
		}
	}
	if pref.Email != "" && d.Mail != nil {
		subject, body := d.pageEmail(p)
		if err := d.Mail(ctx, pref.Email, subject, body); err != nil {
			d.note(p.ID, "email_failed", m.Sub, err.Error())
		} else {
			d.note(p.ID, "email_sent", m.Sub, "")
			ok = true
		}
	}
	return ok
}

func (d *Dispatcher) record(pageID string, change func(*Page)) {
	d.Store.mu.Lock()
	defer d.Store.mu.Unlock()
	if p := d.pageLocked(pageID); p != nil {
		change(p)
		d.saveOrLog()
	}
}

func (d *Dispatcher) note(pageID, what, sub, detail string) {
	at := d.now().Unix()
	d.record(pageID, func(p *Page) { p.log(at, what, sub, detail) })
}

// advance moves a page to its next level, reporting whether there is one.
func (d *Dispatcher) advance(pageID, why string) bool {
	now := d.now().Unix()
	d.Store.mu.Lock()
	defer d.Store.mu.Unlock()
	p := d.pageLocked(pageID)
	if p == nil || p.State != PageOpen {
		return false
	}
	p.log(now, why, "", "")
	if p.Level+1 >= levelCount {
		p.State = PageExhausted
		p.ClosedAt = now
		p.log(now, "exhausted", "", "every level was tried and nobody took it")
		d.saveOrLog()
		d.Log.Error("nobody took a page", "app", d.AppID, "page", p.ID)
		return false
	}
	p.Level++
	p.LevelAt = now
	p.log(now, "escalated", "", "")
	d.saveOrLog()
	return true
}

// Tick escalates the pages whose level has had its time.
func (d *Dispatcher) Tick(ctx context.Context) {
	now := d.now()
	ack := d.EffectivePlan().Ack()
	d.Store.mu.Lock()
	var due []string
	for _, p := range d.Store.st.Pages {
		if p.State == PageOpen && now.Sub(time.Unix(p.LevelAt, 0)) >= ack {
			due = append(due, p.ID)
		}
	}
	d.Store.mu.Unlock()
	for _, id := range due {
		if d.advance(id, "no_answer") {
			d.sendLevel(ctx, id)
		}
	}
}

// ErrNoForm is an answer to a form this app did not send, or sent to
// somebody else.
var ErrNoForm = errors.New("no such form for this person")

// Answer records a person's answer to a form they were sent. digest is
// the one their signed answer commits to.
func (d *Dispatcher) Answer(ctx context.Context, formID, sub, digest, action string) error {
	now := d.now().Unix()
	d.Store.mu.Lock()
	var page *Page
	var sent Sent
	for _, p := range d.Store.st.Pages {
		if s, ok := p.Forms[formID]; ok {
			page, sent = p, s
			break
		}
	}
	if page == nil || sent.Sub != sub || sent.Digest != digest {
		d.Store.mu.Unlock()
		return ErrNoForm
	}
	escalate := false
	switch action {
	case ActionTake:
		if page.State == PageOpen {
			page.State, page.TakenBy, page.TakenAt = PageTaken, sub, now
			page.log(now, "taken", sub, "")
		}
	case ActionDecline:
		sent.Declined = true
		page.Forms[formID] = sent
		page.log(now, "declined", sub, "")
		escalate = page.State == PageOpen && allDeclined(page)
	default:
		d.Store.mu.Unlock()
		return fmt.Errorf("unknown action %q", action)
	}
	id := page.ID
	d.saveOrLog()
	d.Store.mu.Unlock()
	if escalate && d.advance(id, "all_declined") {
		d.sendLevel(ctx, id)
	}
	return nil
}

func allDeclined(p *Page) bool {
	any := false
	for _, s := range p.Forms {
		if s.Level != p.Level {
			continue
		}
		any = true
		if !s.Declined {
			return false
		}
	}
	return any
}

// Take lets a signed-in team member take a page from the portal.
func (d *Dispatcher) Take(pageID, sub string) error {
	now := d.now().Unix()
	d.Store.mu.Lock()
	defer d.Store.mu.Unlock()
	p := d.pageLocked(pageID)
	if p == nil {
		return errors.New("no such page")
	}
	if p.State != PageOpen && p.State != PageExhausted {
		return errors.New("this page is already " + p.State)
	}
	p.State, p.TakenBy, p.TakenAt, p.ClosedAt = PageTaken, sub, now, 0
	p.log(now, "taken", sub, "from the portal")
	return d.Store.saveLocked()
}

// Resolve closes the component's page and tells whoever was paged.
func (d *Dispatcher) Resolve(ctx context.Context, componentID string) {
	now := d.now().Unix()
	d.Store.mu.Lock()
	var page *Page
	for _, p := range d.Store.st.Pages {
		if p.ComponentID == componentID && (p.State == PageOpen || p.State == PageTaken || p.State == PageExhausted) {
			page = p
		}
	}
	if page == nil {
		d.Store.mu.Unlock()
		return
	}
	page.State, page.ClosedAt = PageResolved, now
	page.log(now, "resolved", "", "")
	told := map[string]bool{}
	for _, s := range page.Forms {
		told[s.Sub] = true
	}
	component, id := page.Component, page.ID
	prefs := d.Store.prefsLocked()
	d.saveOrLog()
	d.Store.mu.Unlock()
	prefs = d.mergedPrefs(prefs)

	title := fmt.Sprintf("%s has recovered", d.name())
	body := fmt.Sprintf("%s is answering again.", component)
	for sub := range told {
		if d.Wallet == nil {
			break
		}
		if _, err := d.Wallet.Message(ctx, sub, title, body); err != nil {
			d.note(id, "wallet_failed", sub, err.Error())
		}
	}
	for sub, p := range prefs {
		if p.Email == "" || d.Mail == nil || !told[sub] {
			continue
		}
		if err := d.Mail(ctx, p.Email, title, body+d.consoleLine()); err != nil {
			d.note(id, "email_failed", sub, err.Error())
		}
	}
}

// Test sends one harmless notice by each channel the person chose, so
// they can see that it reaches them before an outage does.
func (d *Dispatcher) Test(ctx context.Context, sub string) map[string]string {
	pref := d.Preference(sub)
	out := map[string]string{}
	title := "Test alert from " + d.name()
	body := "This is a test. Alerts for this app will reach you here."
	if pref.Wallet {
		switch {
		case d.Wallet == nil:
			out["wallet"] = "not available"
		default:
			status, err := d.Wallet.Message(ctx, sub, title, body)
			if err != nil {
				status = err.Error()
			}
			out["wallet"] = status
		}
	}
	if pref.Email != "" {
		switch {
		case d.Mail == nil:
			out["email"] = "not available"
		default:
			if err := d.Mail(ctx, pref.Email, title, body); err != nil {
				out["email"] = err.Error()
			} else {
				out["email"] = "sent"
			}
		}
	}
	return out
}

// Form actions.
const (
	ActionTake    = "take"
	ActionDecline = "decline"
)

// buildForm composes the decision the wallet draws, within the wallet's
// limits on length.
func (d *Dispatcher) buildForm(formID string, p *Page) (string, error) {
	fields := []map[string]string{
		{"label": "App", "value": clip(d.name(), 200)},
		{"label": "Component", "value": clip(p.Component, 200)},
		{"label": "Since", "value": time.Unix(p.OpenedAt, 0).UTC().Format("2 Jan 15:04 UTC")},
	}
	if p.Detail != "" {
		fields = append(fields, map[string]string{"label": "What failed", "value": clip(p.Detail, 200)})
	}
	raw, err := json.Marshal(map[string]any{
		"v": 1, "id": formID, "title": clip(d.name()+" is down", 80),
		"blocks": []any{
			map[string]any{"type": "text", "text": "Will you take this incident? Declining passes it on."},
			map[string]any{"type": "fields", "items": fields},
		},
		"actions": []map[string]string{
			{"id": ActionTake, "kind": "accept"},
			{"id": ActionDecline, "kind": "decline"},
		},
		"callback": d.Callback,
	})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (d *Dispatcher) pageEmail(p *Page) (subject, body string) {
	subject = clip(d.name()+" is down: "+p.Component, 180)
	var b strings.Builder
	fmt.Fprintf(&b, "%s has stopped answering.\n\n", d.name())
	fmt.Fprintf(&b, "Component: %s\nSince: %s\n", p.Component, time.Unix(p.OpenedAt, 0).UTC().Format(time.RFC1123))
	if p.Detail != "" {
		fmt.Fprintf(&b, "What failed: %s\n", p.Detail)
	}
	b.WriteString("\nTake it in your Privasys Wallet or in the portal, or it passes to the next person.")
	b.WriteString(d.consoleLine())
	return subject, b.String()
}

func (d *Dispatcher) consoleLine() string {
	if d.ConsoleURL == "" {
		return ""
	}
	return "\n\n" + d.ConsoleURL
}

// clip shortens text to n characters and removes what the wallet refuses:
// control characters and the invisible ones that can disguise text.
func clip(s string, n int) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0xad || r == 0x61c || r == 0xfeff ||
			(r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2060 && r <= 0x2069) {
			out = append(out, ' ')
			continue
		}
		out = append(out, r)
	}
	if len(out) > n {
		out = append(out[:n-1], '…')
	}
	return string(out)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// FormOpen reports whether this app is waiting on the answer to exactly
// this form. The wallet asks before it offers the buttons, over a channel
// it attested, so a form the platform made up is never answerable.
func (d *Dispatcher) FormOpen(formID, digest string) bool {
	d.Store.mu.Lock()
	defer d.Store.mu.Unlock()
	for _, p := range d.Store.st.Pages {
		s, ok := p.Forms[formID]
		if ok {
			return p.State == PageOpen && !s.Declined && s.Digest == digest
		}
	}
	return false
}
