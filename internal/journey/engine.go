// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package journey executes a monitor's steps against the watched
// service.
//
// A journey is what separates this from a ping. It logs in with a real
// least-privilege account, does the thing the SLA is about, checks that
// the answer is right rather than merely present, and cleans up after
// itself. That is only safe to run because of where it runs: the
// credential is sealed to the measurement of this build, and the
// engine refuses to send it anywhere the credential was not bound to.
//
// The engine draws one distinction the rest of the system depends on.
// A failure of the watched service (a refused connection, a 500, a
// broken assertion) is downtime. A failure of the monitor itself (a
// missing credential, an undeclared target, a template that does not
// resolve) is not downtime: it is recorded as an error, counted against
// monitoring coverage, and never charged to the customer's service.
package journey

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
)

// Limits on what one journey may read and keep.
const (
	// MaxBody is how much of a response the engine reads. Assertions run
	// over what it read; a body larger than this is truncated, and the
	// step says so.
	MaxBody = 256 << 10
	// MaxCapture is how much of a response is kept in the record. Enough
	// for a responder to see what the service said, small enough that a
	// year of incidents is not a data lake.
	MaxCapture = 1024
	// MaxRedirects a journey will follow when a step opts in.
	MaxRedirects = 5
)

// Engine runs journeys.
type Engine struct {
	// Secrets resolves credentials, and refuses to resolve one for a
	// host it is not bound to.
	Secrets SecretResolver
	// Egress decides which hosts this instance may contact at all.
	Egress *Allowlist
	// Now is the clock, injectable for tests.
	Now func() time.Time
	// UserAgent identifies the monitor to the watched service, so an
	// operator reading their own access log can tell synthetic traffic
	// from real users.
	UserAgent string
}

// Result is one execution of a journey.
type Result struct {
	Verdict     string
	DurationMs  int
	FailedStep  string
	ErrorClass  string
	Detail      string
	Steps       []model.StepResult
	Vars        map[string]string
	UsedSecrets []string
}

// New returns an engine.
func New(resolver SecretResolver, egress *Allowlist) *Engine {
	return &Engine{
		Secrets:   resolver,
		Egress:    egress,
		Now:       time.Now,
		UserAgent: "Privasys-Service-Monitoring/1.0 (+https://privasys.org)",
	}
}

// Run executes a monitor's journey once.
func (e *Engine) Run(ctx context.Context, m *model.Monitor) Result {
	start := e.now()
	red := secrets.NewRedactor()
	vars := map[string]string{}
	used := map[string]bool{}

	res := Result{Verdict: model.VerdictUp, Vars: vars}

	timeout := time.Duration(m.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = model.DefaultTimeout * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	failed := false
	for i := range m.Steps {
		s := &m.Steps[i]
		if s.Cleanup {
			continue
		}
		sr, fail := e.step(runCtx, s, vars, red, used)
		res.Steps = append(res.Steps, sr)
		if fail != nil {
			failed = true
			res.FailedStep = s.Name
			res.ErrorClass = fail.class
			res.Detail = red.Redact(fail.detail)
			break
		}
	}

	// Cleanup runs whether or not the journey succeeded. A monitor that
	// creates an order and then fails an assertion must still delete the
	// order, or the watched service accumulates our litter until someone
	// notices. A cleanup step that fails is reported and does not, on
	// its own, mark the service down: the customer's service answered,
	// our housekeeping did not.
	cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancelCleanup()
	for i := range m.Steps {
		s := &m.Steps[i]
		if !s.Cleanup {
			continue
		}
		sr, fail := e.step(cleanupCtx, s, vars, red, used)
		if fail != nil {
			sr.Detail = "cleanup: " + red.Redact(fail.detail)
		}
		res.Steps = append(res.Steps, sr)
	}

	res.DurationMs = int(e.now().Sub(start) / time.Millisecond)

	switch {
	case failed:
		res.Verdict = verdictFor(res.ErrorClass)
	case m.LatencyBudgetMs > 0 && res.DurationMs > m.LatencyBudgetMs:
		res.Verdict = model.VerdictDegraded
		res.Detail = fmt.Sprintf("the journey completed in %dms, over the %dms budget",
			res.DurationMs, m.LatencyBudgetMs)
	}

	// Last line of defence. Every capture and detail was redacted as it
	// was produced; this asserts it worked. A leak turns the reading
	// into an error with no captures rather than writing a credential
	// into the record, which is the one outcome that must not happen.
	if leaked(red, &res) {
		res.Verdict = model.VerdictError
		res.ErrorClass = model.ErrClassRedaction
		res.Detail = "a credential appeared in the captured output; the capture was discarded"
		for i := range res.Steps {
			res.Steps[i].Capture = ""
			res.Steps[i].Detail = ""
		}
	}

	res.UsedSecrets = make([]string, 0, len(used))
	for name := range used {
		res.UsedSecrets = append(res.UsedSecrets, name)
	}
	sort.Strings(res.UsedSecrets)
	return res
}

// stepFailure carries why a step failed and whose fault it is.
type stepFailure struct {
	class  string
	detail string
}

func (e *Engine) step(ctx context.Context, s *model.Step, vars map[string]string,
	red *secrets.Redactor, used map[string]bool) (model.StepResult, *stepFailure) {

	begin := e.now()
	sr := model.StepResult{Name: s.Name, Kind: s.Kind, OK: true}
	finish := func() { sr.DurationMs = int(e.now().Sub(begin) / time.Millisecond) }

	switch s.Kind {
	case model.StepSleep:
		select {
		case <-time.After(time.Duration(s.SleepMs) * time.Millisecond):
		case <-ctx.Done():
			finish()
			sr.OK = false
			return sr, &stepFailure{class: model.ErrClassTimeout, detail: "the journey ran out of time while waiting"}
		}
		finish()
		return sr, nil

	case model.StepAssert, model.StepExtract:
		// Both operate on the last observation, which the engine keeps in
		// vars: an assert or extract step with no request before it has
		// nothing to read, and that is a definition error.
		obs := &observation{vars: vars, status: intVar(vars, "__status"), latency: intVar(vars, "__latency_ms"),
			body: vars["__body"], headers: headerVars(vars)}
		if fail := e.checks(s, obs, vars, sr.Name); fail != nil {
			finish()
			sr.OK = false
			sr.Detail = red.Redact(fail.detail)
			return sr, fail
		}
		finish()
		return sr, nil

	case model.StepHTTP:
		return e.request(ctx, s, vars, red, used, sr, begin)
	}

	finish()
	sr.OK = false
	return sr, &stepFailure{class: model.ErrClassPolicy, detail: "unknown step kind " + s.Kind}
}

func (e *Engine) request(ctx context.Context, s *model.Step, vars map[string]string,
	red *secrets.Redactor, used map[string]bool, sr model.StepResult, begin time.Time) (model.StepResult, *stepFailure) {

	finish := func() { sr.DurationMs = int(e.now().Sub(begin) / time.Millisecond) }
	fail := func(class, detail string) (model.StepResult, *stepFailure) {
		finish()
		sr.OK = false
		sr.Detail = red.Redact(detail)
		return sr, &stepFailure{class: class, detail: detail}
	}

	// The URL is rendered without access to credentials. A URL travels
	// through proxies, caches and the service's own access log, so a
	// credential in one is a credential published.
	if referencesSecret(s.URL) {
		return fail(model.ErrClassPolicy, ErrSecretInURL.Error())
	}
	urlScope := &scope{vars: vars}
	target, err := urlScope.render(s.URL)
	if err != nil {
		return fail(model.ErrClassPolicy, err.Error())
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return fail(model.ErrClassPolicy, fmt.Sprintf("the resolved URL is not valid: %v", err))
	}
	if e.Egress != nil {
		if err := e.Egress.Check(parsed.Host); err != nil {
			return fail(model.ErrClassPolicy, err.Error())
		}
	}

	// Headers and body may carry credentials, resolved for this host and
	// no other. The vault performs the binding check itself, so a
	// repointed monitor is refused here rather than reviewed later.
	body := &scope{vars: vars, secrets: e.Secrets, host: parsed.Host}
	renderedBody, err := body.render(s.Body)
	if err != nil {
		return fail(classForResolve(err), err.Error())
	}
	headers := make(map[string]string, len(s.Headers))
	for k, v := range s.Headers {
		rv, err := body.render(v)
		if err != nil {
			return fail(classForResolve(err), err.Error())
		}
		headers[k] = rv
	}
	for name, value := range body.used {
		red.Add(name, value)
		used[name] = true
	}

	method := strings.ToUpper(s.Method)
	var reader io.Reader
	if renderedBody != "" {
		reader = strings.NewReader(renderedBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return fail(model.ErrClassPolicy, err.Error())
	}
	req.Header.Set("User-Agent", e.UserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client(s.FollowRedirects).Do(req)
	if err != nil {
		return fail(classifyTransport(ctx, err), transportDetail(err))
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return fail(classifyTransport(ctx, readErr), "the response could not be read: "+readErr.Error())
	}
	sr.Status = resp.StatusCode
	finish()

	obs := &observation{
		status: resp.StatusCode, latency: sr.DurationMs,
		headers: flatten(resp.Header), body: string(raw), vars: vars,
	}
	// The observation is what later assert and extract steps read.
	vars["__status"] = fmt.Sprint(resp.StatusCode)
	vars["__latency_ms"] = fmt.Sprint(sr.DurationMs)
	vars["__body"] = obs.body
	setHeaderVars(vars, obs.headers)

	sr.Capture = red.Redact(capture(obs.body))

	if len(s.ExpectStatus) > 0 && !contains(s.ExpectStatus, resp.StatusCode) {
		return fail(model.ErrClassStatus,
			fmt.Sprintf("the service answered %d, expected %s", resp.StatusCode, statusList(s.ExpectStatus)))
	}
	if len(s.ExpectStatus) == 0 && resp.StatusCode >= 500 {
		return fail(model.ErrClassStatus, fmt.Sprintf("the service answered %d", resp.StatusCode))
	}
	if f := e.checks(s, obs, vars, sr.Name); f != nil {
		sr.OK = false
		sr.Detail = red.Redact(f.detail)
		return sr, f
	}
	// A secret-marked extraction (a session token, say) is redacted for
	// the rest of the journey exactly like a configured credential.
	for _, ex := range s.Extractions {
		if ex.Secret {
			red.Add(ex.Var, vars[ex.Var])
		}
	}
	sr.Capture = red.Redact(sr.Capture)
	return sr, nil
}

// checks runs a step's extractions and then its assertions.
//
// An assertion's target and expected value are templated, so a journey
// can require that the order it reads back is the order it placed
// rather than merely that some order came back. They are resolved
// against variables only: a comparison against a credential would put
// that credential into the failure message, and failure messages are
// what end up in an incident timeline a customer reads.
func (e *Engine) checks(s *model.Step, obs *observation, vars map[string]string, _ string) *stepFailure {
	for _, ex := range s.Extractions {
		value, ok := extract(obs, ex)
		if !ok {
			return &stepFailure{class: model.ErrClassAssertion,
				detail: fmt.Sprintf("%s could not be extracted from the response", ex.Var)}
		}
		vars[ex.Var] = value
	}
	sc := &scope{vars: vars}
	for _, a := range s.Assertions {
		resolved := a
		if referencesSecret(a.Value) || referencesSecret(a.Target) {
			return &stepFailure{class: model.ErrClassPolicy,
				detail: "an assertion may not reference a credential"}
		}
		var err error
		if resolved.Value, err = sc.render(a.Value); err != nil {
			return &stepFailure{class: model.ErrClassPolicy, detail: err.Error()}
		}
		if resolved.Target, err = sc.render(a.Target); err != nil {
			return &stepFailure{class: model.ErrClassPolicy, detail: err.Error()}
		}
		if reason := obs.evaluate(resolved); reason != "" {
			return &stepFailure{class: model.ErrClassAssertion, detail: reason}
		}
	}
	return nil
}

func extract(obs *observation, ex model.Extraction) (string, bool) {
	switch ex.Source {
	case model.SrcStatus:
		return fmt.Sprint(obs.status), obs.status > 0
	case model.SrcHeader:
		v, ok := obs.headers[strings.ToLower(ex.Target)]
		return v, ok
	case model.SrcBody:
		return obs.body, true
	case model.SrcJSON:
		doc, ok := obs.json()
		if !ok {
			return "", false
		}
		v, found := lookup(doc, ex.Target)
		if !found {
			return "", false
		}
		return stringify(v), true
	}
	return "", false
}

// client builds a transport for one request.
//
// Proxies are ignored: a monitor that measures through an unattested
// intermediary is measuring the intermediary. Redirects are refused
// unless the step asked for them, and even then every hop is checked
// against the egress allowlist, so a redirect cannot walk a request
// (and its Authorization header) to a host nobody declared.
func (e *Engine) client(followRedirects bool) *http.Client {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     true,
	}
	c := &http.Client{Transport: transport}
	if !followRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", MaxRedirects)
		}
		if e.Egress != nil {
			return e.Egress.Check(req.URL.Host)
		}
		return nil
	}
	return c
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// verdictFor decides whose failure it was. This mapping is the honesty
// of the whole record: a monitor that charges its own misconfiguration
// to the customer's availability is worse than no monitor.
func verdictFor(class string) string {
	switch class {
	case model.ErrClassPolicy, model.ErrClassInternal, model.ErrClassRedaction:
		return model.VerdictError
	default:
		return model.VerdictDown
	}
}

// classForResolve maps a template resolution failure. A refused
// credential binding is a policy failure, not the service's fault.
func classForResolve(err error) string {
	if errors.Is(err, secrets.ErrBinding) || errors.Is(err, secrets.ErrUnknown) {
		return model.ErrClassPolicy
	}
	return model.ErrClassPolicy
}

func classifyTransport(ctx context.Context, err error) string {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return model.ErrClassTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.ErrClassTimeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return model.ErrClassDNS
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return model.ErrClassTLS
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return model.ErrClassTLS
	}
	if strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "certificate") {
		return model.ErrClassTLS
	}
	return model.ErrClassConnect
}

// transportDetail turns a Go transport error into something a customer
// can read in an incident timeline.
func transportDetail(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i > 0 && strings.HasPrefix(msg, "Get \"") {
		msg = msg[i+2:]
	}
	switch {
	case strings.Contains(msg, "connection refused"):
		return "the connection was refused"
	case strings.Contains(msg, "no such host"):
		return "the hostname does not resolve"
	case strings.Contains(msg, "context deadline exceeded"), strings.Contains(msg, "Client.Timeout"):
		return "the service did not answer within the timeout"
	case strings.Contains(msg, "certificate"):
		return "the TLS certificate was not accepted: " + msg
	}
	return msg
}

func capture(body string) string {
	body = strings.TrimSpace(body)
	if len(body) <= MaxCapture {
		return body
	}
	return body[:MaxCapture] + "... (truncated)"
}

func leaked(red *secrets.Redactor, res *Result) bool {
	if red.Empty() {
		return false
	}
	if red.Leaks(res.Detail) {
		return true
	}
	for _, s := range res.Steps {
		if red.Leaks(s.Capture) || red.Leaks(s.Detail) {
			return true
		}
	}
	return false
}

func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[strings.ToLower(k)] = v[0]
		}
	}
	return out
}

// Response headers are carried between steps in the variable map under
// a reserved prefix, so an assert step after a request can read them
// without the engine holding a second piece of state.
const headerVarPrefix = "__header."

func setHeaderVars(vars map[string]string, headers map[string]string) {
	for k := range vars {
		if strings.HasPrefix(k, headerVarPrefix) {
			delete(vars, k)
		}
	}
	for k, v := range headers {
		vars[headerVarPrefix+k] = v
	}
}

func headerVars(vars map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range vars {
		if strings.HasPrefix(k, headerVarPrefix) {
			out[strings.TrimPrefix(k, headerVarPrefix)] = v
		}
	}
	return out
}

func intVar(vars map[string]string, key string) int {
	var n int
	fmt.Sscanf(vars[key], "%d", &n)
	return n
}

func contains(list []int, v int) bool {
	for _, n := range list {
		if n == v {
			return true
		}
	}
	return false
}

func statusList(list []int) string {
	parts := make([]string, len(list))
	for i, n := range list {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, " or ")
}
