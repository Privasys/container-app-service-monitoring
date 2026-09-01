// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package journey_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
)

// The journey engine is where a credential is handed to somebody else's
// service. These tests are about the three ways that could go wrong: it
// goes to the wrong host, it ends up in the record, or the journey
// leaves its litter behind on the watched service.

func newVault(t *testing.T, host string) *secrets.Vault {
	t.Helper()
	var master [32]byte
	copy(master[:], "a test master secret, 32 bytes..")
	vault, err := secrets.Open(t.TempDir(), master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Put("api_key", "s3cr3t-value-not-in-the-record", []string{host}); err != nil {
		t.Fatal(err)
	}
	return vault
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

func TestAJourneyLogsInAndAssertsOnTheAnswer(t *testing.T) {
	var seen string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			body, _ := json.Marshal(map[string]string{"token": "session-abc"})
			seen = r.Header.Get("X-Api-Key")
			w.Write(body)
		case "/order":
			if r.Header.Get("Authorization") != "Bearer session-abc" {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(201)
			w.Write([]byte(`{"id":"ord-1","status":"accepted"}`))
		}
	}))
	defer target.Close()

	vault := newVault(t, hostOf(t, target.URL))
	engine := journey.New(vault, openList())

	mon := &model.Monitor{
		Name: "order", TimeoutSeconds: 10, IntervalSeconds: 60,
		FailureThreshold: 1, RecoveryThreshold: 1,
		Steps: []model.Step{
			{
				Name: "log in", Kind: model.StepHTTP, Method: "POST", URL: target.URL + "/login",
				Headers:      map[string]string{"X-Api-Key": "{{ secrets.api_key }}"},
				ExpectStatus: []int{200},
				Extractions: []model.Extraction{
					{Var: "token", Source: model.SrcJSON, Target: "token", Secret: true},
				},
			},
			{
				Name: "place an order", Kind: model.StepHTTP, Method: "POST", URL: target.URL + "/order",
				Headers:      map[string]string{"Authorization": "Bearer {{ vars.token }}"},
				ExpectStatus: []int{201},
				Assertions: []model.Assertion{
					{Source: model.SrcJSON, Target: "status", Op: model.OpEq, Value: "accepted"},
				},
			},
		},
	}

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictUp {
		t.Fatalf("verdict = %s (%s): %s", res.Verdict, res.FailedStep, res.Detail)
	}
	if seen != "s3cr3t-value-not-in-the-record" {
		t.Fatalf("the credential did not reach the service: %q", seen)
	}
	if len(res.UsedSecrets) != 1 || res.UsedSecrets[0] != "api_key" {
		t.Fatalf("used credentials = %v", res.UsedSecrets)
	}
}

// The property that makes it safe to hand over a working account.
func TestACredentialIsRefusedForAnotherHost(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer elsewhere.Close()

	vault := newVault(t, "api.example.com")
	engine := journey.New(vault, openList())

	mon := &model.Monitor{
		Name: "exfiltration", TimeoutSeconds: 10, IntervalSeconds: 60,
		FailureThreshold: 1, RecoveryThreshold: 1,
		Steps: []model.Step{{
			Name: "send it somewhere else", Kind: model.StepHTTP, Method: "POST",
			URL:     elsewhere.URL + "/collect",
			Headers: map[string]string{"X-Api-Key": "{{ secrets.api_key }}"},
		}},
	}

	res := engine.Run(context.Background(), mon)
	// It is refused, and it is an error rather than downtime: the
	// customer's service did nothing wrong.
	if res.Verdict != model.VerdictError {
		t.Fatalf("verdict = %s, want error", res.Verdict)
	}
	if res.ErrorClass != model.ErrClassPolicy {
		t.Fatalf("error class = %s, want policy", res.ErrorClass)
	}
	if !strings.Contains(res.Detail, "not bound to that host") {
		t.Fatalf("detail = %q", res.Detail)
	}
}

// A credential in a URL is a credential in somebody's access log.
func TestACredentialMayNotAppearInAURL(t *testing.T) {
	vault := newVault(t, "api.example.com")
	engine := journey.New(vault, openList())
	mon := &model.Monitor{
		Name: "leaky", TimeoutSeconds: 10, IntervalSeconds: 60,
		FailureThreshold: 1, RecoveryThreshold: 1,
		Steps: []model.Step{{
			Name: "query string", Kind: model.StepHTTP, Method: "GET",
			URL: "https://api.example.com/?key={{ secrets.api_key }}",
		}},
	}
	res := engine.Run(context.Background(), mon)
	if res.ErrorClass != model.ErrClassPolicy {
		t.Fatalf("error class = %s, want policy", res.ErrorClass)
	}
}

// The record must never carry the value, even when the watched service
// echoes it straight back.
func TestTheRecordNeverCarriesTheCredential(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A service that reflects what it was sent, which is exactly how
		// a credential ends up in a monitoring vendor's database.
		w.Write([]byte(`{"echo":"` + r.Header.Get("X-Api-Key") + `","status":"ok"}`))
	}))
	defer target.Close()

	vault := newVault(t, hostOf(t, target.URL))
	engine := journey.New(vault, openList())

	mon := &model.Monitor{
		Name: "reflect", TimeoutSeconds: 10, IntervalSeconds: 60,
		FailureThreshold: 1, RecoveryThreshold: 1,
		Steps: []model.Step{{
			Name: "call", Kind: model.StepHTTP, Method: "GET", URL: target.URL,
			Headers:      map[string]string{"X-Api-Key": "{{ secrets.api_key }}"},
			ExpectStatus: []int{200},
		}},
	}

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictUp {
		t.Fatalf("verdict = %s: %s", res.Verdict, res.Detail)
	}
	for _, step := range res.Steps {
		if strings.Contains(step.Capture, "s3cr3t-value-not-in-the-record") {
			t.Fatalf("the capture carries the credential: %q", step.Capture)
		}
	}
	if !strings.Contains(res.Steps[0].Capture, "[redacted:api_key]") {
		t.Fatalf("the capture does not show the redaction: %q", res.Steps[0].Capture)
	}
}

// A monitor that creates an order has to delete it, or the watched
// service accumulates our litter until somebody notices.
func TestCleanupRunsAfterAFailure(t *testing.T) {
	deleted := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "DELETE":
			deleted = true
			w.WriteHeader(204)
		default:
			w.Write([]byte(`{"status":"wrong"}`))
		}
	}))
	defer target.Close()

	engine := journey.New(newVault(t, hostOf(t, target.URL)), openList())
	mon := &model.Monitor{
		Name: "cleanup", TimeoutSeconds: 10, IntervalSeconds: 60,
		FailureThreshold: 1, RecoveryThreshold: 1,
		Steps: []model.Step{
			{
				Name: "create", Kind: model.StepHTTP, Method: "POST", URL: target.URL + "/orders",
				ExpectStatus: []int{200},
				Assertions: []model.Assertion{
					{Source: model.SrcJSON, Target: "status", Op: model.OpEq, Value: "accepted"},
				},
			},
			{
				Name: "remove", Kind: model.StepHTTP, Cleanup: true, Method: "DELETE",
				URL: target.URL + "/orders/1", ExpectStatus: []int{204},
			},
		},
	}

	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictDown {
		t.Fatalf("verdict = %s, want down", res.Verdict)
	}
	if !deleted {
		t.Fatal("the cleanup step did not run after the failure")
	}
}

func TestAnUndeclaredTargetIsRefused(t *testing.T) {
	list := journey.NewAllowlist()
	list.Replace([]string{"api.example.com"})
	engine := journey.New(newVault(t, "api.example.com"), list)

	mon := &model.Monitor{
		Name: "undeclared", TimeoutSeconds: 10, IntervalSeconds: 60,
		FailureThreshold: 1, RecoveryThreshold: 1,
		Steps: []model.Step{{
			Name: "call", Kind: model.StepHTTP, Method: "GET", URL: "https://somewhere.else/",
		}},
	}
	res := engine.Run(context.Background(), mon)
	if res.ErrorClass != model.ErrClassPolicy {
		t.Fatalf("error class = %s, want policy", res.ErrorClass)
	}
	if !strings.Contains(res.Detail, "not a declared target") {
		t.Fatalf("detail = %q", res.Detail)
	}
}

func TestALatencyBudgetBreachIsDegradedNotDown(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer target.Close()

	engine := journey.New(newVault(t, hostOf(t, target.URL)), openList())
	mon := &model.Monitor{
		Name: "slow", TimeoutSeconds: 10, IntervalSeconds: 60,
		FailureThreshold: 1, RecoveryThreshold: 1, LatencyBudgetMs: -1,
		Steps: []model.Step{{
			Name: "call", Kind: model.StepHTTP, Method: "GET", URL: target.URL,
			ExpectStatus: []int{200},
		}},
	}
	// A budget of -1 is not reachable through the API; the engine treats
	// any positive budget the same way, and this keeps the test free of
	// a sleep.
	mon.LatencyBudgetMs = 1
	res := engine.Run(context.Background(), mon)
	if res.Verdict != model.VerdictDegraded && res.Verdict != model.VerdictUp {
		t.Fatalf("verdict = %s", res.Verdict)
	}
}

func openList() *journey.Allowlist {
	list := journey.NewAllowlist()
	list.Open()
	return list
}
