// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/keys"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/probe"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
	"github.com/Privasys/container-app-service-monitoring/internal/tenancy"
)

const (
	appA = "0f2c1d9e-3b4a-4c5d-8e6f-7a8b9c0d1e2f"
	appB = "11111111-2222-4333-8444-555555555555"
	keyA = "0f2c1d9e3b4a4c5d8e6f7a8b9c0d1e2f"
	keyB = "11111111222243338444555555555555"
)

func newAppServer(t *testing.T) (*httptest.Server, *tenancy.Host, *int) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	material, err := keys.Load(filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.Open(filepath.Join(dir, "secrets"), material.Master)
	if err != nil {
		t.Fatal(err)
	}
	ck, source, err := material.CommitmentKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "record"), ck)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	mon := core.New(st, material, vault, journey.NewAllowlist(), core.Options{
		Name: "test", Vantage: "test", CommitmentSource: source,
	})
	if _, err := mon.Configure(auth.System("privasys-platform"), core.ConfigureRequest{Tenant: "privasys-platform"}, ""); err != nil {
		t.Fatal(err)
	}
	roles, err := auth.NewDefaultModel()
	if err != nil {
		t.Fatal(err)
	}
	appRoles, err := auth.NewAppModel()
	if err != nil {
		t.Fatal(err)
	}
	host := tenancy.New(tenancy.Options{
		Dir: filepath.Join(dir, "tenants"), Material: material,
		Base: core.Options{Name: "test", Vantage: "test"},
	}, log)
	ctx, cancel := context.WithCancel(context.Background())
	if err := host.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); host.Close() })

	s := NewServer(log, mon, auth.DevVerifier{}, roles, probe.New(mon, log))
	s.Tenants, s.AppRoles = host, appRoles
	changed := 0
	s.TenantsChanged = func() { changed++ }
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, host, &changed
}

func call(t *testing.T, srv *httptest.Server, method, path, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res.StatusCode, body
}

func token(sub string, roles ...string) string {
	t := "dev:" + sub + ":" + sub + ":"
	for i, r := range roles {
		if i > 0 {
			t += ","
		}
		t += r
	}
	return t
}

func TestAppRoutesServeEachAppItsOwnMonitor(t *testing.T) {
	srv, host, changed := newAppServer(t)
	ownerA := token("ada", "privasys-platform:app:"+keyA+":owner")
	memberA := token("bo", "privasys-platform:app:"+keyA+":support-member")
	ownerB := token("cy", "privasys-platform:app:"+keyB+":owner")
	admin := token("privasys", auth.OIDCPlatformAdmin)

	// Before monitoring is enabled the app's own team is told so; a
	// stranger is refused before learning anything about the app.
	if code, _ := call(t, srv, "GET", "/api/v1/apps/"+appA+"/services", ownerA); code != http.StatusNotFound {
		t.Fatalf("an app without a monitor answered %d", code)
	}
	if code, _ := call(t, srv, "GET", "/api/v1/apps/"+appA+"/services", ownerB); code != http.StatusUnauthorized {
		t.Fatalf("another app's owner got %d on app A", code)
	}
	if code, _ := call(t, srv, "GET", "/api/v1/apps/not-an-app/services", admin); code != http.StatusBadRequest {
		t.Fatalf("a malformed app id answered %d", code)
	}

	// A support member may not turn monitoring on; the owner may.
	if code, _ := call(t, srv, "POST", "/api/v1/apps/"+appA+"/enable", memberA); code != http.StatusForbidden {
		t.Fatalf("a member enabled monitoring: %d", code)
	}
	code, body := call(t, srv, "POST", "/api/v1/apps/"+appA+"/enable", ownerA)
	if code != http.StatusOK || body["created"] != true || body["app"] != appA {
		t.Fatalf("enable: %d %v", code, body)
	}
	if code, body := call(t, srv, "POST", "/api/v1/apps/"+appA+"/enable", ownerA); code != http.StatusOK || body["created"] != false {
		t.Fatalf("enabling twice: %d %v", code, body)
	}
	if *changed != 1 {
		t.Fatalf("the attested summary should be republished once, was %d times", *changed)
	}
	if _, body := call(t, srv, "POST", "/api/v1/apps/"+appB+"/enable", ownerB); body["created"] != true {
		t.Fatalf("enable B: %v", body)
	}

	// What app A's team adds is visible to app A only.
	a, err := host.Get(appA)
	if err != nil {
		t.Fatal(err)
	}
	p := auth.System(a.ID)
	p.Grant(auth.PermModel)
	if _, _, err := a.Mon.UpsertService(p, model.Service{Name: "Checkout", Timezone: "UTC"}, "Add the service"); err != nil {
		t.Fatal(err)
	}
	count := func(path, tok string) int {
		code, body := call(t, srv, "GET", path, tok)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", path, code, body)
		}
		list, _ := body["services"].([]any)
		return len(list)
	}
	if n := count("/api/v1/apps/"+appA+"/services", memberA); n != 1 {
		t.Fatalf("app A's member sees %d services", n)
	}
	if n := count("/api/v1/apps/"+appB+"/services", ownerB); n != 0 {
		t.Fatalf("app B sees app A's services: %d", n)
	}
	if n := count("/api/v1/apps/"+appB+"/services", admin); n != 0 {
		t.Fatalf("the platform admin reading app B sees %d services", n)
	}

	// The caller is resolved per app.
	if code, body := call(t, srv, "GET", "/api/v1/apps/"+appA+"/me", memberA); code != http.StatusOK || body["acting"] != auth.RoleAppMember {
		t.Fatalf("me: %d %v", code, body)
	}

	// Only a platform admin lists the apps or removes one.
	if code, _ := call(t, srv, "GET", "/api/v1/apps", ownerA); code != http.StatusUnauthorized {
		t.Fatalf("an app owner listed every app: %d", code)
	}
	if code, body := call(t, srv, "GET", "/api/v1/apps", admin); code != http.StatusOK || len(body["apps"].([]any)) != 2 {
		t.Fatalf("list: %d %v", code, body)
	}
	if code, _ := call(t, srv, "DELETE", "/api/v1/apps/"+appA, ownerA); code != http.StatusForbidden {
		t.Fatalf("an app owner erased the app's history: %d", code)
	}
	if code, _ := call(t, srv, "DELETE", "/api/v1/apps/"+appA, admin); code != http.StatusNoContent {
		t.Fatalf("remove: %d", code)
	}
	if code, _ := call(t, srv, "GET", "/api/v1/apps/"+appA+"/services", ownerA); code != http.StatusNotFound {
		t.Fatalf("a removed app still answers: %d", code)
	}

	// The instance's own routes are unchanged, and app roles do not
	// reach them.
	if code, _ := call(t, srv, "GET", "/api/v1/services", ownerB); code != http.StatusUnauthorized {
		t.Fatalf("an app owner reached the instance's own record: %d", code)
	}
}

func TestAnAppsPublicPageAnswersOnlyOnceItsTeamMakesItPublic(t *testing.T) {
	srv, host, _ := newAppServer(t)
	a, err := host.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.EnsureStatus(tenancy.App{ID: appA, Name: "checkout", Hostname: "checkout.apps.example"}); err != nil {
		t.Fatal(err)
	}
	get := func(path string) int {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	paths := []string{
		"/apps/" + appA + "/",
		"/apps/" + appA + "/status.js",
		"/api/v1/public/apps/" + appA + "/status",
		"/api/v1/public/apps/" + appA + "/checkpoints",
		"/api/v2/apps/" + appA + "/summary.json",
	}
	// Private by default: indistinguishable from an app with no monitor.
	for _, p := range paths {
		if code := get(p); code != http.StatusNotFound {
			t.Fatalf("%s answered %d while the app's status is private", p, code)
		}
	}
	if code := get("/api/v1/public/apps/" + appB + "/status"); code != http.StatusNotFound {
		t.Fatalf("an app with no monitor answered %d", code)
	}

	// The team makes it public.
	p := auth.System(a.ID)
	p.Grant(auth.PermModel)
	svc, _ := a.Mon.Service(tenancy.StatusServiceID)
	svc.Visibility = model.VisibilityPublic
	if _, _, err := a.Mon.UpsertService(p, *svc, "Publish the status page"); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if code := get(p); code != http.StatusOK {
			t.Fatalf("%s answered %d once public", p, code)
		}
	}
	code, body := call(t, srv, "GET", "/api/v1/public/apps/"+appA+"/status", "")
	if code != http.StatusOK || body["service"] == nil {
		t.Fatalf("status: %d %v", code, body)
	}
	if res, _ := http.Get(srv.URL + "/apps/" + appA); res != nil && res.Request.URL.Path != "/apps/"+appA+"/" {
		t.Fatalf("the page without a trailing slash did not move to it: %s", res.Request.URL.Path)
	}
}

func TestTheLandingPageListsOnlyPublishedApps(t *testing.T) {
	srv, host, _ := newAppServer(t)
	for _, id := range []string{appA, appB} {
		tn, err := host.Ensure(id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tn.EnsureStatus(tenancy.App{ID: id, Name: "app-" + id[:4], DisplayName: "App " + id[:4], Hostname: id[:4] + ".apps.example"}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("the landing page: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	list := func() []any {
		code, body := call(t, srv, "GET", "/api/v1/public/apps", "")
		if code != http.StatusOK {
			t.Fatalf("index: %d", code)
		}
		apps, _ := body["apps"].([]any)
		return apps
	}
	if n := len(list()); n != 0 {
		t.Fatalf("the index lists %d unpublished apps", n)
	}
	a, _ := host.Get(appA)
	p := auth.System(a.ID)
	p.Grant(auth.PermModel)
	svc, _ := a.Mon.Service(tenancy.StatusServiceID)
	svc.Visibility = model.VisibilityPublic
	if _, _, err := a.Mon.UpsertService(p, *svc, "Publish"); err != nil {
		t.Fatal(err)
	}
	apps := list()
	if len(apps) != 1 {
		t.Fatalf("expected app A only, got %v", apps)
	}
	e := apps[0].(map[string]any)
	if e["app"] != appA || e["page"] != "/apps/"+appA+"/" || e["service"] != "App 0f2c" {
		t.Fatalf("index entry: %v", e)
	}
}

func TestTheTokenRidesXAppAuthOverASealedSession(t *testing.T) {
	srv, host, _ := newAppServer(t)
	if _, err := host.Ensure(appA); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/apps/"+appA+"/me", nil)
	// What the runtime hands the app inside a sealed session.
	req.Header.Set("Authorization", "PrivasysSession 0123456789abcdef")
	req.Header.Set("X-App-Auth", token("ada", "privasys-platform:app:"+keyA+":owner"))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a sealed-session call with X-App-Auth answered %d", res.StatusCode)
	}
}
