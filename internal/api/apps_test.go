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
	srv, host, changed, _ := buildAppServer(t)
	return srv, host, changed
}

func newOnCallServer(t *testing.T) (*httptest.Server, *tenancy.Host, *Server) {
	t.Helper()
	srv, host, _, s := buildAppServer(t)
	return srv, host, s
}

func buildAppServer(t *testing.T) (*httptest.Server, *tenancy.Host, *int, *Server) {
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
	return srv, host, &changed, s
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

// The accounts the directory tests use: the monitor's own, and a customer.
const (
	homeApp    = "99999999-8888-4777-8666-555555555555"
	ourAccount = "aaaaaaaa-0000-4000-8000-000000000001"
	customer   = "bbbbbbbb-0000-4000-8000-000000000002"
)

// directoryServer hosts two apps: A, ours and listed, and B, a customer's
// and not listed. Both publish their status page.
func directoryServer(t *testing.T, listB bool) (*httptest.Server, *tenancy.Host) {
	t.Helper()
	srv, host, _, s := buildAppServer(t)
	s.HomeApp = homeApp
	for _, id := range []string{appA, appB} {
		tn, err := host.Ensure(id)
		if err != nil {
			t.Fatal(err)
		}
		host.Sync(directoryApps(listB), true)
		p := auth.System(tn.ID)
		p.Grant(auth.PermModel)
		svc, _ := tn.Mon.Service(tenancy.StatusServiceID)
		svc.Visibility = model.VisibilityPublic
		if _, _, err := tn.Mon.UpsertService(p, *svc, "Publish"); err != nil {
			t.Fatal(err)
		}
	}
	return srv, host
}

func directoryApps(listB bool) []tenancy.App {
	return []tenancy.App{
		{ID: homeApp, Name: "platform-monitoring", Hostname: "platform-monitoring.apps.example",
			AccountID: ourAccount, AccountSlug: "privasys", AccountName: "Privasys"},
		{ID: appA, Name: "checkout", DisplayName: "Checkout", Hostname: "checkout.apps.example",
			AccountID: ourAccount, AccountSlug: "privasys", AccountName: "Privasys", Listed: true},
		{ID: appB, Name: "ledger", DisplayName: "Ledger", Hostname: "ledger.apps.example",
			AccountID: customer, AccountSlug: "acme", AccountName: "Acme", Listed: listB},
	}
}

func listed(t *testing.T, srv *httptest.Server, path string) (int, []string) {
	t.Helper()
	code, body := call(t, srv, "GET", path, "")
	pages := []string{}
	apps, _ := body["apps"].([]any)
	for _, a := range apps {
		pages = append(pages, a.(map[string]any)["page"].(string))
	}
	return code, pages
}

func TestTheHomePageListsOnlyItsOwnAccountsListedApps(t *testing.T) {
	srv, _ := directoryServer(t, true)
	// The customer listed B, but in their own directory, not ours.
	if _, pages := listed(t, srv, "/api/v1/public/apps"); len(pages) != 1 || pages[0] != "/@privasys/checkout/" {
		t.Fatalf("home directory: %v", pages)
	}
	if _, pages := listed(t, srv, "/api/v1/public/accounts/@acme/apps"); len(pages) != 1 || pages[0] != "/@acme/ledger/" {
		t.Fatalf("acme directory: %v", pages)
	}
	if code, _ := listed(t, srv, "/api/v1/public/accounts/@nobody/apps"); code != http.StatusNotFound {
		t.Fatalf("an unknown account answered %d", code)
	}
}

func TestAnUnlistedAppIsInNoDirectoryButKeepsItsPage(t *testing.T) {
	srv, _ := directoryServer(t, false)
	if _, pages := listed(t, srv, "/api/v1/public/accounts/@acme/apps"); len(pages) != 0 {
		t.Fatalf("an unlisted app was listed: %v", pages)
	}
	for _, path := range []string{"/@acme/ledger/", "/api/v1/public/apps/ledger/status"} {
		if res, err := http.Get(srv.URL + path); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("%s: %v %v", path, res.StatusCode, err)
		}
	}
	// An app answers only under its own account's address.
	if res, _ := http.Get(srv.URL + "/@privasys/ledger/"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("another account's address answered %d", res.StatusCode)
	}
}

func TestAnAppsOldAddressTakesTheReaderToItsAccountsPage(t *testing.T) {
	srv, _ := directoryServer(t, false)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for path, want := range map[string]string{
		"/apps/ledger/":       "/@acme/ledger/",
		"/apps/" + appB + "/": "/@acme/ledger/",
		"/@acme":              "/@acme/",
		"/@acme/ledger":       "/@acme/ledger/",
	} {
		res, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != want {
			t.Fatalf("%s: %d to %q", path, res.StatusCode, res.Header.Get("Location"))
		}
	}
	// A first segment without the @ is never an account.
	if res, _ := client.Get(srv.URL + "/acme/"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("/acme/ answered %d", res.StatusCode)
	}
	if res, _ := client.Get(srv.URL + "/@acme/"); res.StatusCode != http.StatusOK {
		t.Fatalf("/@acme/ answered %d", res.StatusCode)
	}
}

func TestAnAppsPublicPageAnswersAtItsPlatformName(t *testing.T) {
	srv, host, _ := newAppServer(t)
	a, err := host.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	// An account with no short name keeps its apps at their own address.
	host.Sync([]tenancy.App{{ID: appA, Name: "checkout", Hostname: "checkout.apps.example"}}, true)
	p := auth.System(a.ID)
	p.Grant(auth.PermModel)
	svc, _ := a.Mon.Service(tenancy.StatusServiceID)
	svc.Visibility = model.VisibilityPublic
	if _, _, err := a.Mon.UpsertService(p, *svc, "Publish"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/apps/checkout/", "/apps/checkout/status.js", "/api/v1/public/apps/checkout/status", "/api/v2/apps/checkout/summary.json"} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s answered %d", path, res.StatusCode)
		}
	}
}

func TestAnyoneSignedInMayAskForTheListingToBeReadAgain(t *testing.T) {
	srv, _, _ := newAppServer(t)
	path := "/api/v1/apps/" + appA + "/refresh-listing"
	if code, _ := call(t, srv, "POST", path, ""); code != http.StatusUnauthorized {
		t.Fatalf("without a token: %d", code)
	}
	if code, _ := call(t, srv, "POST", path, token("stranger")); code != http.StatusAccepted {
		t.Fatalf("a signed-in stranger: %d", code)
	}
}
