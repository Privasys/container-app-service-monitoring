// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/oncall"
)

// answers stands in for the identity provider's signature check.
type answers struct{ byToken map[string]*auth.Identity }

func (a answers) Verify(_ context.Context, token string) (*auth.Identity, error) {
	if id, ok := a.byToken[token]; ok {
		return id, nil
	}
	return nil, errors.New("bad signature")
}

type recordingWallet struct {
	mu    sync.Mutex
	forms []string
}

func (w *recordingWallet) Form(_ context.Context, _, form string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.forms = append(w.forms, form)
	return "sent", nil
}

func (w *recordingWallet) Message(context.Context, string, string, string) (string, error) {
	return "sent", nil
}

func send(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func answerToken(name string) string {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"app-form-answer+jwt"}`))
	return head + "." + name + ".sig"
}

func TestOnCallRolesAndWalletAnswers(t *testing.T) {
	srv, host, s := newOnCallServer(t)
	a, err := host.Ensure(appA)
	if err != nil {
		t.Fatal(err)
	}
	store, err := oncall.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wallet := &recordingWallet{}
	a.OnCall = &oncall.Dispatcher{
		Store: store, AppID: a.ID, Wallet: wallet, Callback: "/answer",
		Team: func(context.Context) ([]oncall.Member, error) {
			return []oncall.Member{{Sub: "bo", Role: oncall.RoleSupportMember}}, nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.OnCall.Prepare()
	base := "/api/v1/apps/" + appA + "/oncall"
	owner := token("ada", "privasys-platform:app:"+keyA+":owner")
	member := token("bo", "privasys-platform:app:"+keyA+":support-member")
	stranger := token("cy", "privasys-platform:app:"+keyB+":owner")

	if code, _ := send(t, srv, "GET", base, stranger, nil); code != http.StatusUnauthorized {
		t.Fatalf("another app's owner read the rota: %d", code)
	}

	// Each person sets their own preference, whatever sub they send.
	code, body := send(t, srv, "POST", base+"/me", member, map[string]any{
		"sub": "ada", "wallet": true, "email": "bo@example.org", "when": "always",
	})
	if code != http.StatusOK || body["me"].(map[string]any)["sub"] != "bo" {
		t.Fatalf("me: %d %v", code, body)
	}
	if got := store.Preference("ada"); got.Email != "" {
		t.Fatalf("someone set another person's preference: %+v", got)
	}
	if code, _ := send(t, srv, "POST", base+"/me", member, map[string]any{"wallet": false, "when": "always"}); code == http.StatusOK {
		t.Fatal("a preference that reaches nobody was accepted")
	}

	// Only the team's leads change the rota.
	plan := map[string]any{"rotation": []string{"bo"}, "period_days": 7, "ack_minutes": 5}
	if code, _ := send(t, srv, "POST", base+"/plan", member, plan); code != http.StatusForbidden {
		t.Fatalf("a member changed the rota: %d", code)
	}
	if code, _ := send(t, srv, "POST", base+"/plan", owner, plan); code != http.StatusOK {
		t.Fatalf("the owner could not set the rota: %d", code)
	}

	// A page reaches Bo, and only a signed answer from Bo takes it.
	a.OnCall.Open(context.Background(), "inc", "cmp", "App", "refused")
	if len(wallet.forms) != 1 {
		t.Fatalf("forms: %d", len(wallet.forms))
	}
	var form struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(wallet.forms[0]), &form)
	sum := sha256.Sum256([]byte(wallet.forms[0]))
	digest := hex.EncodeToString(sum[:])
	claims := func(action string) map[string]any {
		return map[string]any{"form_id": form.ID, "form_digest": digest, "action": action}
	}
	s.FormAnswers = answers{byToken: map[string]*auth.Identity{
		answerToken("bo"):    {Sub: "bo", Claims: claims("take")},
		answerToken("ada"):   {Sub: "ada", Claims: claims("take")},
		answerToken("other"): {Sub: "bo", Claims: map[string]any{"form_id": "another", "form_digest": digest, "action": "take"}},
		"plain.access.token": {Sub: "bo", Claims: claims("take")},
	}}
	post := func(answer string) int {
		code, _ := send(t, srv, "POST", base+"/answer", "", map[string]any{"form_id": form.ID, "action": "take", "answer": answer})
		return code
	}
	for name, tok := range map[string]string{
		"an access token":    "plain.access.token",
		"an unsigned answer": answerToken("forged"),
		"another form":       answerToken("other"),
	} {
		if code := post(tok); code != http.StatusUnauthorized {
			t.Fatalf("%s was accepted: %d", name, code)
		}
	}
	if code := post(answerToken("ada")); code != http.StatusNotFound {
		t.Fatalf("someone it was not sent to answered: %d", code)
	}
	if p := store.Pages(1)[0]; p.State != oncall.PageOpen {
		t.Fatalf("the page moved on a refused answer: %+v", p)
	}
	if code := post(answerToken("bo")); code != http.StatusOK {
		t.Fatalf("the genuine answer was refused: %d", code)
	}
	if p := store.Pages(1)[0]; p.State != oncall.PageTaken || p.TakenBy != "bo" {
		t.Fatalf("page: %+v", p)
	}

	// What the team reads holds no address and no form digests.
	_, overview := send(t, srv, "GET", base, member, nil)
	raw, _ := json.Marshal(overview["pages"])
	if strings.Contains(string(raw), digest) || strings.Contains(string(raw), "example.org") {
		t.Fatalf("the overview leaks: %s", raw)
	}
}

func TestTheMailCertificateIsPublicAndHoldsNoKey(t *testing.T) {
	srv, _, s := newOnCallServer(t)
	if code, _ := send(t, srv, "GET", "/api/v1/public/mail-certificate", "", nil); code != http.StatusNotFound {
		t.Fatalf("no certificate configured: %d", code)
	}
	s.MailCert = &MailCertificate{Certificate: "-----BEGIN CERTIFICATE-----", Thumbprint: "AB", NotAfter: "2028-11-17T00:00:00Z"}
	code, body := send(t, srv, "GET", "/api/v1/public/mail-certificate", "", nil)
	if code != http.StatusOK || body["thumbprint"] != "AB" {
		t.Fatalf("certificate: %d %v", code, body)
	}
}
