// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package mail

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTheCredentialIsMadeOnceAndLastsTwoYears(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mail")
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	c, err := LoadCredential(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.NotAfter(); !got.Equal(now.Add(Lifetime).Truncate(time.Second)) {
		t.Fatalf("expires %v", got)
	}
	again, err := LoadCredential(dir, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if again.Thumbprint() != c.Thumbprint() {
		t.Fatal("a restart made a new certificate")
	}
	if block, _ := pem.Decode(c.CertificatePEM()); block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("the public certificate is not a PEM certificate")
	}
	if strings.Contains(string(c.CertificatePEM()), "PRIVATE") {
		t.Fatal("the public certificate carries the key")
	}
	info, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if os.PathSeparator == '/' && info.Mode().Perm() != 0o600 {
		t.Fatalf("the key is readable by others: %v", info.Mode())
	}
}

func TestSendSignsAnAssertionAndReusesTheToken(t *testing.T) {
	c, err := LoadCredential(filepath.Join(t.TempDir(), "mail"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tokens, sends := 0, 0
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			tokens++
			_ = r.ParseForm()
			parts := strings.Split(r.Form.Get("client_assertion"), ".")
			if len(parts) != 3 {
				t.Errorf("assertion: %q", r.Form.Get("client_assertion"))
			}
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&c.key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
				t.Errorf("signature: %v", err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims map[string]any
			_ = json.Unmarshal(raw, &claims)
			if claims["iss"] != "client" || claims["sub"] != "client" ||
				!strings.HasSuffix(claims["aud"].(string), "/tenant/oauth2/v2.0/token") {
				t.Errorf("claims: %v", claims)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
		case r.URL.Path == "/v1.0/users/no-reply@example.org/sendMail":
			sends++
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("authorization: %q", r.Header.Get("Authorization"))
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &sent)
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	s := &Sender{TenantID: "tenant", ClientID: "client", Credential: c, LoginBase: srv.URL, GraphBase: srv.URL}
	for range 2 {
		if err := s.Send(context.Background(), "no-reply@example.org", "ada@example.org", "Down", "It is down"); err != nil {
			t.Fatal(err)
		}
	}
	if tokens != 1 || sends != 2 {
		t.Fatalf("tokens %d sends %d", tokens, sends)
	}
	if msg := sent["message"].(map[string]any); msg["subject"] != "Down" {
		t.Fatalf("message: %v", msg)
	}
}

func TestARefusedTokenSaysWhy(t *testing.T) {
	c, err := LoadCredential(filepath.Join(t.TempDir(), "mail"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS700027: certificate not registered"}`))
	}))
	defer srv.Close()
	s := &Sender{TenantID: "t", ClientID: "c", Credential: c, LoginBase: srv.URL, GraphBase: srv.URL}
	err = s.Send(context.Background(), "a@example.org", "b@example.org", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "AADSTS700027") {
		t.Fatalf("error: %v", err)
	}
}
