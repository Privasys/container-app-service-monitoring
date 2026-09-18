// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// managerStub answers the self-targeted container routes the way the
// enclave-os-virtual manager does: only the launcher-minted token as a
// Bearer token, for the container it is bound to.
func managerStub(t *testing.T, name, token string, hits *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits = append(*hits, r.Method+" "+r.URL.Path)
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"expected Bearer PRIVASYS_CONTAINER_TOKEN"}`))
			return
		}
		if strings.TrimPrefix(auth, "Bearer ") != token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid container token"}`))
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/v1/containers/"+name+"/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
}

// After an in-place redeploy the monitor restores its configuration from
// its volume and lifts the runtime's configure gate itself. It used to
// send the token in X-Container-Token, which the manager refuses with 401
// "expected Bearer PRIVASYS_CONTAINER_TOKEN", so the gate stayed down.
func TestConfigCompleteSendsTheContainerTokenAsABearer(t *testing.T) {
	var hits []string
	srv := managerStub(t, "platform-monitoring", "tok-123", &hits)
	defer srv.Close()

	m := NewManager(srv.URL, "platform-monitoring", "tok-123")
	if err := m.ConfigComplete(context.Background()); err != nil {
		t.Fatalf("config-complete: %v", err)
	}
	if len(hits) != 1 || hits[0] != "POST /api/v1/containers/platform-monitoring/config-complete" {
		t.Fatalf("calls %v", hits)
	}
	// The attestation extensions use the same authentication.
	if err := m.PublishSigningKey(context.Background(), []byte("public key")); err != nil {
		t.Fatalf("attestation extension: %v", err)
	}
}

func TestConfigCompleteReportsARefusal(t *testing.T) {
	var hits []string
	srv := managerStub(t, "platform-monitoring", "tok-123", &hits)
	defer srv.Close()

	err := NewManager(srv.URL, "platform-monitoring", "another token").ConfigComplete(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a refused call must be reported, got %v", err)
	}
	if NewManager("", "x", "y").ConfigComplete(context.Background()) != nil {
		t.Fatal("off the platform there is no gate and nothing to report")
	}
}
