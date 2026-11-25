// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// issuer serves a discovery document and one RSA key, and signs tokens.
type testIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &testIssuer{key: key}
	b64 := base64.RawURLEncoding.EncodeToString
	iss.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": iss.srv.URL + "/jwks"})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
				"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(iss.srv.Close)
	return iss
}

func (iss *testIssuer) token(t *testing.T, aud any, roles ...string) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": iss.srv.URL, "sub": "person", "aud": aud, "roles": roles,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	input := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, iss.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func TestATestPlatformTokenGrantsOnlyItsOwnPlatformsRoles(t *testing.T) {
	iss := newTestIssuer(t)
	v := NewJWKSVerifier(iss.srv.URL, "privasys-platform-test, privasys-platform").WithRoleNamespace(PlatformNamespace)
	ctx := context.Background()

	// A test-platform token: its own roles are read in the role model's
	// names, the production platform's are dropped, others pass.
	id, err := v.Verify(ctx, iss.token(t, "privasys-platform-test",
		"privasys-platform-test:app:abc:owner",
		"privasys-platform-test:account:def:member",
		"privasys-platform:app:other:owner",
		"privasys-platform:admin",
		"monitoring:viewer",
	))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"privasys-platform:app:abc:owner", "privasys-platform:account:def:member", "monitoring:viewer"}
	if !reflect.DeepEqual(id.Roles, want) {
		t.Fatalf("test-platform roles: %v", id.Roles)
	}

	// A production-platform token is read exactly as before.
	prod := []string{"privasys-platform:app:abc:owner", "privasys-platform-test:app:abc:owner"}
	id, err = v.Verify(ctx, iss.token(t, []string{"privasys-platform"}, prod...))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(id.Roles, prod) {
		t.Fatalf("production roles: %v", id.Roles)
	}

	// Any other audience is refused.
	if _, err := v.Verify(ctx, iss.token(t, "someone-else", "privasys-platform:admin")); err == nil {
		t.Fatal("a token for another audience was accepted")
	}
}

func TestAVerifierWithoutANamespaceLeavesRolesAlone(t *testing.T) {
	iss := newTestIssuer(t)
	v := NewJWKSVerifier(iss.srv.URL, "app-form:x")
	roles := []string{"privasys-platform:admin", "app-form:x:y"}
	id, err := v.Verify(context.Background(), iss.token(t, "app-form:x", roles...))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(id.Roles, roles) {
		t.Fatalf("roles: %v", id.Roles)
	}
}

func TestTheAudiencesCanComeFromConfigurationLearntLater(t *testing.T) {
	iss := newTestIssuer(t)
	var learnt []string
	v := NewJWKSVerifier(iss.srv.URL, "privasys-platform").WithRoleNamespace(PlatformNamespace).
		WithAudiences(func() []string { return learnt })
	ctx := context.Background()
	test := iss.token(t, "privasys-platform-test", "privasys-platform-test:admin")
	if _, err := v.Verify(ctx, test); err == nil {
		t.Fatal("a test-platform token was accepted before the monitor knew it serves the test platform")
	}
	learnt = []string{"privasys-platform-test", "privasys-platform"}
	id, err := v.Verify(ctx, test)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(id.Roles, []string{"privasys-platform:admin"}) {
		t.Fatalf("roles: %v", id.Roles)
	}
}

func TestTheAudienceOrderAndNearMissesDecideNothingByAccident(t *testing.T) {
	iss := newTestIssuer(t)
	ctx := context.Background()
	both := NewJWKSVerifier(iss.srv.URL, "privasys-platform-test,privasys-platform").WithRoleNamespace(PlatformNamespace)

	// A token for both audiences is read as the test platform's.
	id, err := both.Verify(ctx, iss.token(t, []string{"privasys-platform", "privasys-platform-test"},
		"privasys-platform:admin", "privasys-platform-test:app:abc:viewer", "privasys-platform-testx:admin"))
	if err != nil {
		t.Fatal(err)
	}
	// A near-miss namespace is neither renamed nor dropped: it names nothing.
	want := []string{"privasys-platform:app:abc:viewer", "privasys-platform-testx:admin"}
	if !reflect.DeepEqual(id.Roles, want) {
		t.Fatalf("roles: %v", id.Roles)
	}

	// A production monitor refuses a test-platform token outright.
	prod := NewJWKSVerifier(iss.srv.URL, "privasys-platform").WithRoleNamespace(PlatformNamespace).
		WithAudiences(func() []string { return nil })
	if _, err := prod.Verify(ctx, iss.token(t, "privasys-platform-test", "privasys-platform-test:admin")); err == nil {
		t.Fatal("a production monitor accepted a test-platform token")
	}

	// A monitor that cannot tell which platform it serves accepts no one.
	lost := NewJWKSVerifier(iss.srv.URL, "privasys-platform").WithRoleNamespace(PlatformNamespace).
		WithAudiences(func() []string { return []string{} })
	if _, err := lost.Verify(ctx, iss.token(t, "privasys-platform", "privasys-platform:admin")); err == nil {
		t.Fatal("a monitor that does not know its platform accepted a token")
	}
}
