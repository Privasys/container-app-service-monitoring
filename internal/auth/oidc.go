// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package auth verifies caller identity and maps it onto the register's
// role model.
//
// Bearer tokens are verified offline against the identity provider's
// published JWKS, so authorising a request never means sending the
// request, or anything about it, off the machine. Only the cached key
// set is fetched.
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Identity is the verified result of a bearer token.
type Identity struct {
	Sub     string
	Display string
	Email   string
	Issuer  string
	Roles   []string
	Claims  map[string]any
}

// Verifier validates a bearer token.
type Verifier interface {
	Verify(ctx context.Context, token string) (*Identity, error)
}

// DevVerifier accepts "dev:<sub>[:<display>][:<role>,<role>…]" tokens.
// It exists so the monitor can be driven end to end on a laptop; the
// configuration layer refuses to enable it on the platform.
type DevVerifier struct{}

// Verify parses a development token.
func (DevVerifier) Verify(_ context.Context, token string) (*Identity, error) {
	if !strings.HasPrefix(token, "dev:") {
		return nil, errors.New("auth: development verifier expects 'dev:<sub>:<display>:<roles>'")
	}
	// Only the first two colons separate fields: identity-provider role
	// names carry colons of their own ("monitoring:owner"), and a
	// development token that could not express a real role name would
	// not be exercising the real role model.
	parts := strings.SplitN(strings.TrimPrefix(token, "dev:"), ":", 3)
	if parts[0] == "" {
		return nil, errors.New("auth: development token has no subject")
	}
	id := &Identity{Sub: parts[0], Issuer: "dev://privasys.id"}
	if len(parts) > 1 {
		id.Display = parts[1]
	}
	if len(parts) > 2 && parts[2] != "" {
		id.Roles = strings.Split(parts[2], ",")
	}
	return id, nil
}

// JWKSVerifier validates tokens against an issuer's published keys.
type JWKSVerifier struct {
	issuer   string
	audience string
	client   *http.Client

	mu        sync.RWMutex
	keys      map[string]*jwk
	fetchedAt time.Time
}

// NewJWKSVerifier returns a verifier for tokens issued by issuer. An
// empty audience skips the audience check.
func NewJWKSVerifier(issuer, audience string) *JWKSVerifier {
	return &JWKSVerifier{
		issuer:   strings.TrimRight(issuer, "/"),
		audience: audience,
		client:   &http.Client{Timeout: 10 * time.Second},
		keys:     map[string]*jwk{},
	}
}

// Verify checks signature, issuer, audience and expiry.
func (v *JWKSVerifier) Verify(ctx context.Context, token string) (*Identity, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("auth: malformed token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth: header decode: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("auth: header parse: %w", err)
	}
	key, err := v.signingKey(ctx, header.Kid, header.Alg)
	if err != nil {
		return nil, fmt.Errorf("auth: key lookup: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("auth: signature decode: %w", err)
	}
	if err := verifySignature(header.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, fmt.Errorf("auth: signature: %w", err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth: claims decode: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("auth: claims parse: %w", err)
	}
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return nil, fmt.Errorf("auth: issuer %q is not %q", iss, v.issuer)
	}
	if v.audience != "" && !audienceMatches(claims, v.audience) {
		return nil, fmt.Errorf("auth: token is not for audience %q", v.audience)
	}
	if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
		return nil, errors.New("auth: token expired")
	}
	id := &Identity{Issuer: v.issuer, Roles: rolesClaim(claims), Claims: claims}
	id.Sub, _ = claims["sub"].(string)
	id.Email, _ = claims["email"].(string)
	id.Display, _ = claims["name"].(string)
	if id.Display == "" {
		id.Display = id.Email
	}
	if id.Sub == "" {
		return nil, errors.New("auth: token has no subject")
	}
	return id, nil
}

func rolesClaim(claims map[string]any) []string {
	var out []string
	if arr, ok := claims["roles"].([]any); ok {
		for _, r := range arr {
			if s, ok := r.(string); ok {
				out = append(out, s)
			}
		}
	}
	if ra, ok := claims["realm_access"].(map[string]any); ok {
		if arr, ok := ra["roles"].([]any); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func audienceMatches(claims map[string]any, expected string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == expected
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (v *JWKSVerifier) signingKey(ctx context.Context, kid, alg string) (*jwk, error) {
	v.mu.RLock()
	if len(v.keys) > 0 && time.Since(v.fetchedAt) < 5*time.Minute {
		if k, ok := v.keys[kid]; ok {
			v.mu.RUnlock()
			return k, nil
		}
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.keys) > 0 && time.Since(v.fetchedAt) < 5*time.Minute {
		if k, ok := v.keys[kid]; ok {
			return k, nil
		}
	}
	uri, err := v.discover(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := v.fetch(ctx, uri)
	if err != nil {
		return nil, err
	}
	v.keys, v.fetchedAt = keys, time.Now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	if kid == "" {
		for _, k := range keys {
			if k.Alg == alg || (k.Use == "sig" && k.Alg == "") {
				return k, nil
			}
		}
	}
	return nil, fmt.Errorf("key %q is not in the published key set", kid)
}

func (v *JWKSVerifier) discover(ctx context.Context) (string, error) {
	body, err := v.get(ctx, v.issuer+"/.well-known/openid-configuration")
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	var doc struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("discovery parse: %w", err)
	}
	if doc.JwksURI == "" {
		return "", errors.New("discovery: no jwks_uri")
	}
	return doc.JwksURI, nil
}

func (v *JWKSVerifier) fetch(ctx context.Context, uri string) (map[string]*jwk, error) {
	body, err := v.get(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("key set parse: %w", err)
	}
	keys := make(map[string]*jwk, len(doc.Keys))
	for i := range doc.Keys {
		k := doc.Keys[i]
		keys[k.Kid] = &k
	}
	if len(keys) == 0 {
		return nil, errors.New("key set is empty")
	}
	return keys, nil
}

func (v *JWKSVerifier) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func verifySignature(alg string, key *jwk, signingInput, sig []byte) error {
	switch {
	case strings.HasPrefix(alg, "RS"):
		return verifyRSA(alg, key, signingInput, sig)
	case strings.HasPrefix(alg, "ES"):
		return verifyEC(key, signingInput, sig)
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func verifyRSA(alg string, key *jwk, signingInput, sig []byte) error {
	if key.Kty != "RSA" {
		return fmt.Errorf("expected an RSA key, got %s", key.Kty)
	}
	nb, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return err
	}
	eb, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 + int(b)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	var h crypto.Hash
	switch alg {
	case "RS256":
		h = crypto.SHA256
	case "RS384":
		h = crypto.SHA384
	case "RS512":
		h = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA algorithm %q", alg)
	}
	hh := h.New()
	hh.Write(signingInput)
	return rsa.VerifyPKCS1v15(pub, h, hh.Sum(nil), sig)
}

func verifyEC(key *jwk, signingInput, sig []byte) error {
	if key.Kty != "EC" {
		return fmt.Errorf("expected an EC key, got %s", key.Kty)
	}
	xb, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return err
	}
	yb, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return err
	}
	var curve elliptic.Curve
	var size int
	var digest func([]byte) []byte
	switch key.Crv {
	case "P-256":
		curve, size = elliptic.P256(), 32
		digest = func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
	case "P-384":
		curve, size = elliptic.P384(), 48
		digest = func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }
	default:
		return fmt.Errorf("unsupported curve %q", key.Crv)
	}
	if len(sig) != size*2 {
		return fmt.Errorf("signature is %d bytes, expected %d", len(sig), size*2)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	if !ecdsa.Verify(pub, digest(signingInput), r, s) {
		return errors.New("signature does not verify")
	}
	return nil
}
