// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package mail sends the monitor's email through Microsoft Graph.
//
// The monitor authenticates with a certificate rather than a client
// secret. It generates the key itself, on its sealed volume, and only the
// public certificate ever leaves: an operator uploads that to the app
// registration. Each token request is then a short-lived assertion signed
// with the key, so there is no shared secret to deliver, store or leak.
package mail

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is defined as a SHA-1 thumbprint
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Lifetime is how long a generated certificate is valid.
const Lifetime = 2 * 365 * 24 * time.Hour

// Credential is the monitor's key and its self-signed certificate.
type Credential struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

// LoadCredential reads the credential in dir, generating it on first use.
func LoadCredential(dir string, now time.Time) (*Credential, error) {
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	keyPEM, keyErr := os.ReadFile(keyPath)
	certPEM, certErr := os.ReadFile(certPath)
	if errors.Is(keyErr, os.ErrNotExist) && errors.Is(certErr, os.ErrNotExist) {
		return generate(dir, keyPath, certPath, now)
	}
	if keyErr != nil {
		return nil, fmt.Errorf("mail: %w", keyErr)
	}
	if certErr != nil {
		return nil, fmt.Errorf("mail: %w", certErr)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	certBlock, _ := pem.Decode(certPEM)
	if keyBlock == nil || certBlock == nil {
		return nil, errors.New("mail: the stored credential is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	return &Credential{key: key, cert: cert, der: certBlock.Bytes}, nil
}

func generate(dir, keyPath, certPath string, now time.Time) (*Credential, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Privasys monitor mail"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(Lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("mail: %w", err)
	}
	return &Credential{key: key, cert: cert, der: der}, nil
}

// CertificatePEM is the public certificate, what the app registration takes.
func (c *Credential) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// NotAfter is when the certificate expires.
func (c *Credential) NotAfter() time.Time { return c.cert.NotAfter }

// Thumbprint is the certificate's SHA-1 thumbprint in upper-case hex, the
// form the app registration displays it in.
func (c *Credential) Thumbprint() string {
	sum := sha1.Sum(c.der) //nolint:gosec // see the import
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// assertion is the signed client assertion for one token request.
func (c *Credential) assertion(clientID, audience string, now time.Time) (string, error) {
	thumb := sha1.Sum(c.der) //nolint:gosec // see the import
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "x5t": base64.RawURLEncoding.EncodeToString(thumb[:]),
	})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"aud": audience, "iss": clientID, "sub": clientID,
		"jti": hex.EncodeToString(jti),
		"nbf": now.Unix(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Sender sends mail as the app registration.
type Sender struct {
	TenantID, ClientID string
	Credential         *Credential

	// LoginBase and GraphBase are the Microsoft endpoints; tests replace them.
	LoginBase, GraphBase string
	Client               *http.Client
	Now                  func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// Hosts are what the sender must be allowed to reach.
var Hosts = []string{"login.microsoftonline.com", "graph.microsoft.com"}

func (s *Sender) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sender) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (s *Sender) accessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.token != "" && now.Before(s.expires) {
		return s.token, nil
	}
	base := s.LoginBase
	if base == "" {
		base = "https://login.microsoftonline.com"
	}
	tokenURL := base + "/" + url.PathEscape(s.TenantID) + "/oauth2/v2.0/token"
	assertion, err := s.Credential.assertion(s.ClientID, tokenURL, now)
	if err != nil {
		return "", fmt.Errorf("mail: %w", err)
	}
	form := url.Values{
		"client_id":             {s.ClientID},
		"scope":                 {"https://graph.microsoft.com/.default"},
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("mail: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("mail: token request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mail: the token request answered %d: %s", resp.StatusCode, oauthError(raw))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("mail: the token response had no access token")
	}
	s.token, s.expires = out.AccessToken, now.Add(time.Duration(out.ExpiresIn)*time.Second-time.Minute)
	return s.token, nil
}

// oauthError keeps the error code and description, which name the fault
// and carry no token.
func oauthError(raw []byte) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(raw, &e) != nil || e.Error == "" {
		return "no detail"
	}
	if len(e.Description) > 240 {
		e.Description = e.Description[:240]
	}
	return e.Error + ": " + e.Description
}

// Send delivers one plain-text message from a mailbox the registration may
// send as.
func (s *Sender) Send(ctx context.Context, from, to, subject, body string) error {
	token, err := s.accessToken(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"message": map[string]any{
			"subject":      subject,
			"body":         map[string]string{"contentType": "Text", "content": body},
			"toRecipients": []any{map[string]any{"emailAddress": map[string]string{"address": to}}},
		},
		"saveToSentItems": false,
	})
	if err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	base := s.GraphBase
	if base == "" {
		base = "https://graph.microsoft.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/v1.0/users/"+url.PathEscape(from)+"/sendMail", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("mail: send: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("mail: sendMail answered %d: %s", resp.StatusCode, truncate(string(raw), 240))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
