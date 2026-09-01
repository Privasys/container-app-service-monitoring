// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package journey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
)

// The browser leg.
//
// A browser journey runs somewhere else: a renderer with its own
// measurement, its own enclave, no vault and no volume. That is
// deliberate. A journey renders whatever the watched service returns,
// which on a bad day is whatever an attacker put there, and the process
// holding the customer's credentials and the availability record should
// not be the process parsing it.
//
// What crosses the gap is one request carrying resolved values, and one
// response carrying what the page did. The credential goes only after
// the renderer's measurement has been checked against the digest the
// owner pinned, so "which build am I handing this to" is answered by a
// hardware quote rather than by a hostname.

// BrowserClient talks to the renderer.
type BrowserClient struct {
	// URL is where the renderer serves.
	URL string
	// Token is the shared secret the renderer requires. Attestation says
	// which build is on the other end; this says which caller we are.
	Token string
	// ExpectedDigest is the workload image digest the owner pinned. A
	// renderer presenting any other measurement is refused before the
	// request body, and therefore before the credential, is sent.
	ExpectedDigest string
	// RootCAs is the trust anchor for the renderer's certificate. Empty
	// uses the system pool.
	RootCAs *x509.CertPool
	// Insecure skips attestation entirely. Only a developer's machine
	// sets it, and the runtime refuses to when the platform credentials
	// are present.
	Insecure bool

	client *http.Client
}

// OIDImageDigest is where the platform measures the workload image into
// the RA-TLS leaf certificate.
var OIDImageDigest = []int{1, 3, 6, 1, 4, 1, 65230, 3, 2}

// Configured reports whether a renderer has been set up.
func (c *BrowserClient) Configured() bool { return c != nil && c.URL != "" }

// Render runs a journey on the renderer.
func (c *BrowserClient) Render(ctx context.Context, body []byte) (*BrowserResult, error) {
	if !c.Configured() {
		return nil, fmt.Errorf("browser: no renderer is configured for browser journeys")
	}
	if c.client == nil {
		c.client = c.build()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.URL, "/")+"/render", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("browser: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("browser: reading the render: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("browser: the renderer answered %d: %s",
			resp.StatusCode, truncate(string(raw), 200))
	}
	var out BrowserResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("browser: the renderer's answer did not parse: %w", err)
	}
	return &out, nil
}

func (c *BrowserClient) build() *http.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.RootCAs}
	if c.Insecure {
		tlsConfig.InsecureSkipVerify = true
	} else if c.ExpectedDigest != "" {
		// The measurement is checked on the certificate the renderer
		// presented, during the handshake, so nothing is sent to a build
		// nobody pinned. The chain is still verified normally: this adds
		// a condition, it does not replace one.
		tlsConfig.VerifyPeerCertificate = c.verifyMeasurement
	}
	return &http.Client{
		Timeout:   3 * time.Minute,
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig},
	}
}

// verifyMeasurement requires the leaf to carry the pinned workload
// image digest.
//
// This is deterministic attestation: the quote rides in the certificate
// and binds the key, and the certificate is renewed daily, so what it
// proves is that this key was generated inside a genuine enclave
// running this measurement within the renewal window. Freshness at the
// connection level needs a challenge in the handshake and a TLS stack
// that can carry one; that is a later upgrade and this is not it.
func (c *BrowserClient) verifyMeasurement(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("browser: the renderer presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("browser: the renderer's certificate did not parse: %w", err)
	}
	want := strings.ToLower(strings.TrimPrefix(c.ExpectedDigest, "sha256:"))
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(OIDImageDigest) {
			continue
		}
		// The platform writes the digest as raw bytes; older builds wrote
		// it as lower-case hex. Accept either rather than fail closed on
		// a formatting difference.
		got := strings.ToLower(strings.TrimSpace(string(ext.Value)))
		if got != want {
			got = hex.EncodeToString(ext.Value)
		}
		if got == want {
			return nil
		}
		return fmt.Errorf("browser: the renderer is running %s, not the pinned %s",
			truncate(got, 16), truncate(want, 16))
	}
	return fmt.Errorf("browser: the renderer's certificate carries no workload measurement")
}

// BrowserResult is what the renderer reported.
type BrowserResult struct {
	OK         bool                `json:"ok"`
	FailedStep string              `json:"failed_step"`
	Error      string              `json:"error"`
	ErrorClass string              `json:"error_class"`
	DurationMs int                 `json:"duration_ms"`
	Steps      []BrowserStepResult `json:"steps"`
	Console    []string            `json:"console"`
	Failed     []BrowserFailed     `json:"failed_requests"`
}

// BrowserStepResult is one action's outcome.
type BrowserStepResult struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	OK         bool   `json:"ok"`
	DurationMs int    `json:"duration_ms"`
	Detail     string `json:"detail"`
	URL        string `json:"url"`
	Text       string `json:"text"`
	Screenshot string `json:"screenshot"`
	OCRText    string `json:"ocr_text"`
	Value      string `json:"value"`
}

// BrowserFailed is one subresource that did not load.
type BrowserFailed struct {
	URL    string `json:"url"`
	Reason string `json:"reason"`
	Type   string `json:"type"`
}

// browserRequest is the wire shape the renderer accepts.
type browserRequest struct {
	Steps     []browserStep `json:"steps"`
	Width     int           `json:"width,omitempty"`
	Height    int           `json:"height,omitempty"`
	TimeoutMs int           `json:"timeout_ms,omitempty"`
	UserAgent string        `json:"user_agent,omitempty"`
	OCR       bool          `json:"ocr,omitempty"`
}

type browserStep struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	URL         string `json:"url,omitempty"`
	Selector    string `json:"selector,omitempty"`
	Value       string `json:"value,omitempty"`
	Key         string `json:"key,omitempty"`
	Expression  string `json:"expression,omitempty"`
	WaitVisible bool   `json:"wait_visible,omitempty"`
	SleepMs     int    `json:"sleep_ms,omitempty"`
	TimeoutMs   int    `json:"timeout_ms,omitempty"`
	Screenshot  bool   `json:"screenshot,omitempty"`
	FullPage    bool   `json:"full_page,omitempty"`
	Text        bool   `json:"text,omitempty"`
}

// buildBrowserRequest resolves a monitor's browser steps.
//
// Credentials are resolved against the host of the page the step acts
// on, which for a browser journey is whatever the last navigation set.
// The binding therefore still holds: a journey that navigates somewhere
// else and then fills a password field is refused at the fill, not
// after the credential has gone.
func buildBrowserRequest(mon *model.Monitor, resolver SecretResolver,
	red *secrets.Redactor, used map[string]bool) ([]byte, *stepFailure) {

	req := browserRequest{
		Width: mon.Viewport.Width, Height: mon.Viewport.Height,
		TimeoutMs: mon.TimeoutSeconds * 1000,
		OCR:       mon.Viewport.OCR,
	}
	vars := map[string]string{}
	host := ""

	for i := range mon.Steps {
		s := &mon.Steps[i]
		out := browserStep{
			Name: s.Name, Kind: s.BrowserKind(), Selector: s.Selector, Key: s.Key,
			WaitVisible: s.WaitVisible, SleepMs: s.SleepMs, TimeoutMs: s.TimeoutSeconds * 1000,
			Screenshot: s.Screenshot != nil, FullPage: s.FullPage, Text: s.Capture,
		}

		// A URL is rendered without access to credentials, and it decides
		// the host every later credential is resolved against.
		if s.URL != "" {
			if referencesSecret(s.URL) {
				return nil, &stepFailure{class: model.ErrClassPolicy, detail: ErrSecretInURL.Error()}
			}
			rendered, err := (&scope{vars: vars}).render(s.URL)
			if err != nil {
				return nil, &stepFailure{class: model.ErrClassPolicy, detail: err.Error()}
			}
			out.URL = rendered
			host = hostOfURL(rendered)
		}

		scoped := &scope{vars: vars, secrets: resolver, host: host}
		var err error
		if out.Value, err = scoped.render(s.Value); err != nil {
			return nil, &stepFailure{class: classForResolve(err), detail: err.Error()}
		}
		if out.Expression, err = scoped.render(s.Expression); err != nil {
			return nil, &stepFailure{class: model.ErrClassPolicy, detail: err.Error()}
		}
		for name, value := range scoped.used {
			red.Add(name, value)
			used[name] = true
		}
		req.Steps = append(req.Steps, out)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, &stepFailure{class: model.ErrClassInternal, detail: err.Error()}
	}
	return body, nil
}

func hostOfURL(raw string) string {
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}

// FingerprintToken is how a token is recorded without being recorded:
// the monitor keeps a hash so an operator can tell one renderer
// credential from another without the record holding either.
func FingerprintToken(token string) string {
	sum := sha256.Sum256([]byte("privasys-monitor/renderer-token/v1" + token))
	return hex.EncodeToString(sum[:8])
}
