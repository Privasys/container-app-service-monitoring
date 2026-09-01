// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package platform talks to the enclave manager that runs this
// container.
//
// The only thing the register asks of it is to carry two values into
// the per-container RA-TLS leaf certificate. A client that verifies the
// certificate is verifying a hardware quote over the measurement of
// this build; these extensions ride alongside it, so the same handshake
// that proves what code is running also proves what key it was given
// and what state it is serving.
package platform

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Object identifiers under the app's attestation arc.
const (
	// OIDSigningKey carries SHA-256 over the public half of the key this
	// build signs its reports, checkpoints and alerts with. A verifying
	// client therefore knows which measurement holds the key behind any
	// evidence it is handed.
	OIDSigningKey = "1.3.6.1.4.1.65230.3.5.1"
	// OIDLedgerRoot carries the live ledger root, so a
	// challenge-mode handshake returns the current authenticated state
	// as part of the certificate rather than as a claim in the body.
	OIDLedgerRoot = "1.3.6.1.4.1.65230.3.5.2"
)

// Manager is the in-enclave callback client.
type Manager struct {
	baseURL   string
	container string
	token     string
	client    *http.Client
}

// NewManager returns a client, or nil when the callback credentials are
// absent (a developer's machine rather than the platform).
func NewManager(managerURL, container, token string) *Manager {
	if managerURL == "" || container == "" || token == "" {
		return nil
	}
	if _, err := url.Parse(managerURL); err != nil {
		return nil
	}
	return &Manager{
		baseURL: managerURL, container: container, token: token,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// SetExtension installs an attestation extension on the next
// per-container leaf.
func (m *Manager) SetExtension(ctx context.Context, oid string, value []byte) error {
	if m == nil {
		return nil
	}
	body, err := json.Marshal(map[string]string{
		"oid":       oid,
		"value_b64": base64.StdEncoding.EncodeToString(value),
	})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/v1/containers/%s/attestation-extensions",
		m.baseURL, url.PathEscape(m.container))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.token)
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("platform: attestation extension: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("platform: attestation extension %s: %d %s", oid, resp.StatusCode, detail)
	}
	return nil
}

// PublishRoot installs the live ledger root.
func (m *Manager) PublishRoot(ctx context.Context, rootHex string) error {
	raw, err := hex.DecodeString(rootHex)
	if err != nil {
		return fmt.Errorf("platform: root is not hex: %w", err)
	}
	return m.SetExtension(ctx, OIDLedgerRoot, raw)
}

// ConfigComplete lifts the runtime's configure gate without an owner
// present.
//
// The gate is the platform's, and it re-arms on every restart. That is
// right for a first boot and wrong for every boot after it: a monitor
// keeps its configuration on its own sealed volume, and nobody is
// standing by at three in the morning to type it again. Without this
// call every redeploy looks like configuration loss while the
// configuration was never gone.
func (m *Manager) ConfigComplete(ctx context.Context) error {
	if m == nil {
		return nil
	}
	endpoint := fmt.Sprintf("%s/api/v1/containers/%s/config-complete",
		m.baseURL, url.PathEscape(m.container))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Container-Token", m.token)
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("platform: config-complete: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("platform: config-complete: %d %s", resp.StatusCode, detail)
	}
	return nil
}

// PublishSigningKey commits SHA-256 of the report signing key to the
// per-container leaf certificate.
//
// This is the load-bearing extension. A report, a checkpoint and an
// alert are all signed with this key, so binding it to the measurement
// means a verifier who checked the certificate has checked which build
// holds the key that signed the evidence.
func (m *Manager) PublishSigningKey(ctx context.Context, publicKey []byte) error {
	sum := sha256.Sum256(publicKey)
	return m.SetExtension(ctx, OIDSigningKey, sum[:])
}
