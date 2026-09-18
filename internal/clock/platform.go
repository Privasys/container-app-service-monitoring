// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// The platform control plane, as the clock uses it.
//
// The monitor calls it as an attested app, not as a person: every
// request carries an identity certificate minted for this container by
// the measured enclave manager, and a hardware quote binding that
// certificate to a fresh challenge. The control plane verifies the
// quote, reads the app id the manager stamped on the certificate, and
// checks that this app holds the platform right the endpoint needs. No
// token or password is configured anywhere.

// Enclave is one runtime of the fleet as the control plane lists it: an
// enclave (kind "enclave", or no kind from an older control plane) or a
// member of the active vault constellation (kind "vault", with no manager
// hostname). Every runtime is reached directly at GatewayHost:Port.
type Enclave struct {
	ID          string `json:"id"`
	Kind        string `json:"kind,omitempty"`
	Name        string `json:"name"`
	TeeType     string `json:"tee_type"`
	MgrHostname string `json:"mgr_hostname"`
	GatewayHost string `json:"gateway_host"`
	Port        int    `json:"port"`
	// ClockConfigVersion is the clock config version the runtime
	// acknowledged to the control plane (0: never).
	ClockConfigVersion int64  `json:"clock_config_version"`
	Quarantined        bool   `json:"quarantined"`
	QuarantineReason   string `json:"quarantine_reason,omitempty"`

	// ClockConfigCurrent is the version of the clock config the control
	// plane has set now, from the list this entry came in, and
	// ClockConfigKnown whether that list said at all (a control plane
	// older than the field does not).
	ClockConfigCurrent int64 `json:"-"`
	ClockConfigKnown   bool  `json:"-"`
}

// ClockArmed reports whether the runtime acknowledged the current clock
// config, so it holds this monitor's key and runs the clock: the only
// runtimes the monitor may quarantine. One that never took the config (a
// build without the clock routes, or one the push has not reached) has
// no clock to be wrong, and cannot answer a poll: holding it to the clock
// would take it out of service for being what it is. A list that does
// not say (an older control plane) arms nothing.
func (e Enclave) ClockArmed() bool {
	return e.ClockConfigKnown && e.ClockConfigCurrent > 0 && e.ClockConfigVersion >= e.ClockConfigCurrent
}

// ClockNeverConfigured reports whether the control plane says the runtime
// never acknowledged any clock config.
func (e Enclave) ClockNeverConfigured() bool {
	return e.ClockConfigKnown && e.ClockConfigVersion == 0
}

// IsVault reports whether the runtime is a vault: polled directly at its
// own address, and never quarantined (callers reach a vault directly, not
// through a gateway), only alerted on.
func (e Enclave) IsVault() bool {
	return strings.EqualFold(e.Kind, model.ClockKindVault)
}

// KindOrDefault is the runtime's kind, "enclave" when the control plane
// named none.
func (e Enclave) KindOrDefault() string {
	if e.IsVault() {
		return model.ClockKindVault
	}
	return model.ClockKindEnclave
}

// IsSGX reports whether the enclave runs the SGX runtime, whose clock
// endpoint lives on its core rather than on a manager API. Every vault
// does.
func (e Enclave) IsSGX() bool {
	return e.IsVault() || strings.EqualFold(e.TeeType, "sgx") || strings.EqualFold(e.TeeType, "mini")
}

// PollPath is where the enclave's runtime takes a floor.
func (e Enclave) PollPath() string {
	if e.IsSGX() {
		return "/clock/poll"
	}
	return "/api/v1/clock/poll"
}

// IdentitySource mints the attested-app headers for one call: the
// identity certificate (DER), and a quote proving it for the challenge.
type IdentitySource func(ctx context.Context, challenge []byte) (certDER, quote []byte, err error)

// Platform is the control-plane client.
type Platform struct {
	baseURL  string
	identity IdentitySource
	now      func() time.Time
	hc       *http.Client
}

// NewPlatform returns a client. now is the clock the challenge
// timestamp is taken from, which should be the trusted one: the control
// plane refuses a challenge more than a few minutes from its own time.
func NewPlatform(baseURL string, identity IdentitySource, now func() time.Time) *Platform {
	return &Platform{
		baseURL:  strings.TrimRight(baseURL, "/"),
		identity: identity, now: now,
		hc: &http.Client{Timeout: 20 * time.Second},
	}
}

// ErrNoIdentity means the monitor is not running on the platform, so it
// has no attested identity to call the control plane with.
var ErrNoIdentity = errors.New("clock: no attested app identity is available (not running on the platform)")

// challenge is 32 bytes: the Unix seconds, big-endian, then randomness.
func (p *Platform) challenge() ([]byte, error) {
	c := make([]byte, 32)
	binary.BigEndian.PutUint64(c[:8], uint64(p.now().Unix()))
	if _, err := rand.Read(c[8:]); err != nil {
		return nil, err
	}
	return c, nil
}

func (p *Platform) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	if p.identity == nil {
		return 0, ErrNoIdentity
	}
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, rdr)
	if err != nil {
		return 0, err
	}
	challenge, err := p.challenge()
	if err != nil {
		return 0, err
	}
	cert, quote, err := p.identity(ctx, challenge)
	if err != nil {
		return 0, fmt.Errorf("clock: attested identity: %w", err)
	}
	req.Header.Set("X-Privasys-App-Identity", base64.StdEncoding.EncodeToString(cert))
	req.Header.Set("X-Privasys-App-Challenge", base64.StdEncoding.EncodeToString(challenge))
	req.Header.Set("X-Privasys-App-Evidence", base64.StdEncoding.EncodeToString(quote))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("clock: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("clock: %s %s answered %d: %s",
			method, path, resp.StatusCode, truncate(strings.TrimSpace(string(raw)), 300))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("clock: %s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// Enclaves lists the active enclaves, each stamped with the current clock
// config version the list carries.
func (p *Platform) Enclaves(ctx context.Context) ([]Enclave, error) {
	var out struct {
		Current  *int64    `json:"clock_config_current_version"`
		Enclaves []Enclave `json:"enclaves"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/api/v1/platform/enclaves", nil, &out); err != nil {
		return nil, err
	}
	if out.Current != nil {
		for i := range out.Enclaves {
			out.Enclaves[i].ClockConfigCurrent = *out.Current
			out.Enclaves[i].ClockConfigKnown = true
		}
	}
	return out.Enclaves, nil
}

// quarantineBody is what a quarantine or a release carries.
type quarantineBody struct {
	Reason   string         `json:"reason"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

// Quarantine asks the platform to stop serving an enclave's apps.
func (p *Platform) Quarantine(ctx context.Context, enclaveID, reason string, evidence map[string]any) (int, error) {
	return p.do(ctx, http.MethodPost, "/api/v1/platform/enclaves/"+url.PathEscape(enclaveID)+"/quarantine",
		quarantineBody{Reason: reason, Evidence: evidence}, nil)
}

// Release asks the platform to serve an enclave's apps again.
func (p *Platform) Release(ctx context.Context, enclaveID, reason string, evidence map[string]any) (int, error) {
	return p.do(ctx, http.MethodDelete, "/api/v1/platform/enclaves/"+url.PathEscape(enclaveID)+"/quarantine",
		quarantineBody{Reason: reason, Evidence: evidence}, nil)
}

// AttestationCredentials returns the attestation server the platform
// verifies quotes with, and a short-lived token for it. The monitor
// uses them to have each runtime's quote checked, with no secret of its
// own configured.
func (p *Platform) AttestationCredentials(ctx context.Context) (server, token string, expires time.Time, err error) {
	var out struct {
		AttestationToken          string `json:"attestation_token"`
		AttestationTokenExpiresAt int64  `json:"attestation_token_expires_at"`
		Constellation             struct {
			AttestationServer string `json:"attestation_server"`
		} `json:"constellation"`
	}
	if _, err = p.do(ctx, http.MethodGet, "/api/v1/keyvaults/operated", nil, &out); err != nil {
		return "", "", time.Time{}, err
	}
	if out.AttestationToken == "" || out.Constellation.AttestationServer == "" {
		return "", "", time.Time{}, errors.New("clock: the platform returned no attestation server or token")
	}
	if out.AttestationTokenExpiresAt > 0 {
		expires = time.Unix(out.AttestationTokenExpiresAt, 0)
	}
	return out.Constellation.AttestationServer, out.AttestationToken, expires, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
