// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"enclave-os-mini/clients/go/ratls"
)

// Polling a runtime.
//
// A floor goes straight to the runtime's own address, the gateway_host
// and port the control plane lists, for an enclave as for a vault. No
// DNS name is resolved: a name the platform builds can be wrong (a
// display name with spaces made "EU France 1-mgr.apps.privasys.org",
// which resolves nowhere, and both prod SGX enclaves were quarantined as
// unreachable for it), and a lookup is one more thing a host could break
// between the monitor and its runtime. An enclave's manager hostname is
// sent only as the TLS server name, and only when it is a valid DNS name;
// otherwise no server name is sent at all (the virtual runtime's front
// routes a connection with an unknown or no server name to its manager
// API, and the SGX core serves its clock routes whatever the name). The
// monitor verifies the runtime's own certificate: its chain to the
// Privasys fleet, then a hardware quote obtained on the same connection
// and bound to it, checked by the attestation server. Only then is the
// floor sent. The reply is authentic because of that channel.

// PollResult is what one poll produced.
type PollResult struct {
	// Reply is the runtime's answer. Set only for a 200.
	Reply *PollReply
	// HTTPStatus is the runtime's status code, zero when it never
	// answered.
	HTTPStatus int
	// Body is the start of a non-200 answer, for the record.
	Body string
	// RTT is the round trip of the floor itself, on the monotonic clock,
	// excluding the handshake and the attestation.
	RTT time.Duration
	// PlatformID identifies the machine the verified quote came from.
	PlatformID string
}

// Poll errors, so the caller can tell "no answer" from "an answer that
// cannot be attributed to an enclave".
var (
	ErrUnreachable = errors.New("clock: the runtime could not be reached")
	ErrUnverified  = errors.New("clock: the runtime's attestation did not verify")
)

// Poller sends one floor to one enclave.
type Poller interface {
	Poll(ctx context.Context, e Enclave, req PollRequest) (*PollResult, error)
}

// PollTimeout bounds one poll: connection, attestation, and the answer.
// A runtime that disagrees with the floor fetches an NTS quorum before
// it answers, which it caps at about fifteen seconds.
const PollTimeout = 30 * time.Second

// CredentialSource returns the attestation server and a token for it.
type CredentialSource func(ctx context.Context) (server, token string, err error)

// RATLSPoller is the real poller.
type RATLSPoller struct {
	Credentials CredentialSource
	// AllowDebugImages accepts runtimes on development images.
	AllowDebugImages bool
	// Timeout bounds the connection, the attestation, and the exchange.
	Timeout time.Duration
}

// pollAddress is where a floor for e goes: the runtime's own host:port,
// and the server name to send, if any: an enclave's manager hostname when
// it is a valid DNS name, never for a vault (nothing routes by name in
// front of one).
func pollAddress(e Enclave) (host string, port int, serverName string, err error) {
	if e.GatewayHost == "" || e.Port <= 0 {
		return "", 0, "", fmt.Errorf("%w: the platform gave no address for %s %s", ErrUnreachable, e.KindOrDefault(), e.Name)
	}
	if !e.IsVault() && isDNSName(e.MgrHostname) {
		serverName = e.MgrHostname
	}
	return e.GatewayHost, e.Port, serverName, nil
}

// isDNSName reports whether s is a hostname a TLS client may send as a
// server name: dot-separated labels of 1 to 63 letters, digits or
// hyphens, none starting or ending with a hyphen, at most 253 bytes, and
// not an IP address.
func isDNSName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Poll implements Poller.
func (p *RATLSPoller) Poll(ctx context.Context, e Enclave, req PollRequest) (*PollResult, error) {
	host, port, serverName, err := pollAddress(e)
	if err != nil {
		return nil, err
	}
	server, token, err := p.Credentials(ctx)
	if err != nil {
		// Our side: without a verifier the answer could not be trusted, so
		// the floor is not sent at all.
		return nil, fmt.Errorf("clock: attestation credentials: %w", err)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = PollTimeout
	}
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < timeout {
			timeout = left
		}
	}

	// No client identity: the signed floor authenticates the monitor, and a
	// runtime that has no trusted time cannot verify a caller's evidence
	// (that is a decision on time, so it fails closed). Presenting one
	// would make exactly the runtimes that most need a poll unreachable.
	opts := &ratls.Options{
		ServerName:  serverName,
		Timeout:     timeout,
		Attestation: ratls.AttestationChallenge,
	}
	cli, err := ratls.Connect(host, port, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer cli.Close()

	tee := ratls.TeeTypeTDX
	if e.IsSGX() {
		tee = ratls.TeeTypeSGX
	}
	info, err := cli.VerifyCertificate(&ratls.VerificationPolicy{
		TEE:               tee,
		QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: server, Token: token},
		AllowDebugImages:  p.AllowDebugImages,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnverified, err)
	}
	result := &PollResult{}
	if info.QuoteVerification != nil {
		result.PlatformID = info.QuoteVerification.PlatformID()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	_ = cli.Conn().SetDeadline(time.Now().Add(timeout))
	started := time.Now()
	hostHeader := serverName
	if hostHeader == "" {
		hostHeader = host
	}
	resp, err := cli.HTTPDo("POST", e.PollPath(), hostHeader, body, "")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	result.RTT = time.Since(started)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the answer: %v", ErrUnreachable, err)
	}
	result.HTTPStatus = resp.StatusCode
	if resp.StatusCode != 200 {
		result.Body = truncate(string(bytes.TrimSpace(raw)), 300)
		return result, nil
	}
	var reply PollReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		result.Body = truncate(string(bytes.TrimSpace(raw)), 300)
		return result, nil
	}
	result.Reply = &reply
	return result, nil
}
