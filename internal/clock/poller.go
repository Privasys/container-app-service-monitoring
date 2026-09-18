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
	"time"

	"enclave-os-mini/clients/go/ratls"
)

// Polling a runtime.
//
// A floor goes to an enclave's manager hostname, the one route the
// gateways keep serving while an enclave is quarantined. The connection
// advertises the RA-TLS protocol marker, so the gateway splices it
// straight through to the enclave instead of terminating it, and the
// monitor verifies the enclave's own certificate: its chain to the
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

// CredentialSource returns the attestation server and a token for it.
type CredentialSource func(ctx context.Context) (server, token string, err error)

// RATLSPoller is the real poller.
type RATLSPoller struct {
	Credentials CredentialSource
	// AllowDebugImages accepts runtimes on development images.
	AllowDebugImages bool
	// Identity, when set, is presented to a runtime that asks the caller
	// for its own attestation.
	Identity *ratls.EgressIdentity
	// Timeout bounds the connection, the attestation, and the exchange.
	Timeout time.Duration
}

// Poll implements Poller.
func (p *RATLSPoller) Poll(ctx context.Context, e Enclave, req PollRequest) (*PollResult, error) {
	host := e.MgrHostname
	if host == "" {
		return nil, fmt.Errorf("%w: the platform gave no manager hostname for %s", ErrUnreachable, e.Name)
	}
	server, token, err := p.Credentials(ctx)
	if err != nil {
		// Our side: without a verifier the answer could not be trusted, so
		// the floor is not sent at all.
		return nil, fmt.Errorf("clock: attestation credentials: %w", err)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < timeout {
			timeout = left
		}
	}

	opts := &ratls.Options{
		ServerName:  host,
		Timeout:     timeout,
		Attestation: ratls.AttestationChallenge,
	}
	if p.Identity != nil {
		opts.GetClientCertificate = p.Identity.GetClientCertificate
		opts.ClientEvidence = p.Identity.ClientEvidence
	}
	cli, err := ratls.Connect(host, 443, opts)
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
	resp, err := cli.HTTPDo("POST", e.PollPath(), host, body, "")
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
