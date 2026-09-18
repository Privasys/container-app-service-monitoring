// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package clock is the platform clock: an optional mode in which this
// monitor watches the time of every enclave of a Privasys fleet rather
// than a customer's service.
//
// Every enclave takes its time from its host, and a host that rolls its
// clock back can get expired credentials accepted. The enclave runtimes
// defend themselves: they compare the host's time with a signed "the
// time is at least T" that this monitor sends them, and when the two
// disagree they ask Network Time Security servers on the internet which
// of the two is wrong. This package is the monitor's half of that. It
// keeps its own trusted time from NTS, signs and sends the floors,
// records every reply in the ledger, receives the incidents the
// runtimes report, and asks the platform to stop routing users to an
// enclave whose host clock is wrong until it is fixed.
//
// The monitor only ever triggers. Its time never becomes an enclave's
// trusted time on its own: a runtime that disagrees with it asks NTS,
// so a monitor that is wrong, or lies, causes an NTS fetch and a false
// alarm, never a wrong time.
package clock

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Signature domains. A signed payload is the domain followed by its
// fields, one per line, with no trailing newline, so a floor can never
// be read as a receipt or the other way round.
const (
	FloorDomain   = "privasys-clock-floor/v1"
	ReceiptDomain = "privasys-clock-receipt/v1"
)

// Poll verdicts, as a runtime reports them.
const (
	// VerdictInSync: the host and the floor agree within the tolerance.
	VerdictInSync = "in_sync"
	// VerdictMonitorWrong: the host and NTS agree and the floor does not.
	// The monitor is the party with the problem.
	VerdictMonitorWrong = "monitor_clock_wrong"
	// VerdictHostWrong: the floor and NTS agree and the host does not.
	// The runtime has frozen its time at the NTS time.
	VerdictHostWrong = "host_clock_wrong"
	// VerdictIgnoredStale: the floor was below the runtime's own, so it
	// said nothing (a replay, or a monitor running slow).
	VerdictIgnoredStale = "ignored_stale"
)

// Incident reasons a runtime may report.
const (
	ReasonHostBehindFloor   = "host_behind_floor"
	ReasonHostClockWrong    = "host_clock_wrong"
	ReasonMonitorClockWrong = "monitor_clock_wrong"
	ReasonNTSUnreachable    = "nts_unreachable"
)

// Tolerance is how far a host clock may be from the monitor's before
// the two are said to disagree, in milliseconds. It is the runtimes'
// tolerance, and the monitor's drift alarm uses the same figure.
const Tolerance = int64(10_000)

// b64 is base64url without padding, the encoding of every key, nonce
// and signature on the wire.
var b64 = base64.RawURLEncoding

// KeyID names an Ed25519 public key: the first sixteen hex characters
// of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// FloorBytes are the exact bytes a floor's signature covers.
func FloorBytes(enclaveID string, tMs, seq int64) []byte {
	return []byte(FloorDomain + "\n" + enclaveID + "\n" +
		strconv.FormatInt(tMs, 10) + "\n" + strconv.FormatInt(seq, 10))
}

// ReceiptBytes are the exact bytes a receipt's signature covers.
func ReceiptBytes(enclaveID, nonce, incidentID string) []byte {
	return []byte(ReceiptDomain + "\n" + enclaveID + "\n" + nonce + "\n" + incidentID)
}

// PollRequest is a signed floor: "for this enclave, the time is at
// least t_ms". The signature is the authentication; the request carries
// no bearer.
type PollRequest struct {
	EnclaveID string `json:"enclave_id"`
	TMs       int64  `json:"t_ms"`
	Seq       int64  `json:"seq"`
	KeyID     string `json:"key_id"`
	Sig       string `json:"sig"`
}

// PollNTS is the NTS time a runtime fetched to settle a disagreement,
// when it fetched one.
type PollNTS struct {
	TimeMs  int64    `json:"time_ms"`
	Servers []string `json:"servers"`
}

// PollReply is a runtime's answer. It is authentic because it arrives
// over an RA-TLS connection whose quote this monitor verified, not
// because it is signed.
type PollReply struct {
	EnclaveID     string  `json:"enclave_id"`
	Runtime       string  `json:"runtime"`
	HostTimeMs    int64   `json:"host_time_ms"`
	TrustedTimeMs int64   `json:"trusted_time_ms"`
	FloorMs       int64   `json:"floor_ms"`
	Flagged       bool    `json:"flagged"`
	Reason        string  `json:"reason"`
	Verdict       string  `json:"verdict"`
	NTS           PollNTS `json:"nts"`
	ConfigKeyID   string  `json:"config_key_id"`
}

// IncidentReport is what a runtime sends when its host clock goes
// wrong between two polls. Anyone can send one; the monitor records it,
// answers it, and acts only on what polling the enclave then shows.
type IncidentReport struct {
	EnclaveID  string `json:"enclave_id"`
	Reason     string `json:"reason"`
	HostTimeMs int64  `json:"host_time_ms"`
	FloorMs    int64  `json:"floor_ms"`
	NTSTimeMs  int64  `json:"nts_time_ms"`
	Nonce      string `json:"nonce"`
}

// Validate checks the shape of a report. It says nothing about whether
// the report is true.
func (r *IncidentReport) Validate() error {
	r.EnclaveID = strings.TrimSpace(r.EnclaveID)
	r.Reason = strings.TrimSpace(r.Reason)
	switch {
	case r.EnclaveID == "":
		return errors.New("clock: an incident needs an enclave_id")
	case len(r.EnclaveID) > 96:
		return errors.New("clock: enclave_id is too long")
	case r.Reason == "":
		return errors.New("clock: an incident needs a reason")
	case len(r.Reason) > 64:
		return errors.New("clock: reason is too long")
	}
	// The nonce is checked, never rewritten: the receipt signs it exactly
	// as the runtime spelled it, which is what the runtime compares.
	nonce, err := b64.DecodeString(strings.TrimRight(r.Nonce, "="))
	if err != nil || len(nonce) != 32 || len(r.Nonce) > 64 {
		return errors.New("clock: nonce must be 32 bytes, base64url")
	}
	return nil
}

// Receipt is the monitor's signed acknowledgement of an incident. A
// runtime that does not get one fails closed, so a receipt is always
// sent, and sent quickly.
type Receipt struct {
	IncidentID string `json:"incident_id"`
	Nonce      string `json:"nonce"`
	KeyID      string `json:"key_id"`
	Sig        string `json:"sig"`
}

// Signer holds the platform clock key.
type Signer struct {
	key ed25519.PrivateKey
	pub ed25519.PublicKey
	id  string
}

// NewSigner wraps a private key.
func NewSigner(key ed25519.PrivateKey) *Signer {
	pub := key.Public().(ed25519.PublicKey)
	return &Signer{key: key, pub: pub, id: KeyID(pub)}
}

// PublicKey is the verification key the runtimes pin.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.pub }

// KeyID names the key.
func (s *Signer) KeyID() string { return s.id }

// EncodedPublicKey is the key in the encoding the platform delivers it
// in.
func (s *Signer) EncodedPublicKey() string { return b64.EncodeToString(s.pub) }

// Floor signs a floor for one enclave.
func (s *Signer) Floor(enclaveID string, tMs, seq int64) PollRequest {
	sig := ed25519.Sign(s.key, FloorBytes(enclaveID, tMs, seq))
	return PollRequest{
		EnclaveID: enclaveID, TMs: tMs, Seq: seq,
		KeyID: s.id, Sig: b64.EncodeToString(sig),
	}
}

// Receipt signs the acknowledgement of one incident.
func (s *Signer) Receipt(enclaveID, nonce, incidentID string) Receipt {
	sig := ed25519.Sign(s.key, ReceiptBytes(enclaveID, nonce, incidentID))
	return Receipt{
		IncidentID: incidentID, Nonce: nonce,
		KeyID: s.id, Sig: b64.EncodeToString(sig),
	}
}

// VerifyFloor checks a floor against a public key, as a runtime does.
func VerifyFloor(pub ed25519.PublicKey, req PollRequest) error {
	if !strings.EqualFold(req.KeyID, KeyID(pub)) {
		return fmt.Errorf("clock: the floor names key %q, not %q", req.KeyID, KeyID(pub))
	}
	sig, err := b64.DecodeString(strings.TrimRight(req.Sig, "="))
	if err != nil {
		return fmt.Errorf("clock: the floor signature is not base64url")
	}
	if !ed25519.Verify(pub, FloorBytes(req.EnclaveID, req.TMs, req.Seq), sig) {
		return errors.New("clock: the floor signature does not verify")
	}
	return nil
}

// VerifyReceipt checks a receipt against a public key, as a runtime
// does before it treats its incident as delivered.
func VerifyReceipt(pub ed25519.PublicKey, enclaveID string, r Receipt) error {
	if !strings.EqualFold(r.KeyID, KeyID(pub)) {
		return fmt.Errorf("clock: the receipt names key %q, not %q", r.KeyID, KeyID(pub))
	}
	sig, err := b64.DecodeString(strings.TrimRight(r.Sig, "="))
	if err != nil {
		return fmt.Errorf("clock: the receipt signature is not base64url")
	}
	if !ed25519.Verify(pub, ReceiptBytes(enclaveID, r.Nonce, r.IncidentID), sig) {
		return errors.New("clock: the receipt signature does not verify")
	}
	return nil
}
