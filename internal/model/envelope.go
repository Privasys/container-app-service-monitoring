// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package model holds the wire and storage types shared by the monitor
// core, the HTTP surface and the offline verifier.
//
// The central type is Envelope, the git-like commit message every
// state-changing transaction carries. The envelope and the write set
// are hashed together into the transaction id, and both are stored
// verbatim in the ledger, so the root commits to the reason for a
// change as well as to the change itself. An availability record is
// only worth what its provenance is worth: a maintenance window with no
// author and no declared-at is exactly the kind of entry a dispute
// turns on.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Reference types linking one transaction to earlier work.
const (
	RefCorrects   = "corrects"
	RefSupersedes = "supersedes"
	RefResolves   = "resolves"
	RefRelates    = "relates"
)

// Transaction kinds. The kind tells the explorer, the status page and
// the callback consumers what happened without parsing the write set.
const (
	KindConfigure          = "config.set"
	KindServiceUpsert      = "service.upsert"
	KindComponentUpsert    = "component.upsert"
	KindMonitorUpsert      = "monitor.upsert"
	KindMonitorRetire      = "monitor.retire"
	KindObjectiveUpsert    = "objective.upsert"
	KindScheduleUpsert     = "schedule.upsert"
	KindSecretPut          = "secret.put"
	KindSecretDestroy      = "secret.destroy"
	KindSamples            = "samples.record"
	KindRollup             = "rollup.fold"
	KindStateChange        = "state.change"
	KindIncidentOpen       = "incident.open"
	KindIncidentUpdate     = "incident.update"
	KindMaintenanceDeclare = "maintenance.declare"
	KindMaintenanceCancel  = "maintenance.cancel"
	KindAlertEmit          = "alert.emit"
	KindAlertDeliver       = "alert.deliver"
	KindReportIssue        = "report.issue"
	KindCheckpoint         = "checkpoint.issue"
	KindRetentionPrune     = "retention.prune"
	KindRuntimeEvent       = "runtime.event"
	KindPackSeed           = "pack.seed"
)

// Ref is a typed link from a transaction to an earlier transaction or
// to an object.
type Ref struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

// Author identifies who made a change and in which capacity. Sub is the
// OIDC subject; Role is the role the author was acting under, which is
// not necessarily the only role they hold. The monitor writes its own
// observations under the reserved system subject, so a reader can tell
// a measured fact from a human assertion at a glance.
type Author struct {
	Sub     string `json:"sub"`
	Display string `json:"display,omitempty"`
	Role    string `json:"role"`
}

// SystemAuthor is the author of everything the monitor observes rather
// than is told.
func SystemAuthor() Author {
	return Author{Sub: "system", Display: "Monitor", Role: "system"}
}

// Envelope is the commit envelope hashed into every transaction.
type Envelope struct {
	Kind      string   `json:"kind"`
	Tenant    string   `json:"tenant"`
	Service   string   `json:"service,omitempty"`
	ObjectIDs []string `json:"object_ids,omitempty"`
	Author    Author   `json:"author"`
	Timestamp int64    `json:"timestamp"`
	Message   string   `json:"message"`
	Refs      []Ref    `json:"refs,omitempty"`
}

// MaxSummary is the git convention the API enforces on the first line.
const MaxSummary = 72

// Summary returns the first line of the message.
func (e *Envelope) Summary() string {
	if i := strings.IndexByte(e.Message, '\n'); i >= 0 {
		return e.Message[:i]
	}
	return e.Message
}

// Body returns everything after the summary line.
func (e *Envelope) Body() string {
	i := strings.IndexByte(e.Message, '\n')
	if i < 0 {
		return ""
	}
	return strings.TrimLeft(e.Message[i+1:], "\n")
}

var refTypes = map[string]bool{
	RefCorrects: true, RefSupersedes: true, RefResolves: true, RefRelates: true,
}

// Validate rejects messageless and malformed envelopes. A transaction
// without a reason is not accepted at any layer: the API refuses it, so
// the ledger never sees one.
func (e *Envelope) Validate() error {
	if e.Kind == "" {
		return errors.New("envelope: kind is required")
	}
	if e.Tenant == "" {
		return errors.New("envelope: tenant is required")
	}
	if e.Author.Sub == "" {
		return errors.New("envelope: author.sub is required")
	}
	if e.Author.Role == "" {
		return errors.New("envelope: author.role is required")
	}
	if e.Timestamp <= 0 {
		return errors.New("envelope: timestamp is required")
	}
	summary := strings.TrimSpace(e.Summary())
	if summary == "" {
		return errors.New("envelope: a change needs a message saying why")
	}
	if len(summary) > MaxSummary {
		return fmt.Errorf("envelope: the summary line is %d characters, the limit is %d",
			len(summary), MaxSummary)
	}
	if strings.HasSuffix(summary, ".") {
		return errors.New("envelope: the summary line does not end with a full stop")
	}
	for _, r := range e.Refs {
		if !refTypes[r.Type] {
			return fmt.Errorf("envelope: unknown reference type %q", r.Type)
		}
		if r.Target == "" {
			return fmt.Errorf("envelope: reference %q has no target", r.Type)
		}
	}
	return nil
}

// TxID is the transaction identifier: SHA-256 over the canonical
// envelope and the canonical write set together. Binding them into one
// hash is what makes a change and the reason for it a single object;
// neither can be substituted without changing the id the ledger commits
// to.
func TxID(envelope, writeSet []byte) string {
	h := sha256.New()
	h.Write([]byte("privasys-monitor/txid/v1"))
	var size [8]byte
	putUint64(size[:], uint64(len(envelope)))
	h.Write(size[:])
	h.Write(envelope)
	putUint64(size[:], uint64(len(writeSet)))
	h.Write(size[:])
	h.Write(writeSet)
	return hex.EncodeToString(h.Sum(nil))
}

func putUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}
