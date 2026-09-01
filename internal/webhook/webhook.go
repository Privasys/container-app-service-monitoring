// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package webhook delivers alerts to a customer's callback.
//
// Three things make this more than an HTTP POST.
//
// The body is signed. A receiver checks an Ed25519 signature against a
// key published at /.well-known/privasys-monitor.json, and that key is
// committed to the RA-TLS leaf certificate, so a notification that
// claims to come from the monitor can be shown to have.
//
// The body carries the ledger coordinates of the change it reports. A
// receiver can take the root and version to the monitor and be handed
// the readings that caused the alert, rather than a summary of them.
//
// Every attempt is recorded, not only the successful one. "You never
// told us" and "you told us six hours late" both become questions with
// answers.
package webhook

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/canon"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
)

// Schema is the payload version, so a receiver can tell what it is
// parsing before it parses it.
const Schema = "privasys.monitor.alert/v1"

// Headers the receiver checks.
const (
	HeaderSignature  = "X-Privasys-Signature"
	HeaderKeyID      = "X-Privasys-Key-Id"
	HeaderTimestamp  = "X-Privasys-Timestamp"
	HeaderDeliveryID = "X-Privasys-Delivery-Id"
	HeaderEvent      = "X-Privasys-Event"
)

// Retry policy. Delivery is retried with a widening gap and then given
// up on: an alert that has been failing for a quarter of an hour is a
// broken callback, not a slow one, and the attempts are all recorded
// either way.
var backoff = []time.Duration{0, 5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}

// Envelope is the signed body.
type Envelope struct {
	Schema string `json:"schema"`
	// ID is the alert's identifier, stable across retries, which is what
	// a receiver deduplicates on.
	ID        string         `json:"id"`
	Event     string         `json:"event"`
	Instance  string         `json:"instance"`
	ServiceID string         `json:"service_id"`
	Subject   string         `json:"subject"`
	CreatedAt int64          `json:"created_at"`
	DedupKey  string         `json:"dedup_key"`
	Payload   map[string]any `json:"payload"`
	// LedgerRoot and LedgerVersion locate the change in the record, so
	// the alert is a pointer to evidence rather than a claim.
	LedgerRoot    string `json:"ledger_root"`
	LedgerVersion uint64 `json:"ledger_version"`
	ImageDigest   string `json:"image_digest,omitempty"`
}

// Sender delivers alerts.
type Sender struct {
	mon    *core.Monitor
	signer ed25519.PrivateKey
	keyID  string
	egress *journey.Allowlist
	log    *slog.Logger
	client *http.Client
	queue  chan job
}

type job struct {
	alert core.Alert
	url   string
}

// New returns a sender with a bounded queue. Delivery never blocks the
// scheduler: a callback that hangs must not stop the monitor watching.
func New(mon *core.Monitor, signer ed25519.PrivateKey, keyID string,
	egress *journey.Allowlist, log *slog.Logger) *Sender {
	return &Sender{
		mon: mon, signer: signer, keyID: keyID, egress: egress, log: log,
		client: &http.Client{Timeout: 20 * time.Second},
		queue:  make(chan job, 512),
	}
}

// Run processes the queue until the context is cancelled.
func (s *Sender) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-s.queue:
			s.deliver(ctx, j)
		}
	}
}

// Enqueue schedules an alert for delivery to a service's callback.
func (s *Sender) Enqueue(a core.Alert) {
	url := s.callbackFor(a.ServiceID)
	if url == "" {
		return
	}
	select {
	case s.queue <- job{alert: a, url: url}:
	default:
		s.log.Error("the delivery queue is full; an alert was not queued", "alert", a.ID)
	}
}

func (s *Sender) callbackFor(serviceID string) string {
	svc, err := s.mon.Service(serviceID)
	if err != nil || svc == nil {
		return ""
	}
	return svc.CallbackURL
}

func (s *Sender) deliver(ctx context.Context, j job) {
	body, err := s.body(j.alert)
	if err != nil {
		s.log.Error("could not build the alert body", "alert", j.alert.ID, "error", err)
		return
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(s.signer, body))

	for attempt := 1; attempt <= len(backoff); attempt++ {
		if wait := backoff[attempt-1]; wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		status, duration, err := s.post(ctx, j.url, body, signature, j.alert)
		delivered := err == nil && status >= 200 && status < 300
		message := ""
		if err != nil {
			message = err.Error()
		}
		if recErr := s.mon.RecordDelivery(j.alert.ID, j.url, attempt, status,
			duration, message, delivered); recErr != nil {
			s.log.Error("could not record a delivery attempt", "alert", j.alert.ID, "error", recErr)
		}
		if delivered {
			return
		}
	}
	s.log.Error("gave up delivering an alert", "alert", j.alert.ID, "url", j.url)
}

func (s *Sender) post(ctx context.Context, url string, body []byte, signature string,
	a core.Alert) (status, durationMs int, err error) {

	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	// The callback host is on the allowlist by construction: it is added
	// when the callback is configured. Checking again here means a
	// configuration that changed underneath cannot deliver to somewhere
	// nobody declared.
	if s.egress != nil {
		if err := s.egress.Check(req.URL.Host); err != nil {
			return 0, 0, err
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderSignature, "ed25519="+signature)
	req.Header.Set(HeaderKeyID, s.keyID)
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(a.CreatedAt, 10))
	req.Header.Set(HeaderDeliveryID, a.ID)
	req.Header.Set(HeaderEvent, a.Event)

	resp, err := s.client.Do(req)
	durationMs = int(time.Since(started) / time.Millisecond)
	if err != nil {
		return 0, durationMs, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, durationMs, fmt.Errorf("the callback answered %d", resp.StatusCode)
	}
	return resp.StatusCode, durationMs, nil
}

// body renders the canonical bytes that are signed and sent. The
// signature covers exactly what the receiver reads, so there is no
// re-serialisation between the two.
func (s *Sender) body(a core.Alert) ([]byte, error) {
	opts := s.mon.Options()
	return canon.Marshal(Envelope{
		Schema: Schema, ID: a.ID, Event: a.Event, Instance: opts.Name,
		ServiceID: a.ServiceID, Subject: a.Subject, CreatedAt: a.CreatedAt,
		DedupKey: a.DedupKey, Payload: a.Payload,
		LedgerRoot: a.LedgerRoot, LedgerVersion: a.LedgerVersion,
		ImageDigest: opts.ImageDigest,
	})
}

// Verify checks a delivered body against a public key. It is exported
// so a receiver can vendor the same check the sender applies rather
// than reimplementing it from prose.
func Verify(pub ed25519.PublicKey, body []byte, signatureHeader string) error {
	const prefix = "ed25519="
	if len(signatureHeader) <= len(prefix) || signatureHeader[:len(prefix)] != prefix {
		return fmt.Errorf("webhook: the signature header is not an ed25519 signature")
	}
	sig, err := base64.StdEncoding.DecodeString(signatureHeader[len(prefix):])
	if err != nil {
		return fmt.Errorf("webhook: signature: %w", err)
	}
	if !ed25519.Verify(pub, body, sig) {
		return fmt.Errorf("webhook: the signature does not verify")
	}
	return nil
}
