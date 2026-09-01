// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package secrets

import (
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
)

// Redactor removes credential values from anything the monitor is about
// to write down.
//
// It is a writer applied before storage rather than a scrubber applied
// afterwards: a capture is redacted on the way out of the journey
// engine, so no code path exists that could persist a value and be
// cleaned up later. The alternative, cleaning stored text, has to be
// perfect every time; this only has to be applied once, at the one
// place text leaves the engine.
//
// Values are removed in their raw form and in the forms an HTTP
// exchange routinely produces: percent-encoded, and base64 as an HTTP
// basic credential or a token echoed back in a body.
type Redactor struct {
	// pairs is ordered longest first, so a value that contains another
	// value is replaced before its substring is.
	pairs []pair
}

type pair struct {
	from string
	to   string
}

// NewRedactor builds a redactor over named values.
func NewRedactor() *Redactor { return &Redactor{} }

// Add registers a value to remove. Empty and very short values are
// ignored: a one-character "secret" would redact the whole capture and
// tell the reader nothing, which is worse than useless when a responder
// is trying to see what the service said.
func (r *Redactor) Add(name, value string) {
	if len(value) < 4 {
		return
	}
	marker := "[redacted:" + name + "]"
	r.add(value, marker)
	if enc := url.QueryEscape(value); enc != value {
		r.add(enc, marker)
	}
	r.add(base64.StdEncoding.EncodeToString([]byte(value)), marker)
	// The basic-auth form, where the value is the password half.
	r.add(base64.StdEncoding.EncodeToString([]byte(":"+value)), marker)
}

func (r *Redactor) add(from, to string) {
	if from == "" {
		return
	}
	for _, p := range r.pairs {
		if p.from == from {
			return
		}
	}
	r.pairs = append(r.pairs, pair{from: from, to: to})
	sort.SliceStable(r.pairs, func(i, j int) bool {
		return len(r.pairs[i].from) > len(r.pairs[j].from)
	})
}

// Redact returns s with every registered value replaced.
func (r *Redactor) Redact(s string) string {
	if r == nil || s == "" {
		return s
	}
	for _, p := range r.pairs {
		if strings.Contains(s, p.from) {
			s = strings.ReplaceAll(s, p.from, p.to)
		}
	}
	return s
}

// Leaks reports whether s still contains a registered value. It is the
// assertion the journey engine makes against its own output before
// anything is written, so a redaction bug fails the sample rather than
// publishing the credential.
func (r *Redactor) Leaks(s string) bool {
	if r == nil || s == "" {
		return false
	}
	for _, p := range r.pairs {
		if strings.Contains(s, p.from) {
			return true
		}
	}
	return false
}

// Empty reports whether the redactor has nothing to remove.
func (r *Redactor) Empty() bool { return r == nil || len(r.pairs) == 0 }
