// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package model

import (
	"encoding/base64"
	"encoding/json"
)

// WriteOp is one effect of a transaction: an upsert or a delete, keyed
// by primary key.
//
// The write set is declarative and is stored verbatim alongside the
// envelope, hashed into the transaction id. So the record does not only
// say that something changed and why; it says exactly what the change
// was, in a form that can be re-read and compared against the rows that
// are there now.
type WriteOp struct {
	Table  string         `json:"table"`
	Key    map[string]any `json:"key"`
	Values map[string]any `json:"values,omitempty"`
	Delete bool           `json:"delete,omitempty"`
}

// TxIDPlaceholder stands in for the transaction id inside a write set.
// The id is a hash over the write set, so a row that wants to carry it
// cannot contain it literally.
const TxIDPlaceholder = "$txid"

// Binary is a byte column's value inside a write set.
//
// A write set is stored as JSON, and encoding/json turns a plain []byte
// into a bare base64 string, indistinguishable from text on the way
// back. Every definition document, capture and signature written here
// is a byte column, so the encoding is tagged: what goes in as bytes
// comes back as bytes, whatever route it took.
type Binary []byte

// MarshalJSON tags the value so the decoder can tell it from a string.
func (b Binary) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{binaryTag: base64.StdEncoding.EncodeToString(b)})
}

const binaryTag = "$bytes"

// DecodeBinary recognises a tagged byte value produced by Binary.
func DecodeBinary(v any) ([]byte, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return nil, false
	}
	encoded, ok := m[binaryTag].(string)
	if !ok {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

// Transaction is the full committed record: the envelope, the write
// set, and where the ledger stood on either side of it.
type Transaction struct {
	Seq           uint64    `json:"seq"`
	TxID          string    `json:"txid"`
	Envelope      Envelope  `json:"envelope"`
	WriteSet      []WriteOp `json:"write_set,omitempty"`
	RootBefore    string    `json:"root_before"`
	VersionBefore uint64    `json:"version_before"`
	VersionAfter  uint64    `json:"version_after"`
}

// Summary is the transaction's first message line, for a log listing.
func (t *Transaction) Summary() string { return t.Envelope.Summary() }
