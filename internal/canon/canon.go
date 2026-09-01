// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package canon produces canonical JSON: the byte form that is hashed
// into transaction ids, payload commitments and checkpoint signatures.
//
// Two processes that agree on the logical value must agree on the
// bytes, so the encoding is fixed: object members sorted by key, no
// insignificant whitespace, shortest round-trip form for numbers, and
// minimal string escaping (no HTML escaping). It is deliberately a
// small subset of RFC 8785 — enough for the JSON the register itself
// produces, and strict about anything it cannot represent.
package canon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf8"
)

// Marshal renders v as canonical JSON. v is first normalised through
// encoding/json, so structs, maps and slices are all accepted.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var norm any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&norm); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := write(&buf, norm); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MustMarshal is Marshal for values known to be encodable.
func MustMarshal(v any) []byte {
	b, err := Marshal(v)
	if err != nil {
		panic("canon: " + err.Error())
	}
	return b
}

func write(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, t)
	case json.Number:
		return writeNumber(buf, t)
	case float64:
		return writeNumber(buf, json.Number(strconv.FormatFloat(t, 'g', -1, 64)))
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := write(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canon: unsupported type %T", v)
	}
	return nil
}

// writeNumber emits integers verbatim and floats in the shortest form
// that round-trips. NaN and infinities have no JSON form and are
// rejected rather than silently mangled.
func writeNumber(buf *bytes.Buffer, n json.Number) error {
	if i, err := strconv.ParseInt(n.String(), 10, 64); err == nil {
		buf.WriteString(strconv.FormatInt(i, 10))
		return nil
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		return fmt.Errorf("canon: bad number %q", n.String())
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canon: number %v has no JSON form", f)
	}
	buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
	return nil
}

const hexDigits = "0123456789abcdef"

func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			switch {
			case r < 0x20:
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[(r>>4)&0xf])
				buf.WriteByte(hexDigits[r&0xf])
			case r == utf8.RuneError:
				buf.WriteString(`\ufffd`)
			default:
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
