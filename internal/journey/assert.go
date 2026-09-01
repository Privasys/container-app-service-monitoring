// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package journey

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// Assertions are what make a journey a measurement of the service
// rather than of the network. A 200 with an empty body is a passing
// ping and a failing order.

// observation is what one request produced, and what assertions read.
type observation struct {
	status  int
	latency int
	headers map[string]string
	body    string
	// decoded is the body parsed as JSON, or nil when it is not JSON.
	// It is decoded once per step, not once per assertion.
	decoded   any
	decodedOK bool
	vars      map[string]string
}

func (o *observation) json() (any, bool) {
	if o.decodedOK {
		return o.decoded, o.decoded != nil
	}
	o.decodedOK = true
	var v any
	if err := json.Unmarshal([]byte(o.body), &v); err != nil {
		o.decoded = nil
		return nil, false
	}
	o.decoded = v
	return v, true
}

// evaluate runs one assertion and returns the reason it failed, or the
// empty string when it held.
func (o *observation) evaluate(a model.Assertion) string {
	actual, present, err := o.value(a)
	if err != "" {
		return err
	}
	switch a.Op {
	case model.OpExists:
		if !present {
			return describe(a, "is not present")
		}
		return ""
	case model.OpAbsent:
		if present {
			return describe(a, fmt.Sprintf("is present (%s)", short(actual)))
		}
		return ""
	}
	if !present {
		return describe(a, "is not present")
	}
	switch a.Op {
	case model.OpEq:
		if !equalish(actual, a.Value) {
			return describe(a, fmt.Sprintf("is %s, expected %s", short(actual), short(a.Value)))
		}
	case model.OpNe:
		if equalish(actual, a.Value) {
			return describe(a, fmt.Sprintf("is %s, which was excluded", short(actual)))
		}
	case model.OpContains:
		if !strings.Contains(actual, a.Value) {
			return describe(a, fmt.Sprintf("does not contain %s", short(a.Value)))
		}
	case model.OpMatches:
		re, cErr := regexp.Compile(a.Value)
		if cErr != nil {
			return fmt.Sprintf("the assertion pattern %s does not compile: %v", short(a.Value), cErr)
		}
		if !re.MatchString(actual) {
			return describe(a, fmt.Sprintf("does not match %s", short(a.Value)))
		}
	case model.OpLt, model.OpLte, model.OpGt, model.OpGte:
		got, err1 := strconv.ParseFloat(strings.TrimSpace(actual), 64)
		want, err2 := strconv.ParseFloat(strings.TrimSpace(a.Value), 64)
		if err1 != nil || err2 != nil {
			return describe(a, fmt.Sprintf("is %s, which is not a number to compare with %s",
				short(actual), short(a.Value)))
		}
		ok := (a.Op == model.OpLt && got < want) ||
			(a.Op == model.OpLte && got <= want) ||
			(a.Op == model.OpGt && got > want) ||
			(a.Op == model.OpGte && got >= want)
		if !ok {
			return describe(a, fmt.Sprintf("is %s, expected %s %s", short(actual), opWord(a.Op), short(a.Value)))
		}
	}
	return ""
}

// value reads the assertion's subject out of the observation.
func (o *observation) value(a model.Assertion) (value string, present bool, failure string) {
	switch a.Source {
	case model.SrcStatus:
		return strconv.Itoa(o.status), o.status > 0, ""
	case model.SrcLatency:
		return strconv.Itoa(o.latency), true, ""
	case model.SrcHeader:
		v, ok := o.headers[strings.ToLower(a.Target)]
		return v, ok, ""
	case model.SrcBody:
		return o.body, true, ""
	case model.SrcVariable:
		v, ok := o.vars[a.Target]
		return v, ok, ""
	case model.SrcJSON:
		doc, ok := o.json()
		if !ok {
			return "", false, "the response is not JSON, so " + subject(a) + " cannot be read"
		}
		v, found := lookup(doc, a.Target)
		if !found {
			return "", false, ""
		}
		return stringify(v), true, ""
	}
	return "", false, fmt.Sprintf("unknown assertion source %q", a.Source)
}

// describe renders a failure. A declared message wins, because what an
// assertion means to the business is usually more useful in an incident
// than what it compares.
func describe(a model.Assertion, what string) string {
	if a.Message != "" {
		return a.Message
	}
	return subject(a) + " " + what
}

// subject names what an assertion is about, in words rather than in
// field names, because these strings end up in an incident timeline
// that a customer reads.
func subject(a model.Assertion) string {
	switch a.Source {
	case model.SrcStatus:
		return "the response status"
	case model.SrcLatency:
		return "the response time in milliseconds"
	case model.SrcHeader:
		return "the " + a.Target + " header"
	case model.SrcBody:
		return "the response body"
	case model.SrcJSON:
		return a.Target + " in the response"
	case model.SrcVariable:
		return "the " + a.Target + " variable"
	}
	return a.Source
}

func opWord(op string) string {
	switch op {
	case model.OpLt:
		return "less than"
	case model.OpLte:
		return "at most"
	case model.OpGt:
		return "greater than"
	case model.OpGte:
		return "at least"
	}
	return op
}

// equalish compares as numbers when both sides look numeric, and as
// strings otherwise, so a JSON 200 and a configured "200" agree.
func equalish(actual, expected string) bool {
	if actual == expected {
		return true
	}
	a, err1 := strconv.ParseFloat(strings.TrimSpace(actual), 64)
	b, err2 := strconv.ParseFloat(strings.TrimSpace(expected), 64)
	return err1 == nil && err2 == nil && a == b
}

func short(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return strconv.Quote(s)
}

// stringify renders a decoded JSON value the way an assertion compares
// it: scalars as themselves, containers as compact JSON.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}

// lookup walks a decoded JSON document with a dotted path, with bracket
// indices for arrays: "data.items[0].id".
//
// It is a deliberate subset of JSONPath. Filters and wildcards would
// let an assertion mean something a reader has to work out, and an
// assertion nobody can read is no use in the argument the report is
// written for.
func lookup(doc any, path string) (any, bool) {
	cur := doc
	for _, seg := range splitPath(path) {
		if seg.index >= 0 {
			arr, ok := cur.([]any)
			if !ok || seg.index >= len(arr) {
				return nil, false
			}
			cur = arr[seg.index]
			continue
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[seg.key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

type pathSeg struct {
	key   string
	index int
}

func splitPath(path string) []pathSeg {
	var out []pathSeg
	path = strings.TrimPrefix(strings.TrimSpace(path), "$")
	path = strings.TrimPrefix(path, ".")
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		for {
			open := strings.IndexByte(part, '[')
			if open < 0 {
				if part != "" {
					out = append(out, pathSeg{key: part, index: -1})
				}
				break
			}
			if open > 0 {
				out = append(out, pathSeg{key: part[:open], index: -1})
			}
			closeIdx := strings.IndexByte(part[open:], ']')
			if closeIdx < 0 {
				break
			}
			n, err := strconv.Atoi(part[open+1 : open+closeIdx])
			if err != nil || n < 0 {
				return out
			}
			out = append(out, pathSeg{index: n})
			part = part[open+closeIdx+1:]
		}
	}
	return out
}
