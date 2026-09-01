// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package journey

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Templating.
//
// A journey step carries "{{ vars.order_id }}" and "{{ secrets.api_key }}"
// placeholders, resolved inside the enclave and nowhere else. The
// resolver is deliberately tiny: no expressions, no function calls, no
// conditionals. A monitoring journey that needs a programming language
// is a journey nobody can read in a dispute, and every construct added
// here is one more way for a credential to end up somewhere it was not
// meant to go.
//
// Three namespaces exist:
//
//	vars.<name>     a value extracted by an earlier step, or a constant
//	secrets.<name>  a credential, resolved against its host binding
//	gen.<kind>      a generated value: uuid, timestamp, iso8601
//
// Secrets resolve only through the vault, and the vault only answers
// for a host the credential is bound to. That check therefore happens
// on every single interpolation rather than once per journey.

// SecretResolver hands out credential values for a specific host.
type SecretResolver interface {
	Use(name, host string) (string, error)
}

// scope is the resolution context for one step.
type scope struct {
	vars    map[string]string
	secrets SecretResolver
	// host is the request target the secrets are being resolved for. An
	// empty host means secrets are not permitted at all, which is how
	// the URL is rendered: the target cannot be its own justification.
	host string
	// used collects the credential names actually interpolated, so the
	// caller can register their values with the redactor and record
	// which credentials a reading depended on.
	used map[string]string
}

// ErrSecretInURL is returned when a URL template asks for a credential.
//
// Credentials go in headers and bodies. A URL is logged by proxies,
// caches and the service's own access log, and a query string is the
// single most common way a credential escapes into somewhere nobody
// intended. Refusing outright is a smaller loss than the exceptions
// would be.
var ErrSecretInURL = errors.New("journey: a credential may not appear in a URL; put it in a header or the body")

// render resolves placeholders in s.
func (sc *scope) render(s string) (string, error) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, "{{")
		if i < 0 {
			b.WriteString(rest)
			return b.String(), nil
		}
		j := strings.Index(rest[i:], "}}")
		if j < 0 {
			return "", fmt.Errorf("journey: unclosed placeholder in %q", truncate(s, 80))
		}
		b.WriteString(rest[:i])
		ref := strings.TrimSpace(rest[i+2 : i+j])
		value, err := sc.resolve(ref)
		if err != nil {
			return "", err
		}
		b.WriteString(value)
		rest = rest[i+j+2:]
	}
}

func (sc *scope) resolve(ref string) (string, error) {
	namespace, name, ok := strings.Cut(ref, ".")
	if !ok {
		return "", fmt.Errorf("journey: %q is not a placeholder; use vars.x, secrets.x or gen.x", ref)
	}
	switch namespace {
	case "vars":
		v, ok := sc.vars[name]
		if !ok {
			return "", fmt.Errorf("journey: no variable named %q has been extracted yet", name)
		}
		return v, nil
	case "secrets":
		if sc.host == "" {
			return "", ErrSecretInURL
		}
		if sc.secrets == nil {
			return "", fmt.Errorf("journey: no credential store is configured")
		}
		v, err := sc.secrets.Use(name, sc.host)
		if err != nil {
			return "", err
		}
		if sc.used == nil {
			sc.used = map[string]string{}
		}
		sc.used[name] = v
		return v, nil
	case "gen":
		return generate(name)
	default:
		return "", fmt.Errorf("journey: unknown placeholder namespace %q", namespace)
	}
}

// generate produces the values a journey needs to create test data that
// does not collide with the last run's.
func generate(kind string) (string, error) {
	switch kind {
	case "uuid":
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		h := hex.EncodeToString(b[:])
		return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
	case "hex":
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		return hex.EncodeToString(b[:]), nil
	case "timestamp":
		return strconv.FormatInt(time.Now().Unix(), 10), nil
	case "iso8601":
		return time.Now().UTC().Format(time.RFC3339), nil
	default:
		return "", fmt.Errorf("journey: gen.%s is not a generated value", kind)
	}
}

// referencesSecret reports whether a template asks for a credential,
// without resolving anything.
func referencesSecret(s string) bool {
	rest := s
	for {
		i := strings.Index(rest, "{{")
		if i < 0 {
			return false
		}
		j := strings.Index(rest[i:], "}}")
		if j < 0 {
			return false
		}
		if strings.HasPrefix(strings.TrimSpace(rest[i+2:i+j]), "secrets.") {
			return true
		}
		rest = rest[i+j+2:]
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
