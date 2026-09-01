// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package secrets holds the credentials a monitor is given, and decides
// where they are allowed to travel.
//
// This is the package the whole product rests on. A conventional
// monitoring service cannot be given a working account, so it probes
// the login page instead of the login. Here the credential arrives over
// a channel whose certificate carries a hardware quote over the
// measurement of this build, is encrypted under a key derived from a
// sealed master secret on a volume whose LUKS key is released only to
// that measurement, and is never returned by any endpoint.
//
// Two rules are enforced here rather than in the caller, because a rule
// enforced by the caller is a rule a future caller can forget:
//
//   - A secret is bound at creation to a set of hosts. Use refuses to
//     hand it over for a request to anything else, so repointing a
//     monitor at an attacker's host cannot exfiltrate the credential.
//     The refusal is a recorded event, not a silent empty string.
//   - Destroying a secret destroys its key. The value is gone at once
//     and the record of it, its bindings and its history remains.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ErrBinding is returned when a secret is asked for on behalf of a host
// it is not bound to.
var ErrBinding = errors.New("secrets: this credential is not bound to that host")

// ErrUnknown is returned for a secret that was never created, or whose
// key has been destroyed.
var ErrUnknown = errors.New("secrets: no such credential")

// Vault is the sealed credential store.
type Vault struct {
	mu     sync.RWMutex
	dir    string
	master [32]byte
	// entries is the in-memory keyring. Values live on disk encrypted
	// under the per-entry key; the keyring itself is encrypted under a
	// key derived from the master secret.
	entries map[string]*entry
}

type entry struct {
	Key   []byte   `json:"key"`
	Hosts []string `json:"hosts"`
}

// Open loads (or creates) the vault under dir.
func Open(dir string, master [32]byte) (*Vault, error) {
	v := &Vault{dir: dir, master: master, entries: map[string]*entry{}}
	if err := os.MkdirAll(filepath.Join(dir, "values"), 0o700); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	if err := v.loadKeyring(); err != nil {
		return nil, err
	}
	return v, nil
}

// Put stores or replaces a credential and returns its fingerprint.
//
// The fingerprint is a keyed hash of the value. It lets an operator
// confirm that a rotation actually changed something, and it lets the
// record say "this monitor ran under credential version X" without the
// value being recoverable from the record.
func (v *Vault) Put(name, value string, hosts []string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	if value == "" {
		return "", errors.New("secrets: an empty value is not a credential")
	}
	clean, err := NormaliseHosts(hosts)
	if err != nil {
		return "", err
	}
	if len(clean) == 0 {
		return "", errors.New("secrets: a credential must be bound to at least one host")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("secrets: %w", err)
	}
	sealed, err := seal(key, []byte(value), []byte(name))
	if err != nil {
		return "", err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if err := os.WriteFile(v.valuePath(name), sealed, 0o600); err != nil {
		return "", fmt.Errorf("secrets: write value: %w", err)
	}
	v.entries[name] = &entry{Key: key, Hosts: clean}
	if err := v.saveKeyring(); err != nil {
		return "", err
	}
	return v.fingerprint(value), nil
}

// Use returns a credential for a request to host. This is the only way
// a value leaves the vault.
func (v *Vault) Use(name, host string) (string, error) {
	v.mu.RLock()
	e, ok := v.entries[name]
	v.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknown, name)
	}
	if !hostAllowed(e.Hosts, host) {
		return "", fmt.Errorf("%w: %s is bound to %s, the request is to %s",
			ErrBinding, name, strings.Join(e.Hosts, ", "), host)
	}
	sealed, err := os.ReadFile(v.valuePath(name))
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrUnknown, name)
	}
	plain, err := open(e.Key, sealed, []byte(name))
	if err != nil {
		return "", fmt.Errorf("secrets: %s: %w", name, err)
	}
	return string(plain), nil
}

// Bindings returns the hosts a credential is bound to.
func (v *Vault) Bindings(name string) ([]string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.entries[name]
	if !ok {
		return nil, false
	}
	return append([]string(nil), e.Hosts...), true
}

// Destroy destroys a credential's key. The value is unrecoverable from
// this moment; the record that it existed, what it was bound to and
// when it was destroyed stays exactly where it was.
func (v *Vault) Destroy(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.entries[name]; !ok {
		return fmt.Errorf("%w: %s", ErrUnknown, name)
	}
	delete(v.entries, name)
	if err := v.saveKeyring(); err != nil {
		return err
	}
	if err := os.Remove(v.valuePath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secrets: remove value: %w", err)
	}
	return nil
}

// Names lists the credentials the vault holds, in order.
func (v *Vault) Names() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.entries))
	for name := range v.entries {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Has reports whether a credential is present and usable.
func (v *Vault) Has(name string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.entries[name]
	return ok
}

// fingerprint is a keyed hash of a value under the master secret.
func (v *Vault) fingerprint(value string) string {
	mac := hmac.New(sha256.New, v.master[:])
	mac.Write([]byte("monitor/secret-fingerprint/v1"))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// Fingerprint exposes the keyed hash for callers comparing a candidate
// value against the stored one without reading it back.
func (v *Vault) Fingerprint(value string) string { return v.fingerprint(value) }

func (v *Vault) valuePath(name string) string {
	sum := sha256.Sum256([]byte("monitor/secret-file/v1" + name))
	return filepath.Join(v.dir, "values", hex.EncodeToString(sum[:16])+".bin")
}

func (v *Vault) keyringPath() string { return filepath.Join(v.dir, "keyring.bin") }

func (v *Vault) keyringKey() ([]byte, error) {
	return hkdf.Key(sha256.New, v.master[:], nil, "monitor/keyring/v1", 32)
}

func (v *Vault) loadKeyring() error {
	sealed, err := os.ReadFile(v.keyringPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("secrets: read keyring: %w", err)
	}
	key, err := v.keyringKey()
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	plain, err := open(key, sealed, []byte("keyring"))
	if err != nil {
		return fmt.Errorf("secrets: keyring: %w", err)
	}
	return json.Unmarshal(plain, &v.entries)
}

func (v *Vault) saveKeyring() error {
	plain, err := json.Marshal(v.entries)
	if err != nil {
		return err
	}
	key, err := v.keyringKey()
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	sealed, err := seal(key, plain, []byte("keyring"))
	if err != nil {
		return err
	}
	tmp := v.keyringPath() + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return fmt.Errorf("secrets: write keyring: %w", err)
	}
	return os.Rename(tmp, v.keyringPath())
}

func seal(key, plain, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plain, aad)...), nil
}

func open(key, sealed, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext is truncated")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
}

// ValidName constrains credential names to something that can appear in
// a template, a log line and a URL path without escaping.
func ValidName(name string) error {
	if name == "" || len(name) > 64 {
		return errors.New("secrets: a name is 1 to 64 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
		default:
			return fmt.Errorf("secrets: %q is not allowed in a credential name", r)
		}
	}
	return nil
}

// NormaliseHosts lower-cases and de-duplicates a binding. A host is a
// bare hostname, optionally with a port; a leading dot binds a whole
// subtree, which is how a customer binds "anything under example.com".
func NormaliseHosts(hosts []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "/ \t") {
			return nil, fmt.Errorf("secrets: %q is not a host", h)
		}
		if h == "*" {
			return nil, errors.New("secrets: a credential cannot be bound to every host")
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out, nil
}

// hostAllowed matches a request host against a binding. Ports are
// compared when the binding names one and ignored when it does not, so
// a binding to "api.example.com" covers the port the service happens to
// listen on without having to be re-issued.
func hostAllowed(bindings []string, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	bare := host
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		bare = host[:i]
	}
	for _, b := range bindings {
		switch {
		case strings.HasPrefix(b, "."):
			if strings.HasSuffix(bare, b) || bare == strings.TrimPrefix(b, ".") {
				return true
			}
		case b == host || b == bare:
			return true
		}
	}
	return false
}
