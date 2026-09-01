// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package journey

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// Egress control.
//
// The enclave runtime does not filter outbound traffic today, so the
// application does it. That is worth saying plainly rather than
// implying otherwise: this is an app-enforced allowlist, not a
// kernel-enforced one, and a compromise of this process is a compromise
// of the rule.
//
// What it buys is still real. The allowlist is built from the monitor
// definitions and the callback allowlist, both of which are signed
// transactions, so a request to a host nobody declared is refused and
// recorded. Combined with the credential binding in the secrets
// package, a monitor cannot be quietly repointed at somewhere that
// collects the credential it was given.

// Allowlist is the set of hosts this instance may contact.
type Allowlist struct {
	mu    sync.RWMutex
	hosts map[string]bool
	// suffixes holds the ".example.com" entries, which cover a subtree.
	suffixes []string
	// open disables the check entirely. Only a developer's machine sets
	// it, and the runtime refuses to when the platform credentials are
	// present.
	open bool
}

// NewAllowlist returns an empty, closed allowlist.
func NewAllowlist() *Allowlist {
	return &Allowlist{hosts: map[string]bool{}}
}

// Open disables the check. It exists for local development, where the
// target is whatever the developer just started.
func (a *Allowlist) Open() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.open = true
}

// IsOpen reports whether the check is disabled, so the status endpoint
// can say so rather than implying a protection that is not there.
func (a *Allowlist) IsOpen() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.open
}

// Replace sets the allowlist to exactly these entries.
func (a *Allowlist) Replace(entries []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hosts = map[string]bool{}
	a.suffixes = nil
	for _, e := range entries {
		a.addLocked(e)
	}
}

// Add permits one host or subtree.
func (a *Allowlist) Add(entry string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.addLocked(entry)
}

func (a *Allowlist) addLocked(entry string) {
	entry = strings.ToLower(strings.TrimSpace(entry))
	if entry == "" {
		return
	}
	if strings.HasPrefix(entry, ".") {
		for _, s := range a.suffixes {
			if s == entry {
				return
			}
		}
		a.suffixes = append(a.suffixes, entry)
		return
	}
	a.hosts[entry] = true
}

// Entries lists the allowlist, hosts first then subtrees.
func (a *Allowlist) Entries() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.hosts)+len(a.suffixes))
	for h := range a.hosts {
		out = append(out, h)
	}
	out = append(out, a.suffixes...)
	return out
}

// Check permits or refuses a request to host, which may carry a port.
func (a *Allowlist) Check(host string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.open {
		return nil
	}
	bare := hostOnly(host)
	if a.hosts[bare] || a.hosts[strings.ToLower(host)] {
		return nil
	}
	for _, s := range a.suffixes {
		if strings.HasSuffix(bare, s) || bare == strings.TrimPrefix(s, ".") {
			return nil
		}
	}
	return fmt.Errorf("egress: %s is not a declared target of this monitor", bare)
}

func hostOnly(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
