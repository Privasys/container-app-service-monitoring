// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package secrets_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
)

func open(t *testing.T) (*secrets.Vault, string) {
	t.Helper()
	dir := t.TempDir()
	var master [32]byte
	copy(master[:], "a test master secret, 32 bytes..")
	vault, err := secrets.Open(dir, master)
	if err != nil {
		t.Fatal(err)
	}
	return vault, dir
}

func TestABoundCredentialGoesNowhereElse(t *testing.T) {
	vault, _ := open(t)
	if _, err := vault.Put("key", "value-value", []string{"api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got, err := vault.Use("key", "api.example.com"); err != nil || got != "value-value" {
		t.Fatalf("Use on the bound host = %q, %v", got, err)
	}
	// The port the service happens to listen on is not part of the
	// binding unless the binding names one.
	if _, err := vault.Use("key", "api.example.com:8443"); err != nil {
		t.Fatalf("a port should not break the binding: %v", err)
	}
	if _, err := vault.Use("key", "attacker.example.net"); !errors.Is(err, secrets.ErrBinding) {
		t.Fatalf("Use on another host = %v, want a binding refusal", err)
	}
	// A subtree binding is deliberate, and a sibling domain is not in it.
	if _, err := vault.Put("wide", "value-value", []string{".example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Use("wide", "anything.example.com"); err != nil {
		t.Fatalf("a subtree binding should cover a subdomain: %v", err)
	}
	if _, err := vault.Use("wide", "example.com.attacker.net"); !errors.Is(err, secrets.ErrBinding) {
		t.Fatal("a suffix match must not admit a lookalike domain")
	}
}

func TestACredentialCannotBeBoundToEverything(t *testing.T) {
	vault, _ := open(t)
	if _, err := vault.Put("key", "value-value", []string{"*"}); err == nil {
		t.Fatal("binding to every host was accepted")
	}
	if _, err := vault.Put("key", "value-value", nil); err == nil {
		t.Fatal("a credential with no binding was accepted")
	}
}

func TestDestroyingACredentialDestroysItsKey(t *testing.T) {
	vault, dir := open(t)
	if _, err := vault.Put("key", "value-value", []string{"api.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := vault.Destroy("key"); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Use("key", "api.example.com"); !errors.Is(err, secrets.ErrUnknown) {
		t.Fatalf("Use after destroy = %v", err)
	}
	// Reopening the vault must not resurrect it.
	var master [32]byte
	copy(master[:], "a test master secret, 32 bytes..")
	reopened, err := secrets.Open(dir, master)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Has("key") {
		t.Fatal("a destroyed credential came back after a restart")
	}
}

func TestAVaultSurvivesARestart(t *testing.T) {
	vault, dir := open(t)
	if _, err := vault.Put("key", "value-value", []string{"api.example.com"}); err != nil {
		t.Fatal(err)
	}
	var master [32]byte
	copy(master[:], "a test master secret, 32 bytes..")
	reopened, err := secrets.Open(dir, master)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Use("key", "api.example.com")
	if err != nil || got != "value-value" {
		t.Fatalf("after a restart Use = %q, %v", got, err)
	}
}

func TestAWrongMasterSecretCannotOpenTheValues(t *testing.T) {
	vault, dir := open(t)
	if _, err := vault.Put("key", "value-value", []string{"api.example.com"}); err != nil {
		t.Fatal(err)
	}
	var wrong [32]byte
	copy(wrong[:], "a different master secret........")
	if _, err := secrets.Open(dir, wrong); err == nil {
		t.Fatal("the vault opened under the wrong master secret")
	}
}

func TestRedactionCoversTheFormsAnExchangeProduces(t *testing.T) {
	red := secrets.NewRedactor()
	red.Add("api_key", "p@ssword with spaces")

	body := `{"echo":"p@ssword with spaces","url":"?k=p%40ssword+with+spaces"}`
	out := red.Redact(body)
	if strings.Contains(out, "p@ssword") {
		t.Fatalf("the raw value survived: %q", out)
	}
	if red.Leaks(out) {
		t.Fatalf("Leaks still reports the value in %q", out)
	}
	if !strings.Contains(out, "[redacted:api_key]") {
		t.Fatalf("no marker in %q", out)
	}
}

func TestVeryShortValuesAreNotRedacted(t *testing.T) {
	// Redacting a two-character value would black out the whole capture
	// and tell a responder nothing, which is worse than useless while
	// they are trying to see what the service said.
	red := secrets.NewRedactor()
	red.Add("tiny", "ab")
	if red.Redact("abcabc") != "abcabc" {
		t.Fatal("a two-character value was redacted")
	}
}
