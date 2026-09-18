// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	seed := sha256.Sum256([]byte("platform clock test key"))
	return NewSigner(ed25519.NewKeyFromSeed(seed[:]))
}

// The signed bytes are a contract shared with the runtimes, which
// rebuild them independently. A change here is a change on the wire.
func TestTheSignedBytesAreExactlyTheContract(t *testing.T) {
	got := string(FloorBytes("enc-1", 1789000000000, 42))
	want := "privasys-clock-floor/v1\nenc-1\n1789000000000\n42"
	if got != want {
		t.Fatalf("floor bytes:\n got %q\nwant %q", got, want)
	}
	got = string(ReceiptBytes("enc-1", "bm9uY2U", "cki_01"))
	want = "privasys-clock-receipt/v1\nenc-1\nbm9uY2U\ncki_01"
	if got != want {
		t.Fatalf("receipt bytes:\n got %q\nwant %q", got, want)
	}
}

func TestTheKeyIDIsTheFirstSixteenHexCharacters(t *testing.T) {
	s := testSigner(t)
	sum := sha256.Sum256(s.PublicKey())
	if want := hex.EncodeToString(sum[:])[:16]; s.KeyID() != want {
		t.Fatalf("key id %q, want %q", s.KeyID(), want)
	}
	if len(s.KeyID()) != 16 || strings.ToLower(s.KeyID()) != s.KeyID() {
		t.Fatalf("key id %q is not 16 lower-case hex characters", s.KeyID())
	}
	raw, err := base64.RawURLEncoding.DecodeString(s.EncodedPublicKey())
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("the published key is not a base64url 32-byte key: %v", err)
	}
}

func TestAFloorVerifiesAndATamperedOneDoesNot(t *testing.T) {
	s := testSigner(t)
	req := s.Floor("enc-1", 1789000000000, 7)
	if err := VerifyFloor(s.PublicKey(), req); err != nil {
		t.Fatalf("a fresh floor did not verify: %v", err)
	}
	// Moving the floor, replaying it for another enclave, or reusing the
	// signature on another sequence number must all fail.
	for name, mutate := range map[string]func(*PollRequest){
		"time":    func(r *PollRequest) { r.TMs += 60_000 },
		"enclave": func(r *PollRequest) { r.EnclaveID = "enc-2" },
		"seq":     func(r *PollRequest) { r.Seq++ },
	} {
		bad := req
		mutate(&bad)
		if err := VerifyFloor(s.PublicKey(), bad); err == nil {
			t.Fatalf("a floor with a changed %s still verified", name)
		}
	}
	other := NewSigner(ed25519.NewKeyFromSeed(make([]byte, 32)))
	if err := VerifyFloor(other.PublicKey(), req); err == nil {
		t.Fatal("a floor verified under another key")
	}
}

func TestAReceiptBindsTheNonceTheEnclaveAndTheIncident(t *testing.T) {
	s := testSigner(t)
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	r := s.Receipt("enc-1", nonce, "cki_1")
	if err := VerifyReceipt(s.PublicKey(), "enc-1", r); err != nil {
		t.Fatalf("a receipt did not verify: %v", err)
	}
	if err := VerifyReceipt(s.PublicKey(), "enc-2", r); err == nil {
		t.Fatal("a receipt verified for another enclave")
	}
	r.Nonce = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	if err := VerifyReceipt(s.PublicKey(), "enc-1", r); err == nil {
		t.Fatal("a receipt verified with another nonce")
	}
}

func TestAnIncidentReportMustCarryA32ByteNonce(t *testing.T) {
	nonce := make([]byte, 32)
	nonce[0] = 0xfb // makes the padded and unpadded spellings differ
	padded := base64.URLEncoding.EncodeToString(nonce)
	r := IncidentReport{EnclaveID: "enc-1", Reason: ReasonHostBehindFloor, Nonce: padded}
	if err := r.Validate(); err != nil {
		t.Fatalf("a padded nonce was refused: %v", err)
	}
	// The receipt signs the nonce exactly as the runtime sent it.
	if r.Nonce != padded {
		t.Fatalf("the nonce was rewritten from %q to %q", padded, r.Nonce)
	}
	r.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	for _, bad := range []IncidentReport{
		{EnclaveID: "", Reason: "x", Nonce: r.Nonce},
		{EnclaveID: "enc-1", Reason: "", Nonce: r.Nonce},
		{EnclaveID: "enc-1", Reason: "x", Nonce: "c2hvcnQ"},
		{EnclaveID: "enc-1", Reason: "x", Nonce: "not base64!"},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("an invalid report was accepted: %+v", bad)
		}
	}
}
