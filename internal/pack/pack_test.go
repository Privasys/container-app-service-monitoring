package pack_test

import (
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/pack"
)

// The packs shipped in the image are part of the product, so a broken
// one should fail the build rather than a customer's first configure.
func TestTheShippedPacksAreValid(t *testing.T) {
	for _, name := range pack.Available("../../packs") {
		p, err := pack.LoadRef("../../packs", name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(p.Monitors) == 0 {
			t.Fatalf("%s has no monitors", name)
		}
	}
	if len(pack.Available("../../packs")) < 2 {
		t.Fatal("the reference packs are missing")
	}
}
