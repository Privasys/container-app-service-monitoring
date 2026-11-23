// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import "testing"

func TestOnlyTheTestControlPlanesTakeTheTestAudience(t *testing.T) {
	for url, test := range map[string]bool{
		"https://api.developer.test.privasys.org":              true,
		"https://API-TEST.developer.privasys.org":              true,
		"https://api.developer.privasys.org":                   false,
		"https://attestation.privasys.org":                     false,
		"https://api.developer.test.privasys.org.evil.example": false,
		"":            false,
		"::not a url": false,
	} {
		if got := len(audiencesFor(url)) > 0; got != test {
			t.Errorf("%q: test platform %v, want %v", url, got, test)
		}
	}
}
