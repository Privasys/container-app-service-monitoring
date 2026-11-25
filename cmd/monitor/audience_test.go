// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"reflect"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/api"
)

func TestOnlyTheTestControlPlanesTakeTheTestAudience(t *testing.T) {
	test := []string{"privasys-platform-test"}
	for url, want := range map[string][]string{
		"https://api.developer.test.privasys.org":              test,
		"https://api.developer.test.privasys.org.":             test,
		"https://API-TEST.developer.privasys.org":              test,
		"https://api.developer.privasys.org":                   nil,
		"https://api.developer.privasys.org.:443":              nil,
		"https://attestation.privasys.org":                     {},
		"https://api.developer.test.privasys.org.evil.example": {},
		"":            {},
		"::not a url": {},
	} {
		if got := audiencesFor(url); !reflect.DeepEqual(got, want) || (got == nil) != (want == nil) {
			t.Errorf("%q: audiences %#v, want %#v", url, got, want)
		}
	}
}

func TestTheSignInFollowsTheControlPlane(t *testing.T) {
	test := testSignIn("https://api.developer.test.privasys.org")
	if test.ClientID != "privasys-platform-test" || test.Audience != "privasys-platform-test" ||
		test.APIBase != "https://api.developer.test.privasys.org" {
		t.Errorf("test sign-in: %+v", test)
	}
	for _, url := range []string{"https://api.developer.privasys.org", "https://api.developer.test.privasys.org.evil.example", ""} {
		if got := testSignIn(url); got != api.ProductionSignIn {
			t.Errorf("%q: sign-in %+v, want production's", url, got)
		}
	}
}
