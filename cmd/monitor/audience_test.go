// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package main

import (
	"reflect"

	"github.com/Privasys/container-app-service-monitoring/internal/api"
	"testing"
)

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
		got := audiencesFor(url)
		if test && !reflect.DeepEqual(got, []string{"privasys-platform-test"}) {
			t.Errorf("%q: audiences %v, want the test audience only", url, got)
		}
		if !test && got != nil {
			t.Errorf("%q: audiences %v, want the configured default", url, got)
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
