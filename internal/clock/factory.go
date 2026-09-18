// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"context"
	"strings"
	"time"

	"enclave-os-mini/clients/go/ratls"

	"github.com/Privasys/container-app-service-monitoring/internal/core"
)

// NewEgressIdentity returns the container's attested identity, minted
// by the enclave manager at managerURL, or nil off the platform.
func NewEgressIdentity(managerURL, containerToken string) *ratls.EgressIdentity {
	if managerURL == "" || containerToken == "" {
		return nil
	}
	base := strings.TrimSuffix(strings.TrimSuffix(managerURL, "/"), "/api/v1/vault-identity")
	return ratls.NewEgressIdentity(base, containerToken)
}

// RATLSFactory builds the real control-plane client and poller, both
// authenticated with the container's attested identity.
func RATLSFactory(id *ratls.EgressIdentity) Factory {
	return func(cfg core.PlatformClock, now func() time.Time, creds CredentialSource) (PlatformAPI, Poller) {
		var identity IdentitySource
		if id != nil {
			identity = func(_ context.Context, challenge []byte) ([]byte, []byte, error) {
				return id.HeaderEvidence(challenge)
			}
		}
		platform := NewPlatform(cfg.ManagementURL, identity, now)
		poller := &RATLSPoller{
			Credentials: creds, AllowDebugImages: cfg.AllowDebugImages, Identity: id,
		}
		return platform, poller
	}
}
