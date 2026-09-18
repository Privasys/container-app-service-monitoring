// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package api

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/clock"
)

func TestARefusedIncidentHasItsOwnStatus(t *testing.T) {
	for err, want := range map[error]int{
		clock.ErrTooManyIncidents:                          http.StatusTooManyRequests,
		fmt.Errorf("wrapped: %w", clock.ErrUnknownEnclave): http.StatusNotFound,
		errors.New("clock: nonce must be 32 bytes"):        http.StatusBadRequest,
	} {
		if got := incidentStatus(err); got != want {
			t.Fatalf("%v: status %d, want %d", err, got, want)
		}
	}
}
