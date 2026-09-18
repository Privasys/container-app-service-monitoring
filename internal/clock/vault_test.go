// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

func testVault() Enclave {
	return Enclave{
		ID: "99999999-8888-7777-6666-555555555555", Kind: model.ClockKindVault,
		Name: "dev-v0.35.0/192.0.2.10:8561", TeeType: "sgx",
		GatewayHost: "192.0.2.10", Port: 8561,
	}
}

func (r *rig) vaultAlert() model.ClockVaultAlert {
	r.t.Helper()
	a, err := r.mon.ClockVaultAlert(r.enclave.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	if a == nil {
		return model.ClockVaultAlert{}
	}
	return *a
}

func TestAVaultWithAWrongHostIsAlertedAndNeverQuarantined(t *testing.T) {
	r := newRigFor(t, testVault())
	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, -3_600_000, VerdictHostWrong, true)
	})
	r.poll()
	a := r.expectAlert(core.EventClockVaultHostClockWrong)
	if a.Subject != r.enclave.ID || a.Payload["kind"] != model.ClockKindVault {
		t.Fatalf("the alert is %+v", a)
	}
	if st := r.vaultAlert(); st.Event != core.EventClockVaultHostClockWrong || st.Reason == "" || st.ReadingID == "" {
		t.Fatalf("standing alert %+v", st)
	}

	// Still wrong: the alert stands, nothing new is raised.
	r.poll()
	r.noAlert(core.EventClockVaultHostClockWrong)

	// Fixed: one recovered alert, and nothing stands any more.
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 150, VerdictInSync, false)
	})
	r.poll()
	rec := r.expectAlert(core.EventClockVaultRecovered)
	if rec.Payload["recovered_from"] != core.EventClockVaultHostClockWrong {
		t.Fatalf("the recovery does not say what it recovered from: %+v", rec.Payload)
	}
	if st := r.vaultAlert(); st.Event != "" {
		t.Fatalf("an alert still stands after the recovery: %+v", st)
	}
	r.poll()
	r.noAlert(core.EventClockVaultRecovered)

	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("the platform was asked to act on a vault: %v", calls)
	}
	if st := r.state(); st.Quarantined {
		t.Fatalf("a vault is recorded as quarantined: %+v", st)
	}
}

func TestASilentVaultIsAlertedOnTheSecondMissedPoll(t *testing.T) {
	r := newRigFor(t, testVault())
	r.poller.set(func(PollRequest) (*PollResult, error) {
		return nil, ErrUnreachable
	})
	r.poll()
	r.noAlert(core.EventClockVaultUnreachable)
	r.poll()
	r.expectAlert(core.EventClockVaultUnreachable)
	r.poll()
	r.noAlert(core.EventClockVaultUnreachable)

	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 0, VerdictInSync, false)
	})
	r.poll()
	r.expectAlert(core.EventClockVaultRecovered)
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("the platform was asked to act on a vault: %v", calls)
	}
}

func TestAVaultThatFailsClosedOrDriftsIsAlerted(t *testing.T) {
	r := newRigFor(t, testVault())
	r.poller.set(func(PollRequest) (*PollResult, error) {
		return &PollResult{HTTPStatus: 503, Body: `{"error":"no trusted time"}`}, nil
	})
	r.poll()
	a := r.expectAlert(core.EventClockVaultHostClockWrong)
	if reason, _ := a.Payload["reason"].(string); !strings.Contains(reason, "failed closed") {
		t.Fatalf("reason %v", a.Payload["reason"])
	}

	// Back, but its host 30 s off the monitor's and not caught by the
	// runtime: the same problem, so no new alert and no recovery; then
	// clean.
	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 30_000, VerdictInSync, false)
	})
	r.poll()
	r.noAlert(core.EventClockVaultRecovered)
	r.noAlert(core.EventClockVaultHostClockWrong)
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 0, VerdictInSync, false)
	})
	r.poll()
	r.expectAlert(core.EventClockVaultRecovered)
}

func TestAVaultWithoutTheClockIsNotAlerted(t *testing.T) {
	// A vault on a build that predates the clock answers 404.
	r := newRigFor(t, testVault())
	r.poller.set(func(PollRequest) (*PollResult, error) {
		return &PollResult{HTTPStatus: 404, Body: `{"error":"not found"}`}, nil
	})
	r.poll()
	r.poll()
	r.noAlert(core.EventClockVaultHostClockWrong)
	r.noAlert(core.EventClockVaultUnreachable)
	if st := r.vaultAlert(); st.Event != "" {
		t.Fatalf("standing alert %+v", st)
	}
}

func TestAnIncidentFromAVaultGetsAReceiptAndCausesAPoll(t *testing.T) {
	r := newRigFor(t, testVault())
	report := newReport(r.enclave.ID)
	receipt, err := r.svc.Incident(context.Background(), report, "192.0.2.10")
	if err != nil {
		t.Fatalf("a vault's report was refused: %v", err)
	}
	if err := VerifyReceipt(r.svc.Signer().PublicKey(), r.enclave.ID, receipt); err != nil {
		t.Fatalf("the receipt does not verify: %v", err)
	}
	r.waitPolled()
	r.waitIdle()
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("a vault's report made the monitor act on the platform: %v", calls)
	}
}

func TestTheFleetViewShowsVaults(t *testing.T) {
	r := newRigFor(t, testVault())
	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, -3_600_000, VerdictHostWrong, true)
	})
	r.poll()
	r.expectAlert(core.EventClockVaultHostClockWrong)
	fleet, err := r.svc.Fleet()
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet.Enclaves) != 1 {
		t.Fatalf("fleet %+v", fleet.Enclaves)
	}
	row := fleet.Enclaves[0]
	if row.Kind != model.ClockKindVault || row.VaultAlert == nil ||
		row.VaultAlert.Event != core.EventClockVaultHostClockWrong || row.Quarantined {
		t.Fatalf("fleet row %+v", row)
	}
}

func TestAVaultIsPolledAtItsOwnAddress(t *testing.T) {
	host, port, sni, err := pollAddress(testVault())
	if err != nil || host != "192.0.2.10" || port != 8561 || sni != "" {
		t.Fatalf("vault address %s:%d sni %q, %v", host, port, sni, err)
	}
	e := Enclave{Name: "m6-dev", TeeType: "tdx", MgrHostname: "m6-dev-mgr.apps.example", GatewayHost: "10.0.0.1", Port: 443}
	host, port, sni, err = pollAddress(e)
	if err != nil || host != "10.0.0.1" || port != 443 || sni != e.MgrHostname {
		t.Fatalf("enclave address %s:%d sni %q, %v", host, port, sni, err)
	}
	v := testVault()
	v.GatewayHost = ""
	if _, _, _, err := pollAddress(v); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("a vault without an address: %v", err)
	}
	if !testVault().IsSGX() || testVault().PollPath() != "/clock/poll" {
		t.Fatal("a vault is not polled on the mini core's route")
	}
	if (Enclave{}).KindOrDefault() != model.ClockKindEnclave {
		t.Fatal("an entry with no kind is not taken as an enclave")
	}
}

func TestDecideVaultRaisesAChangeOfProblem(t *testing.T) {
	unreachable := model.ClockReading{Outcome: model.ClockOutcomeUnreachable}
	prev := model.ClockEnclave{FailedPolls: 1}
	if d := DecideVault(prev, unreachable, core.EventClockVaultHostClockWrong, "k"); d.Event != core.EventClockVaultUnreachable {
		t.Fatalf("a vault that went silent after a clock alert: %+v", d)
	}
	if d := DecideVault(prev, unreachable, core.EventClockVaultUnreachable, "k"); d.Event != "" {
		t.Fatalf("the same problem again: %+v", d)
	}
	if d := DecideVault(model.ClockEnclave{}, unreachable, "", "k"); d.Event != "" {
		t.Fatalf("one missed poll: %+v", d)
	}
}
