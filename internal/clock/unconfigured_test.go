// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package clock

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
)

// euFrance1 is the enclave of the 2026-09-18 incident as the prod control
// plane listed it: an SGX enclave whose display name holds spaces, on a
// runtime without the clock routes, which never acknowledged the clock
// config.
func euFrance1() Enclave {
	return Enclave{
		ID: "33333333-4444-5555-6666-777777777777", Kind: model.ClockKindEnclave,
		Name: "EU France 1", TeeType: "sgx",
		MgrHostname: "EU France 1-mgr.apps.privasys.org",
		GatewayHost: "192.0.2.21", Port: 8445,
		ClockConfigVersion: 0, ClockConfigCurrent: 1, ClockConfigKnown: true,
	}
}

// setListed changes how the platform lists the rig's enclave and has the
// service fetch the list again.
func (r *rig) setListed(change func(e *Enclave)) {
	r.t.Helper()
	r.platform.mu.Lock()
	change(&r.platform.enclaves[0])
	r.enclave = r.platform.enclaves[0]
	r.platform.mu.Unlock()
	if err := r.svc.refreshList(context.Background(), true); err != nil {
		r.t.Fatal(err)
	}
}

func TestTheIncidentEnclaveIsPolledAtItsAddressWithNoServerName(t *testing.T) {
	host, port, sni, err := pollAddress(euFrance1())
	if err != nil {
		t.Fatal(err)
	}
	if host != "192.0.2.21" || port != 8445 {
		t.Fatalf("polled at %s:%d, want the runtime's own address 192.0.2.21:8445", host, port)
	}
	if sni != "" {
		t.Fatalf("server name %q: a name with spaces must never be sent", sni)
	}

	// A slugged manager hostname from a fixed control plane is sent as the
	// server name, and still never resolved: the address is the listed one.
	e := euFrance1()
	e.MgrHostname = "eu-france-1-mgr.apps.privasys.org"
	host, port, sni, err = pollAddress(e)
	if err != nil || host != "192.0.2.21" || port != 8445 || sni != e.MgrHostname {
		t.Fatalf("got %s:%d sni %q, %v", host, port, sni, err)
	}

	// No address: unreachable, whatever the manager hostname.
	e.GatewayHost = ""
	if _, _, _, err := pollAddress(e); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("an enclave without an address: %v", err)
	}
}

func TestServerNamesAreDNSNamesOnly(t *testing.T) {
	for _, ok := range []string{
		"m6-dev-mgr.apps-test.privasys.org", "DEV---eu-paris-1-mgr.apps-test.privasys.org",
		"eu-france-1-mgr.apps.privasys.org", "a.b", "host.",
	} {
		if !isDNSName(ok) {
			t.Errorf("%q should be accepted", ok)
		}
	}
	for _, bad := range []string{
		"", "EU France 1-mgr.apps.privasys.org", "-a.example", "a-.example", "a..example",
		"192.0.2.1", "::1", "a_b.example", "é.example",
		fmt.Sprintf("%063d.%063d.%063d.%063d.example", 1, 2, 3, 4),
	} {
		if isDNSName(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
}

// The incident itself: every poll of the enclave fails (its hostname did
// not resolve), and the enclave never acknowledged the clock config. It
// must never be quarantined; the silence is one alert, once.
func TestAnUnconfiguredEnclaveThatIsSilentIsNeverQuarantined(t *testing.T) {
	r := newRigFor(t, euFrance1())
	r.poller.set(func(PollRequest) (*PollResult, error) {
		return nil, fmt.Errorf("%w: dial tcp: lookup EU France 1-mgr.apps.privasys.org: no such host", ErrUnreachable)
	})
	r.poll()
	r.noAlert(core.EventClockUnconfiguredUnreachable)
	r.poll()
	a := r.expectAlert(core.EventClockUnconfiguredUnreachable)
	if a.Subject != r.enclave.ID || a.Payload["kind"] != model.ClockKindEnclave ||
		a.Payload["quarantined"] != false || a.Payload["clock_config_version"] != int64(0) {
		t.Fatalf("the alert is %+v", a.Payload)
	}
	for i := 0; i < 5; i++ {
		r.poll()
	}
	r.noAlert(core.EventClockUnconfiguredUnreachable)
	r.noAlert(core.EventClockQuarantined)
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("an enclave without the clock config was acted on: %v", calls)
	}
	if st := r.state(); st.Quarantined || st.FailedPolls != 7 {
		t.Fatalf("position %+v", st)
	}
}

// The runtime answers, but it predates the clock: 404. Nothing to alert
// on, nothing to quarantine.
func TestAnUnconfiguredEnclaveWithoutTheClockRoutesIsLeftAlone(t *testing.T) {
	r := newRigFor(t, euFrance1())
	r.poller.set(func(PollRequest) (*PollResult, error) {
		return &PollResult{HTTPStatus: 404, Body: `{"error":"not found"}`}, nil
	})
	r.poll()
	r.poll()
	r.poll()
	r.noAlert(core.EventClockUnconfiguredUnreachable)
	r.noAlert(core.EventClockUnconfiguredClockWrong)
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("calls %v", calls)
	}
	if st := r.vaultAlert(); st.Event != "" {
		t.Fatalf("standing alert %+v", st)
	}
}

// An enclave the push has not reached yet that nonetheless answers with a
// clock problem is alerted on, not quarantined.
func TestAnUnconfiguredEnclaveWithAWrongClockIsAlertedOnly(t *testing.T) {
	r := newRigFor(t, euFrance1())
	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, -3_600_000, VerdictHostWrong, true)
	})
	r.poll()
	r.expectAlert(core.EventClockUnconfiguredClockWrong)
	r.poll()
	r.noAlert(core.EventClockUnconfiguredClockWrong)
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("calls %v", calls)
	}
}

// Once the runtime acknowledges the current config, the standing alert
// ends and the enclave is held to the clock like any other.
func TestAnEnclaveIsHeldToTheClockOnceItAcknowledgesTheConfig(t *testing.T) {
	r := newRigFor(t, euFrance1())
	r.poller.set(func(PollRequest) (*PollResult, error) { return nil, ErrUnreachable })
	r.poll()
	r.poll()
	r.expectAlert(core.EventClockUnconfiguredUnreachable)

	// The config version moves on: acknowledging an older one is not
	// enough.
	r.setListed(func(e *Enclave) { e.ClockConfigVersion, e.ClockConfigCurrent = 1, 2 })
	r.poll()
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("an enclave behind the current config was acted on: %v", calls)
	}

	r.setListed(func(e *Enclave) { e.ClockConfigVersion = 2 })
	key := r.svc.Signer().KeyID()
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, 0, VerdictInSync, false)
	})
	r.poll()
	rec := r.expectAlert(core.EventClockUnconfiguredRecovered)
	if rec.Payload["recovered_from"] != core.EventClockUnconfiguredUnreachable {
		t.Fatalf("recovered alert %+v", rec.Payload)
	}
	r.poll()
	r.noAlert(core.EventClockUnconfiguredRecovered)

	fleet, err := r.svc.Fleet()
	if err != nil {
		t.Fatal(err)
	}
	if row := fleet.Enclaves[0]; !row.ClockArmed || row.ClockConfigVersion != 2 || row.VaultAlert != nil ||
		row.UnconfiguredAlert == nil || row.UnconfiguredAlert.Event != "" {
		t.Fatalf("fleet row %+v", row)
	}

	// Now a wrong host is quarantined.
	r.poller.set(func(req PollRequest) (*PollResult, error) {
		return reply(req, key, -3_600_000, VerdictHostWrong, true)
	})
	r.poll()
	if calls := r.platform.Calls(); len(calls) != 1 || calls[0] != "quarantine:"+r.enclave.ID {
		t.Fatalf("calls %v, want a quarantine", calls)
	}
}

// A quarantine of this monitor's own that stands on a runtime that never
// acknowledged any config (placed before this rule, or before the runtime
// was registered again) is lifted at the next poll.
func TestTheMonitorLiftsItsQuarantineOfANeverConfiguredRuntime(t *testing.T) {
	r := newRigFor(t, armed(euFrance1()))
	r.poller.set(func(PollRequest) (*PollResult, error) { return nil, ErrUnreachable })
	r.poll()
	r.poll()
	if calls := r.platform.Calls(); len(calls) != 1 || calls[0] != "quarantine:"+r.enclave.ID {
		t.Fatalf("calls %v, want the armed enclave quarantined", calls)
	}

	r.setListed(func(e *Enclave) { e.ClockConfigVersion = 0 })
	r.poll()
	calls := r.platform.Calls()
	if len(calls) != 2 || calls[1] != "release:"+r.enclave.ID {
		t.Fatalf("calls %v, want a release", calls)
	}
	r.expectAlert(core.EventClockReleased)
	if st := r.state(); st.Quarantined {
		t.Fatalf("position %+v", st)
	}
}

// A control plane that does not say which config each runtime holds (one
// older than the field) arms nothing: no quarantine, and no release of
// one either.
func TestAnOlderControlPlaneArmsNothing(t *testing.T) {
	e := euFrance1()
	e.ClockConfigKnown, e.ClockConfigCurrent = false, 0
	r := newRigFor(t, e)
	r.poller.set(func(PollRequest) (*PollResult, error) { return nil, ErrUnreachable })
	for i := 0; i < 4; i++ {
		r.poll()
	}
	if calls := r.platform.Calls(); len(calls) != 0 {
		t.Fatalf("calls %v", calls)
	}
}

func TestDecideUnconfiguredRaisesOnChangeOnly(t *testing.T) {
	unreachable := model.ClockReading{Outcome: model.ClockOutcomeUnreachable}
	prev := model.ClockEnclave{FailedPolls: 1}
	if d := DecideUnconfigured(prev, unreachable, "", "k"); d.Event != core.EventClockUnconfiguredUnreachable {
		t.Fatalf("two missed polls: %+v", d)
	}
	if d := DecideUnconfigured(prev, unreachable, core.EventClockUnconfiguredUnreachable, "k"); d.Event != "" {
		t.Fatalf("the same problem again: %+v", d)
	}
	notFound := model.ClockReading{Outcome: model.ClockOutcomeRefused, HTTPStatus: 404}
	if d := DecideUnconfigured(prev, notFound, "", "k"); d.Event != "" {
		t.Fatalf("a 404: %+v", d)
	}
}

// The control-plane client stamps each entry with the current config
// version the list carries, and tells an older list (no such field) from
// a version of 0.
func TestTheListCarriesTheClockConfigVersions(t *testing.T) {
	body := `{"clock_config_current_version":3,"enclaves":[
		{"id":"a","kind":"enclave","name":"EU France 1","tee_type":"sgx","mgr_hostname":"eu-france-1-mgr.apps.privasys.org","gateway_host":"192.0.2.21","port":8445,"clock_config_version":0,"quarantined":false},
		{"id":"b","kind":"enclave","name":"m6","tee_type":"tdx","mgr_hostname":"m6-mgr.apps.privasys.org","gateway_host":"192.0.2.6","port":443,"clock_config_version":3,"quarantined":false}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Privasys-App-Identity") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	identity := func(context.Context, []byte) ([]byte, []byte, error) { return []byte("cert"), []byte("quote"), nil }
	p := NewPlatform(srv.URL, identity, time.Now)
	list, err := p.Enclaves(context.Background())
	if err != nil || len(list) != 2 {
		t.Fatalf("%+v %v", list, err)
	}
	if list[0].ClockArmed() || !list[0].ClockNeverConfigured() || list[0].ClockConfigCurrent != 3 {
		t.Fatalf("never acknowledged: %+v", list[0])
	}
	if !list[1].ClockArmed() {
		t.Fatalf("acknowledged the current version: %+v", list[1])
	}

	body = `{"enclaves":[{"id":"b","kind":"enclave","name":"m6","tee_type":"tdx","gateway_host":"192.0.2.6","port":443}]}`
	list, err = p.Enclaves(context.Background())
	if err != nil || len(list) != 1 || list[0].ClockArmed() || list[0].ClockNeverConfigured() {
		t.Fatalf("an older control plane: %+v %v", list, err)
	}
}
