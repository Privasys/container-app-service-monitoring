// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package model

// The platform clock's record.
//
// An instance running the platform clock watches the time of every
// enclave of a fleet. Its readings, the incidents the runtimes report
// and every quarantine it asks for are ledger rows like everything else
// here, so the fleet view is a read of the record, and a quarantine can
// be followed back to the reading that caused it.

// Transaction kinds of the platform clock.
const (
	KindClockReadings   = "clock.readings"
	KindClockIncident   = "clock.incident"
	KindClockQuarantine = "clock.quarantine"
	KindClockRelease    = "clock.release"
)

// Why a poll was made.
const (
	ClockCauseScheduled = "scheduled"
	ClockCauseIncident  = "incident"
	ClockCauseManual    = "manual"
)

// What came of a poll. Only ClockOutcomeOK carries a runtime's answer;
// every other outcome says why there is none.
const (
	// ClockOutcomeOK: an attested runtime answered.
	ClockOutcomeOK = "ok"
	// ClockOutcomeUnreachable: no connection, or no answer in time.
	ClockOutcomeUnreachable = "unreachable"
	// ClockOutcomeUnverified: the peer's evidence did not verify, so what
	// it said cannot be attributed to an enclave runtime.
	ClockOutcomeUnverified = "unverified"
	// ClockOutcomeRefused: the runtime answered with an error, including
	// the one it gives when it has failed closed.
	ClockOutcomeRefused = "refused"
	// ClockOutcomeInvalid: the answer did not parse, or was about another
	// enclave.
	ClockOutcomeInvalid = "invalid"
)

// ClockReading is one poll of one enclave runtime.
type ClockReading struct {
	ID          string `json:"id"`
	EnclaveID   string `json:"enclave_id"`
	EnclaveName string `json:"enclave_name,omitempty"`
	TeeType     string `json:"tee_type,omitempty"`
	Cause       string `json:"cause"`
	IncidentID  string `json:"incident_id,omitempty"`
	// Seq and SentMs are the floor that was signed and sent.
	Seq    int64 `json:"seq"`
	SentMs int64 `json:"sent_ms"`
	// MonitorMs is the monitor's trusted time when the answer arrived.
	MonitorMs int64 `json:"monitor_ms"`
	// RTTMs is the round trip of the poll, measured on the monotonic
	// clock.
	RTTMs   int64  `json:"rtt_ms"`
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
	// HTTPStatus is the runtime's status code, when it answered at all.
	HTTPStatus int `json:"http_status,omitempty"`
	// The runtime's answer.
	Runtime     string   `json:"runtime,omitempty"`
	HostMs      int64    `json:"host_ms,omitempty"`
	TrustedMs   int64    `json:"trusted_ms,omitempty"`
	FloorMs     int64    `json:"floor_ms,omitempty"`
	Flagged     bool     `json:"flagged"`
	Reason      string   `json:"reason,omitempty"`
	Verdict     string   `json:"verdict,omitempty"`
	NTSMs       int64    `json:"nts_ms,omitempty"`
	NTSServers  []string `json:"nts_servers,omitempty"`
	ConfigKeyID string   `json:"config_key_id,omitempty"`
	PlatformID  string   `json:"platform_id,omitempty"`
	// DriftMs is the host's time minus the monitor's at the midpoint of
	// the round trip: how far the host clock is from the monitor's.
	DriftMs int64 `json:"drift_ms"`
}

// ClockIncident is one incident report as it was received. It is a
// claim, not a finding: anyone can send one.
type ClockIncident struct {
	ID         string `json:"id"`
	EnclaveID  string `json:"enclave_id"`
	Reason     string `json:"reason"`
	HostMs     int64  `json:"host_ms"`
	FloorMs    int64  `json:"floor_ms"`
	NTSMs      int64  `json:"nts_ms"`
	Nonce      string `json:"nonce"`
	ReceivedMs int64  `json:"received_ms"`
	KnownFleet bool   `json:"known_enclave"`
	RemoteAddr string `json:"remote_addr,omitempty"`
}

// ClockAction is a quarantine or a release the monitor asked the
// platform for, and how the platform answered.
type ClockAction struct {
	ID        string `json:"id"`
	EnclaveID string `json:"enclave_id"`
	// Op is "quarantine" or "release".
	Op        string `json:"op"`
	Reason    string `json:"reason"`
	ReadingID string `json:"reading_id,omitempty"`
	// Evidence is the document sent with the request.
	Evidence   map[string]any `json:"evidence,omitempty"`
	Applied    bool           `json:"applied"`
	HTTPStatus int            `json:"http_status,omitempty"`
	Error      string         `json:"error,omitempty"`
	AtMs       int64          `json:"at_ms"`
}

// Clock action operations.
const (
	ClockOpQuarantine = "quarantine"
	ClockOpRelease    = "release"
)

// ClockEnclave is the monitor's current position on one enclave: the
// fleet view is these rows.
type ClockEnclave struct {
	EnclaveID   string `json:"enclave_id"`
	Name        string `json:"name,omitempty"`
	TeeType     string `json:"tee_type,omitempty"`
	MgrHostname string `json:"mgr_hostname,omitempty"`
	// Last reading of any outcome.
	LastReadingID string `json:"last_reading_id,omitempty"`
	LastOutcome   string `json:"last_outcome,omitempty"`
	LastMs        int64  `json:"last_ms,omitempty"`
	// Last reading in which the runtime answered.
	LastOKMs      int64  `json:"last_ok_ms,omitempty"`
	LastVerdict   string `json:"last_verdict,omitempty"`
	LastFlagged   bool   `json:"last_flagged"`
	LastReason    string `json:"last_reason,omitempty"`
	LastDriftMs   int64  `json:"last_drift_ms"`
	LastHostMs    int64  `json:"last_host_ms,omitempty"`
	LastConfigKey string `json:"last_config_key_id,omitempty"`
	// ConfigMissing is true while the runtime does not hold this
	// monitor's key: it refused the floor as unconfigured or foreign, or
	// answered naming another key. The fix is on the platform side, and
	// it is alerted on, never quarantined for.
	ConfigMissing bool `json:"config_missing"`
	// Quarantined is true while a quarantine this monitor asked for is in
	// force. One an operator placed is reported by the platform, not
	// here, and this monitor never lifts it.
	Quarantined      bool   `json:"quarantined"`
	QuarantinedMs    int64  `json:"quarantined_ms,omitempty"`
	QuarantineReason string `json:"quarantine_reason,omitempty"`
	UpdatedMs        int64  `json:"updated_ms"`
}
