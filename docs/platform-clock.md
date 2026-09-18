# The platform clock

An optional mode in which this monitor watches the time of every enclave
of a Privasys fleet, and of every vault of its key vault constellation,
instead of a customer's service. It is off unless a
configure call turns it on, and a customer instance never runs it. The
platform runs one instance per environment, as the app
`platform-monitoring` ("Platform monitoring").

## Why an enclave needs someone to check its clock

An enclave takes its time from its host. Quote freshness, certificate
validity, token expiry and every other "is this still valid" decision
rest on that time, so a host that rolls its clock back can get an
expired credential accepted. The enclave runtimes defend themselves
against this. The monitor is what they check against.

It works in both directions:

- Every five minutes the monitor sends each enclave's runtime a signed
  floor: "for this enclave, the time is at least T". The runtime
  compares its host's time with T. When they agree within 10 seconds,
  the host is trusted. When they do not, the runtime asks Network Time
  Security servers on the internet which of the two is wrong, and if it
  is the host, the runtime freezes its time at the NTS time and flags
  itself.
- A runtime that sees a problem outside a poll (a host time behind its
  floor on a read, a failed NTS fetch at boot or while flagged) reports
  an incident to the monitor straight away; for a host behind the floor
  it waits for a signed receipt before it goes on. Runtimes do not
  otherwise check their host between polls: a host that blocks the
  polls is the monitor's to catch, and it quarantines an enclave that
  misses two polls in a row (see [Quarantine](#quarantine)).

The monitor only ever triggers. Its time never becomes an enclave's
trusted time on its own: a runtime that disagrees with the monitor asks
NTS, so a monitor that is wrong, or lies, causes an NTS fetch and a false
alarm, never a wrong time. That is also why the floor carries no bearer
and the runtime's reply carries no signature: the floor is authenticated
by the monitor's key, and the reply by the attested channel it travels
on.

## The monitor's own time

The monitor's host can be wrong too, so the time it signs does not come
from its wall clock. It comes from NTS (RFC 8915): a TLS 1.3 key
exchange with a named server whose certificate is checked, then NTP
packets authenticated with the keys that exchange produced.

- Ten servers are pinned in the build, one per operator: national
  metrology institutes, internet exchanges, a registry, universities and
  companies across Europe. The list is part of the measurement; changing
  it is a new build.
- Two are picked at random. They must agree within two seconds. If they
  do not, or one does not answer, a third is asked and two that agree
  win. Otherwise there is no trusted time, and the monitor sends no floor
  rather than guess.
- A reply slower than two seconds is refused. The round trip is measured
  on Go's monotonic clock, which the host cannot set, so a reply the host
  holds back moves the estimate by at most half of it.
- The fetched time is kept as an offset from the monotonic clock, never
  from the wall clock. Between two fetches the time moves with the
  monotonic clock, so a host that steps its wall clock after a fetch
  changes nothing. The time is fetched again at every round; if fetches
  keep failing, the last one is extrapolated for 30 minutes and then
  abandoned.
- A server's certificate is checked at the later of the host's time and
  the monitor's floor (the highest time it trusted before, and never
  earlier than the build). A host that rolls the clock back cannot make
  an expired certificate look valid.

## The key

The clock key is an Ed25519 key derived from the sealed master secret,
separate from the key that signs reports, checkpoints and alerts. The
same approved build on the same volume always comes back with the same
key, so the runtimes keep accepting it across a restart, and a different
build cannot hold it.

SHA-256 of the public key is committed to the per-container RA-TLS leaf
at OID `1.3.6.1.4.1.65230.5.4.3`, on an instance running the platform
clock only. The platform reads it there before it hands the key to the
runtimes, so the key they pin is one only this measurement holds.

```
GET /api/v1/clock/key

{"alg":"ed25519","public_key":"<base64url, 32 bytes>","key_id":"21b477a8c7a7960d",
 "sha256":"21b477a8…","attestation_oid":"1.3.6.1.4.1.65230.5.4.3",
 "floor_domain":"privasys-clock-floor/v1","receipt_domain":"privasys-clock-receipt/v1"}
```

`key_id` is the first sixteen hex characters of SHA-256 over the raw
public key.

## Wire formats

Keys are Ed25519, times are Unix milliseconds, base64 is base64url
without padding. A signed payload is the exact UTF-8 bytes of its lines
joined with `\n`, with no trailing newline.

**Floor**, monitor to runtime, `POST /api/v1/clock/poll` on the
enclave-os-virtual manager and `POST /clock/poll` on the enclave-os-mini
core, reached through the enclave's manager hostname (a vault's core
directly at its own address, see [Vaults](#vaults)):

```json
{ "enclave_id": "…", "t_ms": 1789000000000, "seq": 42, "key_id": "…", "sig": "…" }
```

signed over `privasys-clock-floor/v1`, `enclave_id`, `t_ms`, `seq`.
`seq` never repeats, across restarts included: a restarted instance
continues from the highest one in its record.

**Reply**, over the same connection:

```json
{ "enclave_id": "…", "runtime": "virtual", "host_time_ms": 0,
  "trusted_time_ms": 0, "floor_ms": 0, "flagged": false, "reason": "",
  "verdict": "in_sync", "nts": { "time_ms": 0, "servers": [] },
  "config_key_id": "…" }
```

**Incident**, runtime to monitor, `POST /api/v1/clock/incidents`, no
credentials:

```json
{ "enclave_id": "…", "reason": "host_behind_floor", "host_time_ms": 0,
  "floor_ms": 0, "nts_time_ms": 0, "nonce": "<32 bytes>" }
```

**Receipt**, the answer to an incident:

```json
{ "incident_id": "cki_…", "nonce": "…", "key_id": "…", "sig": "…" }
```

signed over `privasys-clock-receipt/v1`, `enclave_id`, `nonce` (exactly
as the runtime sent it), `incident_id`.

## Polling over RA-TLS

A floor goes to the enclave's manager hostname, the one route the
gateways keep serving while an enclave is quarantined. The connection
advertises the RA-TLS protocol marker, so the gateway splices it
straight through to the enclave rather than terminating it. Before the
floor is sent, the monitor verifies what answered:

1. the certificate chains to the Privasys fleet;
2. a hardware quote is requested on the same connection, bound to it
   through a TLS exporter value only its two ends can compute;
3. the quote's report data commits to the certificate's key;
4. the quote is verified by the attestation server, with a short-lived
   token the platform hands the monitor for its attested identity.

A runtime whose evidence does not verify is recorded as `unverified`,
and nothing it said is used.

A vault is polled the same way, except for where the connection goes:
nothing routes by name in front of a vault, so the monitor connects to
the vault's own address as the platform lists it (`gateway_host` and
`port`), with no server name, and sends the floor to the core's
`POST /clock/poll`. The certificate chain, the quote bound to the
connection and its verification by the attestation server are the same.

## Incidents

An incident is answered with a signed receipt at once, whatever else is
happening: a runtime that gets no receipt within five seconds fails
closed, so the receipt never waits on the ledger for more than 700
milliseconds. The report is then recorded, and the enclave it names is
polled straight away.

The report itself decides nothing. Anyone can send one; only an attested
runtime can answer a poll, and the monitor acts on the poll's answer.
Reports cause at most one poll of an enclave a minute; the scheduled
round polls it every five minutes regardless.

Because the endpoint takes no credentials, what it can cost is bounded.
A report is taken only for an enclave in the platform's list, and at most six a minute for one enclave and sixty a minute in all. Each
report taken is one ledger write, so that is also the bound on what the
endpoint can write. A refused report gets no receipt: 404 for an
enclave the monitor does not watch, 429 (with `Retry-After`) over the
rate, 400 for a malformed report.

When the monitor stops, the clock stops first: no new report is taken
(503), the polls reports caused are cancelled and waited for, five
seconds at most, and anything still running after that writes nothing.
A poll cut short that way is not recorded, so it never counts against
the enclave as a silent poll.

The list is fetched as soon as the clock starts, before its first NTS
fetch, and again at every round. A report naming an enclave the list
does not have (one that registered since the last round) causes one
more fetch, then the check again; that happens at most once a minute,
and fetches never overlap, so made-up enclave ids cannot drive calls to
the control plane.

Runtimes reach this endpoint the same way the monitor reaches them,
through the gateway's splice path, and the handler reads nothing a
terminating proxy would add.

## Quarantine

A quarantine asks the platform to stop serving an enclave's apps at the
gateways, so users are not handed answers computed on a wrong or frozen
clock. The enclave keeps running and its manager route stays up, so the
monitor can keep checking it. These quarantine:

- the runtime's verdict is `host_clock_wrong`;
- the runtime answers flagged, serving a frozen time;
- the runtime has no trusted time and is failing closed, whether it says
  so in its answer (`nts_unreachable`, no trusted time) or refuses the
  floor because its host and the floor disagree and NTS is silent;
- the host clock is more than 10 seconds from the monitor's, measured at
  the midpoint of the round trip, unless the runtime found the monitor
  to be the one that is wrong;
- an enclave that was flagged at its last answer stops answering;
- an enclave that gives no answer to two polls in a row (no connection,
  or none within the 30-second poll timeout), whatever it said before,
  with the reason `unreachable`. A host can keep the monitor out by
  dropping the manager route, or by holding the runtime's NTS fetch past
  the timeout, while nothing is flagged yet.

A release needs all of it at once: an attested answer, verdict
`in_sync`, not flagged, a trusted time, and within the tolerance. The
monitor only lifts a quarantine it placed itself; one an operator placed
is theirs. If an operator lifts one of the monitor's and the next answer
still shows the problem, the monitor quarantines again.

Every request carries the reading that caused it as evidence, and every
request is a ledger transaction whether the platform accepted it or not,
with an alert.

Not a clock problem, and never quarantined for on its own:

- a runtime that does not hold this monitor's key: it refuses the floor
  as unconfigured (409) or foreign (401), or answers naming another key.
  That is reported once, as `clock.runtime_config_missing`, and the fix
  is to push the monitor's configuration to the runtimes again;
- a runtime found the monitor's clock wrong (`monitor_clock_wrong`).
  That is the monitor's problem, and it is alerted on as such.

## Vaults

The members of the platform's active key vault constellation run the
same SGX runtime core as the other SGX enclaves, with the same clock, so
the platform lists them too, with `kind` `vault`. They are polled every
round like the enclaves, and their answers are recorded the same way.
Their incident reports are taken like any other listed runtime's.

A vault is never quarantined. Its callers reach it directly at its own
address, not through a gateway, so there is nothing that could withhold
it, and the platform refuses a quarantine that names one. The findings
that would quarantine an enclave raise an alert instead, and the first
clean poll after one (an attested answer, `in_sync`, not flagged, a
trusted time, within the tolerance) raises a recovered alert:

- `clock.vault_host_clock_wrong`: verdict `host_clock_wrong`, a flagged
  (frozen) answer, no trusted time (whether said in an answer or by
  refusing the floor), or a host clock more than 10 seconds from the
  monitor's;
- `clock.vault_unreachable`: two polls in a row with no answer;
- `clock.vault_recovered`: the clean poll, naming the alert it ends.

An alert is raised when the finding changes, not on every reading. The
alert standing on each vault is kept in the record with the reading that
raised it. A vault on a build that predates the clock answers the poll
with 404: that is recorded, and alerted on by neither rule.

## Alerts

Delivered like every other alert, signed and carrying the ledger
coordinates of the change, to the clock's callback:

| Event | When |
| --- | --- |
| `clock.quarantined` | an enclave was quarantined |
| `clock.released` | an enclave was released |
| `clock.action_failed` | the platform refused a quarantine or a release |
| `clock.monitor_clock_wrong` | a runtime found the monitor's clock wrong |
| `clock.runtime_config_missing` | a runtime does not hold the monitor's key |
| `clock.trusted_time_lost` | the monitor has no trusted time, and sends no floor |
| `clock.vault_host_clock_wrong` | a vault's host clock is wrong, its time frozen, or it has none |
| `clock.vault_unreachable` | a vault gave no answer to two polls in a row |
| `clock.vault_recovered` | a clean poll after one of the two above |

## The record

Everything is ledgered, in five tables: `clock_readings` (one row per
poll, answered or not: the floor sent, the monitor's time at the
answer, the round trip, the runtime's host time, trusted time, floor,
flag, verdict and NTS time, and the drift), `clock_incidents` (reports
as received), `clock_actions` (every quarantine and release asked for,
with its evidence and the platform's answer), `clock_enclaves` (the
current position on each enclave and vault) and `clock_vault_alerts` (the
alert standing on each vault). Each vault alert is written in the same
transaction as the alert it raises.

## Endpoints

| Endpoint | Who | What |
| --- | --- | --- |
| `GET /api/v1/clock/key` | anyone | the clock key |
| `POST /api/v1/clock/incidents` | anyone | report an incident, get a receipt |
| `GET /api/v1/clock/fleet` | explorer | the fleet view: every enclave's and vault's latest reading, drift, `kind`, quarantine (enclaves) or `vault_alert` (vaults), and the monitor's own time |
| `GET /api/v1/clock/readings?enclave=&limit=` | explorer | readings, newest first |
| `GET /api/v1/clock/incidents?limit=` | explorer | incident reports, newest first |
| `GET /api/v1/clock/actions?limit=` | explorer | quarantines and releases, newest first |
| `POST /api/v1/clock/enclaves/{id}/poll` | run | poll one enclave now |

On an instance that does not run the platform clock, every one of them
answers 404.

## Turning it on

The instance calls the platform control plane as an attested app: each
request carries an identity certificate minted for this container by
the measured enclave manager and a quote binding it to a fresh
challenge. No token is configured. The platform operator grants the
instance's app id the two platform rights it uses, `clock-monitor` (list
the enclaves) and `clock-quarantine`.

Then the configure call:

```json
{
  "tenant": "privasys-platform",
  "callback_url": "https://alerts.example.org/hooks/clock",
  "platform_clock": {
    "enabled": true,
    "management_url": "https://api.example.org"
  }
}
```

| Field | Meaning |
| --- | --- |
| `enabled` | turns the platform clock on; omitted or false leaves it off |
| `management_url` | the platform control plane |
| `callback_url` | where the clock's alerts go; defaults to the top-level `callback_url` |
| `allow_debug_images` | accept runtimes on development images; leave off for production |

Once it runs, read `GET /api/v1/clock/key`, check its `sha256` against
the certificate extension, and give the platform the `public_key` and
this instance's incident URL (`https://<this instance>/api/v1/clock/incidents`)
so it can deliver both to the runtimes.

The configuration is kept on the sealed volume like the rest, so a
restart resumes polling by itself, from the next sequence number.

## Limits

- **Any genuine runtime of the fleet is accepted as the answerer.** The
  monitor checks that the reply comes from a genuine enclave whose
  certificate chains to the Privasys fleet, over a connection its quote
  is bound to. The platform's enclave list carries no measurements, so
  the monitor does not pin which runtime build each enclave runs; the
  platform does that when it approves the enclave. A vault runs a
  different build from the enclaves, and is accepted on the same terms:
  a genuine SGX quote from a runtime chaining to the fleet.
- **The monotonic clock is the guest kernel's.** Go's monotonic clock
  cannot be set, by the host or anyone else, but its rate comes from the
  guest's clock source. On a guest that reads the processor's timestamp
  counter the host cannot change that rate; on one that reads a
  host-provided clock source it can only skew it slowly, and every round
  fetches the time again.
- **The platform's answers about its enclaves are trusted.** Which
  enclaves exist, and which are already quarantined, is what the control
  plane says. An enclave it does not list is not polled.
- **Readings are not pruned yet.** A reading every five minutes per
  enclave is about a hundred thousand rows per enclave a year, all in the
  ledger.
