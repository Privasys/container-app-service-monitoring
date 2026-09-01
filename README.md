# container-app-service-monitoring

Service availability monitoring that runs as a confidential container on
Privasys [`enclave-os-virtual`](https://docs.privasys.org/solutions/enclave-os/).

Commercial uptime monitoring is shallow because of a trust problem, not
a technical one. Nobody gives a monitoring vendor a working account on
their production system, so those tools probe the login page rather than
the login, and the service level agreement ends up written against
whatever an anonymous request can reach. The gap between "the homepage
returned 200" and "a customer could actually place an order" is where
every real outage lives.

Running the monitor inside a confidential VM changes what can safely be
handed to it. A credential arrives over a channel whose certificate
carries a hardware quote over the measurement of this build, is sealed
to that measurement, and is bound at creation to the hosts it may be
sent to. So the monitor can log in as a real least-privilege account and
exercise the functionality the agreement is actually about.

The second half follows from the first. An availability record is only
worth what its tamper-evidence is worth, so every reading, incident,
maintenance window and report here is a signed transaction in
[immutable-ledger](https://github.com/Privasys/immutable-ledger), an
authenticated key-value store whose single 32-byte root attests the
whole record. An SLA report carries the readings its arithmetic used,
and the verifier shipped in the same image recomputes the number rather
than checking that somebody signed it.

## What it gives you

**Journeys, not pings.** A monitor is an ordered set of steps: log in,
place an order, read it back, assert that the answer is right rather
than merely present, and delete the order afterwards whether or not the
assertions held. Values extracted from one step are templated into the
next, and a step that fails says which assertion failed and what the
service actually returned.

**And in a real browser, when the API is not the point.** A journey can
run as a page instead of a request: click, fill, wait, read what the
page then says, and photograph it. That runs in a separate enclave, the
attested renderer, whose measurement the owner pins before a credential
is handed to it. A screenshot is judged by arithmetic, never by a model:
did anything render at all, and does it still look like the baseline
somebody approved. See [docs/packs.md](docs/packs.md#browser-journeys).

**A credential that cannot travel.** A credential is bound at creation
to a host or a subtree. The engine refuses to interpolate it into a
request to anywhere else, refuses to put it in a URL at all, and the
refusal is a recorded event rather than a silent empty string. Values
are redacted from captures by the writer that produces them, and a
reading whose output still contains a credential is discarded rather
than stored.

**A record neither side can rewrite.** Every change is a transaction
with a git-style commit envelope: author, acting role, timestamp, a
required message. The envelope and the effects are hashed together, so a
change and the reason for it are one object. The ledger maintains a hash
chain over its own root sequence, so the live root commits to the entire
history behind it, and an auditor can fold the published roots between
two signed anchors with no key at all.

**Reports that recompute.** `monitor-verify report` reads a report and
its bundled readings, recomputes agreed service time, downtime,
availability, the user-weighted figure, coverage and every objective,
and compares them with what the document claims. It also checks the
direction that matters in an argument: that no interval the evidence
shows as down is missing from the report. A signed wrong answer fails.

**Honest arithmetic.** The availability formula is
`((agreed service time - downtime) / agreed service time) x 100`, and
each part of it is a decision written down rather than assumed. Agreed
service time is a schedule in the customer's timezone, so a
business-hours agreement is a first-class thing and the day the clocks
change is genuinely an hour shorter. A user-weighted figure is reported
beside the blunt one, because two hours affecting one back-office
function is not two hours affecting the whole call centre.

**Exclusions with their notice attached.** A maintenance window records
when it was declared. Only a planned window declared with the agreed
notice leaves the denominator; everything else is recorded, shown and
left in it, with its lead time on the page. A window entered after the
outage it covers reads as exactly that.

**Coverage reported next to availability.** A monitor that was down
cannot certify uptime. Every report states the fraction of agreed
service time for which a reading exists, enumerates the gaps, and
reports an objective as `indeterminate` rather than met when coverage
falls below the service's floor. A restart is written into the record as
a first-class event so the gap it leaves is visible rather than
indistinguishable from a quiet period.

**A status page you can check.** The public page is the familiar shape:
a banner, a component tree, ninety days of uptime bars, incident
timelines, scheduled maintenance, an Atom feed, and a JSON surface
existing dashboards already parse (`/api/v2/summary.json` and friends).
It is served from inside the measured image, it names the build that
drew it and the state it read, and clicking a bar fetches the inclusion
proof behind it and checks it in the reader's own browser.

## How a reading becomes a number

```
journey runs ─▶ reading ─▶ folded interval ─▶ availability ─▶ report
     │             │              │                              │
 credentials   detection      one ledger row              one ledger row
 sealed to     opens an       with a proof                committing to a
 the build     incident       anyone can ask for          hash of the readings
```

Everything on that line is a ledger row committed to by one root, and
every arrow is a signed transaction with an author and a reason.

## Running it

The platform injects `$PORT`, mounts a sealed volume at `/data`, and
holds every endpoint at HTTP 503 until the configure call succeeds:

```bash
privasys apps configure <app-id> \
  --set tenant=acme \
  --set pack_ref=example-saas \
  --set callback_url=https://acme.example.com/hooks/availability
```

Then deliver the credentials the journeys use. The value is sealed to
this build's measurement and is never returned by any endpoint:

```bash
privasys apps action <app-id> put_secret \
  --arg name=example_password \
  --arg value='…' \
  --arg hosts='["api.acme.example.com"]'
```

Locally, without the platform:

```bash
go run ./tools/target &                       # a stand-in service to watch
PORT=8080 MONITOR_DATA_DIR=./.data \
  MONITOR_DEV_AUTH=1 MONITOR_SELF_CONFIGURE=1 MONITOR_PACK=example-saas \
  go run ./cmd/monitor
```

Development tokens are `dev:<sub>:<display>:<idp roles>`, so
`dev:you:You:monitoring:owner` is an owner. The status page is at
`/status` and the operator explorer at `/explorer`.

## Checking the evidence

```bash
curl -H "$AUTH" https://…/api/v1/checkpoints/key > key.json
curl -H "$AUTH" -X POST https://…/api/v1/reports \
     -d '{"window":"calendar_month","previous":true,"include_proofs":true}' \
   | jq .report > report.json

monitor-verify report report.json --key key.json
```

```
ok    signature: signed by key 12a166b2dda1cccf...
ok    evidence commitment: 43 folded intervals hash to the committed value
ok    recorded row: the report is a row in the state rooted at 5fa06f533b1bc63e...
ok    document: matches the document recorded in the ledger
ok    anchor: version 84 is the state a signed checkpoint attests
ok    agreed service time: 2678400, recomputed from the evidence
ok    downtime: 120, recomputed from the evidence
ok    availability: 999955, recomputed from the evidence
ok    coverage: 999820, recomputed from the evidence
ok    objective Monthly availability: met at 99.995%
ok    declared outages: every interval the evidence shows as down is declared
```

The other subcommands are `bundle` (one row and its inclusion proof),
`chain` (the checkpoint chain, and that each link names the one before
it) and `lineage`, which folds the published roots between two anchors
and needs no key at all. That last one is the check an auditor actually
runs: a record that was rewritten in between cannot reach the anchored
head, because doing so would be a preimage attack.

## What is attested

Caddy terminates RA-TLS in front of the service, so a client that
verified the certificate has verified a hardware quote over the
measurement of the build serving it. Two further extensions ride on the
per-container leaf:

| OID | Value |
| --- | --- |
| `1.3.6.1.4.1.65230.3.2` | the workload image digest |
| `1.3.6.1.4.1.65230.3.5.1` | SHA-256 of the report signing public key |
| `1.3.6.1.4.1.65230.3.5.2` | the live ledger root |

The signing key extension is the load-bearing one. A report, a
checkpoint and an alert are all signed with that key, so binding it to
the measurement means a verifier who checked the certificate knows which
build holds the key behind the evidence.

## Alert callbacks

Alerts are delivered to a callback whose host was declared at configure
time. The body is canonical JSON, signed with the same key, and carries
the ledger root and version at which the change it reports was recorded,
so a consumer can take the alert back to the monitor and be handed the
readings that caused it rather than a summary of them.

```
POST /hooks/availability
X-Privasys-Signature: ed25519=…
X-Privasys-Key-Id: 12a166b2…
X-Privasys-Event: component.down

{"schema":"privasys.monitor.alert/v1","id":"alt_…","event":"component.down",
 "payload":{"component":"Order API","detail":"the service answered 503, expected 201"},
 "ledger_root":"000124ce…","ledger_version":67}
```

A worked example of the receiving side, which is also what CI runs
against a real delivery, is in
[`tools/verify-webhook.mjs`](tools/verify-webhook.mjs).

Every delivery attempt is recorded, not only the successful one, so "you
never told us" and "you told us six hours late" both have answers.

## Limits

Worth stating plainly, because a monitoring product that overstates
itself is the thing this one exists to replace.

- **Time is enclave-asserted.** The guest clock is host-influenced.
  Ordering is protected by the ledger's monotonic version chain and its
  lineage chain, and wall-clock claims are anchored from outside by
  delivering checkpoints to the customer, whose own receipt bounds them.
  We do not claim trusted time.
- **A single vantage point cannot tell "your service is down" from "my
  network is broken."** This build observes from one place and says so;
  quorum across several is designed for and not yet built.
- **Outbound restriction is enforced by this application, not by the
  kernel.** The allowlist is built from signed transactions and refuses
  anything undeclared, but a compromise of this process is a compromise
  of that rule.
- **The monitor observes what its journeys exercise.** An agreement over
  functionality nobody scripted is not measured by this, or by anything
  else.
- **A screenshot cannot be redacted.** Capture is opt-in per step, so a
  journey need not photograph the page it has just typed a credential
  into, and password fields are masked by the browser. A token the page
  displays would be in the picture.
- **No model looks at a screenshot, deliberately.** A model's judgement
  does not recompute, and an availability figure resting on one could
  not be checked. The visual checks are arithmetic over pixels; a model
  belongs on the other side of that line, explaining a difference to a
  person.
- Not FIPS-certified, and not independently audited.

## Repository layout

| Path | What is in it |
| --- | --- |
| [`cmd/monitor`](cmd/monitor) | The service. |
| [`cmd/monitor-verify`](cmd/monitor-verify) | The offline verifier, shipped in the same image. |
| [`internal/journey`](internal/journey) | Step execution, templating, assertions, egress, and the attested browser leg. |
| [`internal/visual`](internal/visual) | What a screenshot means, as arithmetic: blank detection and a perceptual hash against an approved baseline. |
| [`internal/secrets`](internal/secrets) | The sealed credential store and the redactor. |
| [`internal/availability`](internal/availability) | The arithmetic, as a pure package. |
| [`internal/core`](internal/core) | Transactions, detection, incidents, reports, anchors. |
| [`internal/api`](internal/api) | REST, the status page, the explorer. |
| [`packs/example-saas`](packs/example-saas) | The reference service model. |
| [`tools/target`](tools/target) | A stand-in service, so the tests watch something real. |
| [`docs/`](docs) | Architecture, the availability model, packs, operations, auditing. |

## Licence

AGPL-3.0. See [LICENSE](LICENSE).
