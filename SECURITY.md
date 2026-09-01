# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
**security@privasys.org**. Do not open public issues for security
reports. We aim to acknowledge reports within 48 hours and to keep you
informed of progress; coordinated disclosure timelines are agreed per
report.

Please include what you can: the affected commit or image digest, the
service model in use, the acting role of the caller, reproduction steps,
and an impact assessment.

## Scope

This service makes a small number of claims. A way to break any of them
is what we most want to hear about.

- **A credential goes only where it was bound.** A path that sends a
  credential to a host outside its binding, that places one in a URL,
  that admits a lookalike domain through a subtree binding, or that
  follows a redirect to a host the allowlist does not permit.
- **A credential never reaches the record.** A path that writes a
  credential value into a reading, a capture, a log line, an alert
  payload, an incident body or a report, including through a watched
  service that reflects what it was sent.
- **Nothing can be covertly altered or deleted.** A path that changes
  the availability record without a signed, logged transaction; a prune
  that makes removed readings indistinguishable from readings that never
  existed; a maintenance window whose declared-at can be moved after the
  fact.
- **Evidence means what it says.** An inclusion or absence proof
  accepted for a statement false at that root; an evidence bundle that
  verifies after being edited; a checkpoint accepted from a key other
  than the one published; a lineage fold that reaches an anchored head
  over a rewritten root sequence.
- **A report is a computation.** A report whose figures
  `monitor-verify report` accepts but whose own evidence contradicts;
  downtime present in the bundled readings and absent from the report;
  an objective reported as met on evidence below the coverage floor.
- **Authorisation holds.** A caller acting under a role they do not
  hold; a public endpoint that serves a private service; an
  authenticated endpoint reachable without a bearer.

## Out of scope

- The confidentiality of data held by the service the monitor watches.
  This service holds readings about that service and credentials for it,
  not its data.
- Denial of service through resource exhaustion by an authorised caller.
- Reports that a watched service is slow or unavailable. That is the
  product working.
- Findings that depend on `MONITOR_DEV_AUTH` or `MONITOR_SELF_CONFIGURE`
  being enabled. Both are development modes and both are refused when
  the platform's container credentials are present.

## Known limits

These are documented rather than fixed, and are not vulnerabilities:

- Timestamps are the enclave's own assertion. Ordering is protected by
  the ledger's version and lineage chains, and wall-clock claims are
  anchored from outside by checkpoint delivery to the customer.
- A single vantage point cannot distinguish a failure of the watched
  service from a failure of the path to it.
- The outbound allowlist is enforced by this application, not by the
  kernel.
- The monitor observes what its journeys exercise, and nothing else.

## Trust boundaries

The application runs inside a confidential VM. Transport is terminated
by RA-TLS in front of it, so a client that verified the certificate has
verified a hardware quote over the measurement of the build serving the
request. The sealed volume's key is released only to an approved
measurement, so the signing key and the credentials are readable only by
an approved build on that machine.

The platform operator can see TLS metadata, container lifecycle and
resource usage. They cannot read the credentials, the captures or the
record.
