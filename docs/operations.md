# Operations

## Configuration

The platform holds every endpoint at HTTP 503 until the configure call
succeeds, and re-arms the gate on each restart. The configure surface is
gated by the runtime to the app's owners and admins at enclave level, so
the application cannot omit that check.

```bash
privasys apps configure <app-id> \
  --set tenant=acme \
  --set pack_ref=example-saas \
  --set callback_url=https://acme.example.com/hooks/availability \
  --set maintenance_lead_time=86400 \
  --set raw_retention_days=90
```

| Field | Meaning |
| --- | --- |
| `tenant` | the customer this instance watches for. One instance serves one tenant. |
| `pack_ref` / `pack` | a service model baked into the image, or one delivered inline. |
| `callback_url` | where alerts are delivered. Its host joins the outbound allowlist. |
| `callback_hosts` | extra hosts this instance may contact. |
| `maintenance_lead_time` | notice a planned window needs to leave agreed service time. Default 86400. |
| `raw_retention_days` | how long individual readings are kept. Default 90. |

## Environment

| Variable | Meaning |
| --- | --- |
| `PORT` | injected by the platform. Required; there is no fallback, because a hard-coded port collides with a co-located app. |
| `MONITOR_DATA_DIR` | the sealed volume. Default `/data`. |
| `MONITOR_NAME`, `MONITOR_VANTAGE` | instance and observation-point names, which appear in checkpoints and readings. |
| `MONITOR_OIDC_ISSUER`, `MONITOR_OIDC_AUDIENCE` | token verification. Default `https://privasys.id` / `privasys-platform`. |
| `MONITOR_CHECKPOINT_INTERVAL` | how often a quiet monitor anchors itself. Default 6h. |
| `MONITOR_ROLLUP_LAG` | how far behind the present the folder works. Default 90s. |
| `MONITOR_DEV_AUTH`, `MONITOR_SELF_CONFIGURE`, `MONITOR_PACK` | development only. Refused when the platform's container credentials are present. |

## Credentials

```bash
privasys apps action <app-id> put_secret \
  --arg name=example_password \
  --arg value='…' \
  --arg hosts='["api.acme.example.com"]' \
  --arg description='the dedicated monitoring account'
```

The value is sealed to this build's measurement and is never returned by
any endpoint. What comes back is the record: the binding and a keyed
fingerprint, which is how an operator confirms a rotation changed
something without the value being readable.

Rotation is the same call with a new value. Destruction destroys the
key, so the value is unrecoverable from that moment while the record of
it stays:

```bash
curl -H "$AUTH" -X DELETE https://…/api/v1/secrets/example_password
```

Bind a credential to a host or a subtree (`.example.com`), never to
everything; the vault refuses that outright. The binding is what stops a
repointed monitor exfiltrating the account it was given.

## Roles

Roles come from the identity provider's token. The built-in model:

| Role | Identity-provider role | May |
| --- | --- | --- |
| owner | `monitoring:owner` | everything, including retention and instance settings |
| editor | `monitoring:editor` | edit the model, manage credentials, respond, report |
| responder | `monitoring:responder` | run checks, run incidents, declare maintenance, read the record |
| auditor | `monitoring:auditor` | read the record, the anchors and the reports |
| viewer | `monitoring:viewer` | read the record and the anchors |

Anonymous callers reach the public status surface and nothing else.

## Day-to-day

**Watch what it is doing.** `GET /api/v1/status` (or the `status` tool)
gives the lifecycle state, the ledger root and version, each service's
current indicator, the last checkpoint, and the outbound allowlist this
instance is confined to.

**Run a check by hand** while diagnosing something:

```bash
privasys apps action <app-id> run_check --arg monitor=<monitor-id>
```

The reading is recorded and visible, and marked manual, so it never
enters the availability series. Pressing that button during an incident
cannot change what the month's report says.

**Declare maintenance before it starts.** The answer tells you at once
whether the window will leave the agreed service time and why:

```json
{"excluded": true, "lead_time": 604800,
 "lead_time_text": "declared 7 days ahead, so it leaves the agreed service time"}
```

Finding that out from next month's report is finding out too late.

**Run an incident.** Detection opens one automatically with the
triggering readings attached; updates are signed transactions and are
what the status page renders. Resolution needs a message, like every
other change.

**Issue a report** at the end of the period, with proofs:

```bash
privasys apps action <app-id> report \
  --arg window=calendar_month --arg previous=true --arg include_proofs=true
```

Keep it, and keep the checkpoints. See [auditing.md](auditing.md).

## Alert receivers

Verify the signature before acting on the body:

```
X-Privasys-Signature: ed25519=<base64 over the canonical body>
X-Privasys-Key-Id:    <the key in /.well-known/privasys-monitor.json>
X-Privasys-Delivery-Id: <stable across retries; deduplicate on it>
```

The body carries `ledger_root` and `ledger_version`, so an alert is a
pointer to evidence rather than a claim: ask the monitor for that
version and you are handed the readings that caused it.

[`tools/verify-webhook.mjs`](../tools/verify-webhook.mjs) is a worked
example of the check, and is what CI runs against a real delivery. Verify
the bytes that arrived: the signature covers them exactly, so
re-serialising the body before checking makes the check meaningless.

Delivery is retried with a widening gap and then given up on. Every
attempt is recorded, so "you never told us" and "you told us six hours
late" both have answers.

## Restarts and redeploys

A restart is not a reconfiguration. On boot the process restores its
configuration from the sealed volume, lifts the platform's configure
gate itself, and republishes the attested extensions, which live in the
manager's memory rather than on the volume.

The boot is written into the record with the gap since the last one,
because coverage is reported beside availability and a monitor that was
not running did not see a service that was up. Expect a redeploy to show
up as a coverage gap in that period's report. That is the system working.

## Storage

`/data` holds the sealed key material, the credential vault and the
ledger. It is a LUKS2 volume whose key is released only to an approved
measurement, so `container_storage=true` is required: without it the
signing key changes on every deploy and no previously issued evidence
verifies against the new one.

Readings are pruned on the retention window by a signed transaction;
reclaiming the storage behind them is a separate, deliberate step that
refuses to run for a version no checkpoint covers.

## Troubleshooting

**Everything answers 503.** The configure gate has not been lifted.
`GET /health` reports the state and any configuration failure.

**Readings are `error` with class `policy`.** The monitor could not take
a reading: a credential is missing, a credential is bound to a different
host than the step targets, or the step's host is not on the outbound
allowlist. The detail says which. These cost coverage and are never
charged to the watched service.

**A journey fails at an assertion.** The reading names the step and the
assertion, and the capture shows what the service actually returned,
with credentials redacted.

**Objectives are all `indeterminate`.** Coverage is below the service's
floor. The report enumerates the gaps; look for restarts in
`GET /api/v1/events`.

**The status page shows a component with grey bars.** No readings exist
for those days. A day nobody watched is drawn as unknown rather than as
a good day, deliberately.
