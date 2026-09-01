# Auditing the record

Four checks, in increasing order of how much they establish and
decreasing order of how much they require. The last one needs no key at
all, which is why it is the one an auditor actually runs.

Everything here runs against files. `monitor-verify` ships inside the
same image as the service, so an operator can hand a counterparty a
binary that checks the evidence rather than an invitation to trust it.

## Getting the key

```bash
curl -H "$AUTH" https://…/api/v1/checkpoints/key > key.json
```

Or, without a token, from the well-known document, which also names the
measurement the key is bound to:

```bash
curl https://…/.well-known/privasys-monitor.json | jq .signing_key > key.json
```

The same key's SHA-256 is published on the RA-TLS leaf certificate at
OID `1.3.6.1.4.1.65230.3.5.1`. A client that verified the certificate
therefore knows which build holds the key behind everything below.

## One row: `bundle`

```bash
curl -H "$AUTH" "https://…/api/v1/proofs/buckets/$MONITOR/60/$START" > bundle.json
monitor-verify bundle bundle.json --key key.json
```

Three things are established: the inclusion proof folds to the claimed
root, the service signed the bundle, and the state it was read at is the
state a signed checkpoint attests. Editing any field of the bundle
breaks the second check; editing the proof breaks the first.

The evidence endpoint behind the status page is anonymous, so a reader
with no account can do the same thing:

```bash
curl "https://…/api/v1/public/evidence/bucket?monitor=$MONITOR&width=60&start=$START"
```

That is what the status page itself does when a reader clicks a bar. The
arithmetic runs in the browser; the page is only the messenger.

## The anchors: `chain`

```bash
curl -H "$AUTH" "https://…/api/v1/checkpoints?limit=1000" > chain.json
monitor-verify chain chain.json --key key.json
```

Every checkpoint is signed, and every one names the version and root of
the one before it. A service that served two histories has to have
signed both, and the fork appears as a link that does not match.

Checkpoints are what a customer holds outside the system that produced
them. Keep them. A record restored from an older copy of its own storage
is a consistent history, just not the current one, and the only thing
that catches it is a checkpoint the customer already had. A customer's
own receipt of a checkpoint also bounds the enclave's clock claim
against their own, which is the answer to "the timestamps are the
enclave's assertion".

## The history: `lineage`

```bash
FROM=$(jq '[.checkpoints[].checkpoint.version] | min' chain.json)
TO=$(jq   '[.checkpoints[].checkpoint.version] | max' chain.json)
curl -H "$AUTH" "https://…/api/v1/audit/roots?from=$FROM&to=$TO" > roots.json

jq -n --slurpfile c chain.json --slurpfile r roots.json --argjson f "$FROM" --argjson t "$TO" '{
  from: ($c[0].checkpoints[] | select(.checkpoint.version == $f)),
  to:   ($c[0].checkpoints[] | select(.checkpoint.version == $t)),
  roots: $r[0].roots }' > lineage.json

monitor-verify lineage lineage.json --key key.json
```

Every commit extends a hash chain over the root sequence, and the chain
head is itself a leaf, so the live root commits to the entire history
behind it. Given two anchors and the roots between them, all of which
are public, the earlier head folds forward with a pure function and has
to arrive at the later one:

```
head_v = SHA-256("immutable-ledger:history:v1" ‖ head_{v-1} ‖ root_{v-1} ‖ v)
```

A record that was rewritten in between cannot reach the anchored head:
doing so is a preimage attack. The fold needs no commitment key and no
access to the service, which is what makes it a third party's check
rather than the operator's.

## The report: `report`

```bash
curl -H "$AUTH" -X POST https://…/api/v1/reports \
  -d '{"window":"calendar_month","previous":true,"include_proofs":true}' \
  | jq .report > report.json

monitor-verify report report.json --key key.json
```

This is the one that matters, because it does not check that a number
was signed. It recomputes the number.

| Check | What it establishes |
| --- | --- |
| signature | the document is the one the service signed, evidence included |
| evidence commitment | the bundled readings hash to what the report committed to |
| recorded row | the report is a row in the authenticated state, with its proof |
| document | the numbers match the bytes the ledger row holds |
| anchor | that state is one a signed checkpoint attests |
| agreed service time, downtime, availability, user-weighted availability, coverage | each recomputed from the readings and compared |
| objectives | each verdict reproduced, including an indeterminate one |
| declared outages | **no interval the readings show as down is missing from the report** |

The last row is the one to read twice. A supplier who edits a report to
hide an outage fails the signature and the arithmetic; a supplier who
swaps the evidence for a friendlier set fails the commitment and the
arithmetic in the other direction. Both are exercised in CI on every
push, in both directions, and the build fails if either tampered
document verifies.

## Audit and then prune

Readings are kept for the retention window and then removed by a signed
transaction that says so: a pruned interval reads as "pruned under this
policy", which is a different statement from "no such interval". The
folded intervals the arithmetic used stay.

Reclaiming the storage behind them is deliberately a second step, and it
refuses to run for a version no signed checkpoint covers:

1. `monitor-verify lineage` from the previous anchor.
2. Review what changed, if the agreement calls for it.
3. Issue and keep a checkpoint at the new state.
4. Reclaim the storage behind it.

The anchor stands in for the detail from then on. The audit cadence
therefore bounds how long removed data survives, which is the trade
being made and is worth stating to whoever asks.
