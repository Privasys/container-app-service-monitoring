# Architecture

One process, one sealed volume, one authenticated record. Everything the
service knows is a row in that record, and every change to it is a
signed transaction.

## The shape of it

```
                     ┌──────────────────────────────────────────┐
   customer's        │  confidential VM (enclave-os-virtual)    │
   service           │                                          │
      ▲              │   ┌────────────┐    ┌─────────────────┐  │
      │  journeys    │   │ scheduler  │───▶│ journey engine  │  │
      └──────────────┼───│  (probe)   │    │ credentials +   │  │
                     │   └────────────┘    │ egress rules    │  │
                     │         │           └─────────────────┘  │
                     │         ▼                                │
   status page  ◀────┼──  ┌─────────┐   ┌──────────────────┐    │
   explorer     ◀────┼──  │  core   │──▶│ immutable-ledger │    │
   REST + tools ◀────┼──  │         │   │  + sqlledger     │    │
                     │    └─────────┘   └──────────────────┘    │
   callback     ◀────┼──  signed alerts        │                │
                     │                    /data (LUKS2)         │
                     └──────────────────────────────────────────┘
```

## Boot order, and why it is that order

The sealed volume is opened first, because the signing key and the
credentials live there and nothing can be attested without them. The
record is opened next, and the configuration a previous boot wrote is
restored from it. Then the process lifts the platform's configure gate
for itself and republishes its attested extensions. Only then does it
write the boot down, including the gap since the last one.

That last step is not bookkeeping. Coverage is reported beside
availability precisely so a monitor that was not running cannot certify
uptime, and a gap in the readings is otherwise indistinguishable from a
quiet period.

## Storage

[`immutable-ledger`](https://github.com/Privasys/immutable-ledger) with
the history chain enabled, over Pebble, on the LUKS2 volume.

- Every row is a ledger entry, so one 32-byte root attests the whole
  record and any row can be returned with an inclusion proof.
- The SQL layer is embedded with no network listener: the application is
  the only policy boundary in front of its data.
- The history chain writes one reserved leaf per commit whose value
  binds the previous head and root, so the live root commits to the
  entire root lineage. Rewriting history between two anchors and staying
  consistent with the current head is a preimage attack.
- The commitment key is derived from the sealed master secret. Deriving
  rather than delivering removes a class of "the monitor came back but
  cannot open its own record" failures on an unattended restart; the
  volume is the confidentiality boundary either way.

Checkpoints are the one thing that does not live in the tree, and
cannot: a checkpoint states the root at a version, and writing it as a
row would advance the version past the one it states. They live beside
the ledger in their own keyspace, and the chain carries its own
integrity by naming its predecessor.

## Transactions

Every state change goes through one function. It validates the envelope,
writes the transaction row ahead of its effects, applies them, and
commits, all inside one SQL transaction, so the whole action is a single
ledger commit and adds exactly one link to the lineage chain.

The envelope is the git-style commit message: kind, tenant, service,
author (subject, display name, acting role), timestamp, a required
message under 72 characters, and typed links to earlier work. The
envelope and the write set are hashed together into the transaction id,
so a change and the reason for it are one object and neither can be
substituted.

A tick of the scheduler writes all of that tick's readings as one
transaction. At two hundred monitors on a thirty second interval that is
about seven readings per commit and one commit per second, comfortably
inside what the ledger sustains, and it keeps the version count
proportional to time rather than to how many things are watched.

## The journey engine

A journey is an ordered list of steps executed under one timeout, with
cleanup steps that run whether or not the rest succeeded.

Templating has three namespaces and no expressions: `vars.x` for values
extracted earlier, `secrets.x` for credentials, `gen.x` for a generated
uuid or timestamp. A monitoring journey that needs a programming
language is a journey nobody can read in a dispute, and every construct
added there is one more way for a credential to end up somewhere it was
not meant to go.

The engine draws one distinction the rest of the system depends on. A
failure of the watched service is downtime; a failure of the monitor
itself is an error, and is charged to coverage instead.

## Credentials

A credential is encrypted under a per-entry key held in a keyring that
is itself encrypted under a key derived from the sealed master secret.
It is bound at creation to a host or subtree, and the vault refuses to
hand it over for a request anywhere else, so the rule is enforced below
the caller rather than by it.

Redaction happens on the way out. Every secret value used in a journey
is registered with a redactor, captures pass through it before they can
be stored, and the engine then asserts its own output no longer contains
any of them. A leak turns the reading into an error with no captures
rather than writing a credential into the record.

## Egress

The enclave runtime does not filter outbound traffic today, so the
application does. The allowlist is rebuilt from the monitor definitions
and the declared callbacks, both of which are signed transactions, and a
request to anything else is refused in the dialler and recorded.
Redirects are refused unless a step opts in, and every hop is checked.

This is app-enforced, not kernel-enforced, and the docs say so.

## The HTTP surface

- **Public**, no token: the status page, the Statuspage-shaped JSON, the
  Atom feed, the well-known document with the signing key, and the
  evidence endpoint behind the uptime bars. A status page behind a login
  is not a status page.
- **Authenticated**: the REST API and the manifest's tools, resolved
  against the built-in role model from the identity provider's token.
- **Configure**: gated by the runtime to the app's owners and admins, at
  enclave level, so the application cannot omit the check.

The status page and the explorer are served from inside the measured
image. A vanity domain in front of this is a redirect, never a proxy:
the point is that the page a reader runs comes from the build whose
measurement is in the certificate.

## Attested extensions

| OID | Value |
| --- | --- |
| `1.3.6.1.4.1.65230.3.2` | the workload image digest, measured by the platform |
| `1.3.6.1.4.1.65230.3.5.1` | SHA-256 of the report signing public key |
| `1.3.6.1.4.1.65230.3.5.2` | the live ledger root |

They live in the manager's memory rather than on the volume, so they are
republished at every boot and after every configure.

## What is deliberately not here

- **Quorum across vantage points.** Designed for (every reading records
  the vantage it came from) and not built. One instance cannot
  distinguish a failure of the watched service from a failure of the
  path to it, and this build says so rather than implying otherwise.
- **A wire protocol into the SQL layer.** The application is the policy
  boundary; a listener would put one somewhere else.

## The browser leg

A monitor with `engine: browser` does not drive a page itself. It sends
the journey to
[container-app-browser](https://github.com/Privasys/container-app-browser),
a renderer in its own enclave with its own measurement, no vault and no
volume, and gets back what the page did: per-step outcomes, the
document's rendered text, screenshots where the journey asked for them,
console errors and the subresources that failed to load.

The split is not tidiness. A journey renders whatever the watched
service returns, which on a bad day is whatever an attacker put there,
and Chromium is a large attack surface to put beside a credential vault
and an availability record. Keeping it in a separate enclave means a
compromised page has nothing to find.

What crosses the gap is one request carrying resolved values and one
response carrying observations. Before that request is sent, the
renderer's certificate is checked for the workload image digest the
owner pinned at OID `1.3.6.1.4.1.65230.3.2`, so the question "which
build am I handing this credential to" is answered by a hardware quote
rather than by a hostname. The renderer, for its part, requires a shared
token: attestation says which build is on one end, the token says which
caller is on the other.

This is deterministic attestation. The quote binds a certificate that is
renewed daily, so what it establishes is that the key was generated
inside a genuine enclave running that measurement within the renewal
window. Challenge-response freshness needs a nonce in the ClientHello
and a TLS stack that carries one; that is a later upgrade, and the docs
say so rather than implying more.

**The judging stays here.** The renderer reports; this service decides.
Every visual judgement is arithmetic over the returned image: how much
of it is not background, and how many bits of a perceptual hash differ
from an approved baseline. Both are integers, both are re-derivable by
anyone holding the image, and neither needs the renderer to be trusted
about anything except what it saw. That is what keeps a report
recomputable, and it is why no model is asked whether a page looks
right.
