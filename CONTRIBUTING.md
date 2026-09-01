# Contributing

Thank you for your interest in the Privasys service monitor.

## Layout

A single Go module with two commands and a set of internal packages,
plus the service models that turn the generic core into a particular
monitor.

| Path | Purpose |
| --- | --- |
| [`cmd/monitor`](cmd/monitor) | The service: HTTP surface, configure gate, scheduler, alert delivery. |
| [`cmd/monitor-verify`](cmd/monitor-verify) | The customer-side verifier. Checks evidence bundles, checkpoint chains, the lineage fold and whole reports offline, with no access to the monitor. |
| [`internal/core`](internal/core) | The core: transactions, the service model, readings and rollups, detection, incidents, maintenance, reports, anchors, retention. |
| [`internal/availability`](internal/availability) | The arithmetic, as a pure package: agreed service time, exclusions, coverage, objectives. The service and the verifier both call it, which is what makes a report a computation rather than a claim. |
| [`internal/journey`](internal/journey) | Step execution, templating, assertions, and the outbound allowlist. |
| [`internal/secrets`](internal/secrets) | The sealed credential store, the host binding, and the redactor. |
| [`internal/store`](internal/store) | The binding to [immutable-ledger](https://github.com/Privasys/immutable-ledger): the authenticated store, the SQL layer over it, and the statement builder. |
| [`internal/checkpoint`](internal/checkpoint) | Signing and offline verification, shared by the service and the verifier. |
| [`internal/api`](internal/api) | REST surface, tool endpoints, the public status page and the operator explorer. |
| [`internal/pack`](internal/pack) | Loads and validates a service model. |
| [`packs/`](packs) | Service models. `example-saas` is the reference the core is proved against. |
| [`tools/target`](tools/target) | A stand-in service with a login and a resource lifecycle, so the tests watch something real and can make it fail. |
| [`tools/browser-verify.mjs`](tools/browser-verify.mjs) | Runs the page's in-browser verifier outside a browser, so it cannot silently drift from the Go one. |
| [`e2e/`](e2e) | Playwright tests that drive the status page and the explorer in real browsers against a real monitor. |

## Building and testing

```bash
git clone https://github.com/Privasys/container-app-service-monitoring.git
cd container-app-service-monitoring
go build ./...
go test ./...
```

Running it locally, watching the stand-in service:

```bash
go run ./tools/target &
PORT=8080 MONITOR_DATA_DIR=./.data \
  MONITOR_DEV_AUTH=1 MONITOR_SELF_CONFIGURE=1 MONITOR_PACK=example-saas \
  MONITOR_ROLLUP_LAG=5s \
  go run ./cmd/monitor
```

Then deliver the credentials the reference journey logs in with:

```bash
AUTH='Authorization: Bearer dev:you:You:monitoring:owner'
curl -H "$AUTH" -X POST localhost:8080/api/v1/secrets -H 'Content-Type: application/json' \
  -d '{"name":"example_user","value":"monitor","hosts":["127.0.0.1"],"message":"Store the account"}'
curl -H "$AUTH" -X POST localhost:8080/api/v1/secrets -H 'Content-Type: application/json' \
  -d '{"name":"example_password","value":"correct horse battery staple","hosts":["127.0.0.1"],"message":"Store the password"}'
```

The status page is at `/status` and the explorer at `/explorer`.
Development tokens are `dev:<sub>:<display>:<idp roles>`; the roles keep
their colons, so `dev:you:You:monitoring:owner` is an owner. Development
authentication and self-configuration are both refused when the platform
callback credentials are present, so neither can be switched on by
accident inside an enclave.

The browser suite:

```bash
cd e2e
npm ci
npx playwright install chromium firefox
npm test
```

## What a change should come with

**A test that would have failed before it.** The arithmetic and the
credential handling are the two places where a plausible implementation
gives a wrong answer quietly, so both have tests that assert on the
uncomfortable cases: a clock change, a window declared after the event,
a period nobody was watching, a credential pointed at a second host.

**A message saying why.** Commit messages follow git conventions: a
summary line under 72 characters, imperative mood, no full stop, and a
body when the reason is not obvious from the diff. The service enforces
the same rule on its own transactions, so it would be odd to hold the
repository to a lower standard.

**Comments that explain the reason, not the mechanism.** The code says
what it does. A comment earns its place by saying why it is that way:
which failure it prevents, which alternative was rejected, which
guarantee depends on it.

## Things to be careful with

- **The arithmetic is shared with the verifier.** `internal/availability`
  is pure by design: no clock, no store, no network. A change that gives
  it any of those makes a report unverifiable offline.
- **Redaction happens on the way out.** Credentials are removed by the
  writer that produces a capture, not by a scrubber applied afterwards.
  A new path that stores text from a watched service must go through the
  same redactor and the same leak check.
- **The signature covers the document with the signature field blanked,
  not removed.** The browser verifier and the Go one must agree byte for
  byte; `tools/browser-verify.mjs` runs in CI so they cannot drift.
- **Byte columns go into a write set as `model.Binary`.** A plain
  `[]byte` becomes a bare base64 string on the JSON round trip and comes
  back indistinguishable from text.
- **The SQL layer has no DECIMAL, JSON, ENUM, foreign keys or column
  defaults**, and every table needs a primary key. Ratios are integers
  in parts per million throughout: a contractual threshold is the last
  place to accept binary floating point rounding.

## Licence

By contributing you agree that your contributions are licensed under the
AGPL-3.0.
