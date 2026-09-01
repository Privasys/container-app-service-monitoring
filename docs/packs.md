# Service models

A pack is a whole watched service written down: the service, its agreed
service time, its components, the journeys that exercise them, the
objectives they are held to, and the credentials they will ask for.

It exists so that bringing a monitor up is one configuration step rather
than a dozen API calls, and so the end-to-end suite drives the same path
a customer does. What lands in the ledger is the resolved service model,
as ordinary signed transactions: the pack is how the model arrived, not
a second place the model lives.

Packs are baked into the image under `/packs` and named at configure
time with `pack_ref`, or delivered inline as `pack`. The reference is
[`packs/example-saas`](../packs/example-saas), which watches the
stand-in service in [`tools/target`](../tools/target).

## The document

```jsonc
{
  "name": "example-saas",
  "version": "1.0.0",

  "service": {
    "name": "Example SaaS",
    "timezone": "Europe/London",
    "visibility": "public",           // or "private"
    "maintenance_lead_time": 86400,   // notice needed to exclude a window
    "coverage_floor_ppm": 990000      // below this, objectives are indeterminate
  },

  "schedule": {                       // omit for 24x7
    "name": "Business hours",
    "timezone": "Europe/London",
    "windows": [
      { "weekday": 1, "start_min": 540, "end_min": 1020 }
    ],
    "exceptions": [
      { "date": "2026-12-25", "include": false, "reason": "Christmas Day" }
    ]
  },

  "components": [
    { "ref": "api", "name": "Order API", "user_weight": 4000, "rollup": "any" }
  ],

  "secrets": [
    { "name": "example_password", "hosts": ["api.example.com"],
      "description": "The dedicated least-privilege account" }
  ],

  "monitors": [ /* see below */ ],
  "objectives": [ /* see below */ ]
}
```

`weekday` is 0 for Sunday through 6 for Saturday; minutes are from local
midnight, and a window ending at 1440 runs to midnight. An exception
with `include: false` removes a date's recurring windows; one with
`include: true` adds a window to that date.

`rollup` decides when a component is down given its monitors: `any` (the
default), `all` or `majority`.

`secrets` declares what the journeys will ask for, so an operator is
told what to supply rather than discovering it from a failing journey.
Values never appear in a pack.

## A journey

```jsonc
{
  "name": "Place and read an order",
  "component": "api",
  "interval_seconds": 30,
  "timeout_seconds": 20,
  "failure_threshold": 2,      // consecutive failures before it is down
  "recovery_threshold": 2,     // consecutive passes before it is up again
  "latency_budget_ms": 2000,   // over budget is degraded, not down
  "steps": [
    {
      "name": "log in",
      "kind": "http",
      "method": "POST",
      "url": "https://api.example.com/login",
      "headers": { "Content-Type": "application/json" },
      "body": "{\"user\":\"{{ secrets.user }}\",\"password\":\"{{ secrets.password }}\"}",
      "expect_status": [200],
      "extractions": [
        { "var": "token", "source": "json", "target": "token", "secret": true }
      ]
    },
    {
      "name": "place an order",
      "kind": "http",
      "method": "POST",
      "url": "https://api.example.com/orders",
      "headers": { "Authorization": "Bearer {{ vars.token }}" },
      "body": "{\"reference\":\"check-{{ gen.uuid }}\"}",
      "expect_status": [201],
      "assertions": [
        { "source": "json", "target": "status", "op": "eq", "value": "accepted",
          "message": "the order was not accepted" }
      ],
      "extractions": [
        { "var": "order_id", "source": "json", "target": "id" }
      ]
    },
    {
      "name": "read it back",
      "kind": "http",
      "method": "GET",
      "url": "https://api.example.com/orders/{{ vars.order_id }}",
      "headers": { "Authorization": "Bearer {{ vars.token }}" },
      "expect_status": [200],
      "assertions": [
        { "source": "json", "target": "id", "op": "eq", "value": "{{ vars.order_id }}",
          "message": "the order read back is not the order placed" }
      ]
    },
    {
      "name": "remove it",
      "kind": "http",
      "cleanup": true,
      "method": "DELETE",
      "url": "https://api.example.com/orders/{{ vars.order_id }}",
      "headers": { "Authorization": "Bearer {{ vars.token }}" },
      "expect_status": [204, 404]
    }
  ]
}
```

### Steps

`http`, `assert`, `extract` and `sleep`. A `cleanup` step runs whether
or not an earlier step failed, so a monitor that creates an order
deletes it again; a failing cleanup step is reported and does not, on
its own, mark the service down.

### Templating

| Namespace | Meaning |
| --- | --- |
| `{{ vars.x }}` | a value an earlier step extracted |
| `{{ secrets.x }}` | a credential, resolved against its host binding |
| `{{ gen.uuid }}`, `gen.hex`, `gen.timestamp`, `gen.iso8601` | a generated value, for test data that does not collide with the last run's |

**A credential may not appear in a URL.** A URL travels through proxies,
caches and the watched service's own access log; a query string is the
single most common way a credential escapes. Put it in a header or the
body. An assertion may not reference one either, because a failure
message ends up in an incident timeline a customer reads.

### Assertions

`source` is `status`, `latency_ms`, `header`, `body`, `json` or `var`;
`op` is `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `contains`, `matches`,
`exists` or `absent`. A `json` target is a dotted path with bracket
indices, `data.items[0].id`. That is a deliberate subset of JSONPath:
filters and wildcards let an assertion mean something a reader has to
work out, and an assertion nobody can read is no use in the argument the
report is written for.

`message` is what the reading records when the assertion fails. Write it
as what the assertion means to the business, not what it compares.

### Extractions

Bind a value out of a response into a variable. Mark one `secret: true`
and it is redacted for the rest of the journey exactly like a configured
credential, which is what a session token wants.

## Objectives

```jsonc
{
  "name": "Monthly availability",
  "metric": "availability",          // or user_availability, latency_p95
  "target_ppm": 999000,              // 99.9%
  "window": "calendar_month",
  "latency_budget_ms": 2000,         // for latency_p95
  "credits": [
    { "below_ppm": 999000, "credit_percent": 10 },
    { "below_ppm": 990000, "credit_percent": 25 }
  ]
}
```

See [availability.md](availability.md) for what each metric means and
when an objective is reported as indeterminate.

## Writing one

Start from `example-saas` and change the URLs. Three things are worth
getting right before anything else:

**Script what the agreement is about.** If the agreement is about
placing orders, the journey places an order. A journey that only fetches
a health endpoint measures the health endpoint.

**Give the account the least privilege that lets the journey work,** and
bind its credential to the host it belongs to. The enclave removes the
reason to withhold a working account; it does not remove the reason to
scope it.

**Clean up.** A monitor running every thirty seconds for a year is a
million orders if nothing deletes them.
