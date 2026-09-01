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

## Browser journeys

Some services are only exercised the way a customer exercises them: a
form that runs on submit, a dashboard that assembles itself after the
document loads, a checkout that is three scripts and a redirect. An HTTP
journey proves the API answered. A browser journey proves the page
worked.

It costs more, so it is a choice rather than the default, and it runs
somewhere else: the attested renderer
([container-app-browser](https://github.com/Privasys/container-app-browser)),
in its own enclave, with no vault and no volume. A journey renders
whatever the watched service returns, which on a bad day is whatever an
attacker put there, and the process holding the credentials and the
availability record should not be the process parsing it.

Point the monitor at one at configure time:

```bash
privasys apps configure <app-id> \
  --set renderer_url=https://browser.apps.privasys.org \
  --set renderer_token="$(head -c 32 /dev/urandom | base64)" \
  --set renderer_digest=sha256:…
```

The digest is what makes it safe. The credential is handed over only
after the renderer's certificate has been checked against it, so which
build receives it is answered by a hardware quote rather than by a
hostname. Without a renderer configured, a browser journey is refused
rather than quietly downgraded to fetching the HTML.

```jsonc
{
  "name": "Place an order in the browser",
  "component": "checkout",
  "engine": "browser",
  "interval_seconds": 300,
  "timeout_seconds": 90,
  "viewport": { "width": 1280, "height": 800 },
  "steps": [
    { "name": "open",     "kind": "goto",  "url": "https://app.example.com/login" },
    { "name": "wait",     "kind": "wait",  "selector": "#email", "wait_visible": true },
    { "name": "email",    "kind": "fill",  "selector": "#email",    "value": "{{ secrets.example_user }}" },
    { "name": "password", "kind": "fill",  "selector": "#password", "value": "{{ secrets.example_password }}" },
    { "name": "sign in",  "kind": "click", "selector": "button[type=submit]" },
    { "name": "order",    "kind": "click", "selector": "#place-order" },
    {
      "name": "read it", "kind": "read", "capture": true,
      "assertions": [
        { "source": "body",    "op": "contains", "value": "Total: 42.00 GBP" },
        { "source": "console", "op": "absent",
          "message": "the page reported an error to its own console" }
      ]
    },
    {
      "name": "photograph it", "kind": "screenshot",
      "screenshot": {
        "min_ink_ppm": 5000,
        "max_distance": 8,
        "store": "on_fault",
        "masks": [ { "x": 0, "y": 0, "w": 1280, "h": 60 } ]
      }
    }
  ]
}
```

Step kinds are `goto`, `click`, `fill`, `press`, `wait`, `sleep`, `read`,
`screenshot` and `eval`. Credentials go into `fill` values, and the same
rule as everywhere else holds: never into a URL, and never into a
comparison, because a failure message ends up in an incident timeline a
customer reads. The host binding still applies, resolved against
whatever the last navigation set, so a journey that navigates elsewhere
and then types a password is refused at the fill.

### What a screenshot is checked against

Two tests, both arithmetic over pixels, and both re-derivable by anyone
holding the image.

**`min_ink_ppm`** is how much of the picture must not be the background
colour. It is the check that catches a white screen of death behind an
HTTP 200, a stylesheet that failed to load, or a page that rendered a
spinner and gave up, and it is worth more than every cleverer check
after it. The default floor is 5000 parts per million, which is well
under a page of ordinary text and well over an empty one.

**`max_distance`** compares a 64-bit perceptual hash against a baseline
somebody approved. Anti-aliasing and a changed number move a couple of
bits; a redesign, a consent wall or a blank page move dozens. Mask the
regions that legitimately change (a clock, a carousel, a "last updated"
line) or the baseline fails every minute and teaches everyone to ignore
it.

`store` decides whether the image is kept on the sealed volume:
`on_fault` (the default) keeps it when something went wrong or the page
changed, `always` keeps every one, `never` keeps none. The digest, the
hash and the ink measurement go into the record either way, so a reading
always says what was seen even when the picture is gone.

### Approving a baseline

```bash
privasys apps action <app-id> approve_baseline \
  --arg monitor=<monitor-id> --arg step="photograph it" \
  --arg message="Adopt the new checkout layout"
```

That publishes a new monitor version, so the baseline carries an author,
a timestamp and a reason. Moving the bar after a failure is a
transaction in the log sitting next to the failure it excuses, which is
the property that makes a visual check worth having at all.

### Text a page draws rather than writes

Set `"viewport": { "ocr": true }` and the renderer also recognises text
in each screenshot, available to assertions as the `ocr` source. It
costs about a tenth of a second and is only worth it for a canvas, a
chart, or an error baked into an image. Everywhere else the document's
own text is exact, free, and available as the `body` source.

The recogniser is a fixed version inside the renderer's measured image,
so the same screenshot yields the same text and the result can be
re-derived by anyone holding that image.

### Why no model looks at the screenshot

It would be the obvious next step, and it is deliberately not taken. A
report's whole claim is that its numbers recompute from the evidence it
carries. A model's judgement does not recompute: the same picture and
the same prompt need not give the same answer, and bitwise-reproducible
inference costs an order of magnitude in throughput. An availability
figure resting on one would be a figure nobody can check, which is the
thing this product exists to replace.

A model is useful on the other side of that line: explaining to a person
why two pictures differ, or triaging a change nobody expected. That is
worth building, and it is worth keeping out of the arithmetic.
