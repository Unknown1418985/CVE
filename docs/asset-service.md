# Asset Service

The Asset Service (`services/asset-service`, port `4004`, database `asset_service`) owns vendor
and product intelligence: the vendor and product catalog, CPE 2.3 names and other product
identifiers, CVE-to-product associations with affected version ranges, the product vulnerability
history, and vendor vulnerability analytics.

It never reads another service's database. CVEs are referenced by their stable CVE ID; what it
knows about them arrives through RabbitMQ events.

## Data flow

```
intelligence-service ── intelligence.cve-observation.recorded ──▶ ObservationApplier
                                                                    │ resolve products (CPE → purl → slugs → discover)
                                                                    │ reconcile associations per source item
                                                                    ▼
cve-service ── cve.record.created|updated|deleted ──▶ CveFactsProjector ──▶ cve_facts (local copy)
                                                                    │
REST API (/api/v1/vendors, /products, /cve-associations) ◀──────────┘
        │ writes
        ▼
outbox_events ──OutboxRelay──▶ asset.vendor.* · asset.product.* · asset.cve-association.*
```

## Data model

| Table                           | Content                                                                                      |
| ------------------------------- | -------------------------------------------------------------------------------------------- |
| `vendors`                       | Slug (stable identifier), name, description, website, origin, source, counters, version      |
| `products`                      | Vendor, slug (unique per vendor), name, type, origin, source, CVE counter, version           |
| `product_cpes`                  | CPE 2.3 names of a product, with parsed part/vendor/product/version; each name is unique     |
| `product_identifiers`           | Package URLs, SWID tag IDs, vendor SKUs, other; unique per (type, value)                     |
| `cve_product_associations`      | CVE ID × product × source item (source + sourceRecordId), status, first/last seen, withdrawn |
| `affected_version_ranges`       | Exact version or start/end bounds (inclusive or exclusive), status, matched CPE name         |
| `product_vulnerability_history` | Append-only timeline: `added`, `ranges-changed`, `withdrawn`, `restored` with ranges         |
| `observation_cursors`           | Last applied revision per intelligence source item (ordering and deduplication)              |
| `cve_facts`                     | Severity, CVSS score, KEV, EPSS, publication date per CVE, from `cve.record.*` events        |
| `processed_events`              | Inbox of handled event IDs per consumer (30-day retention, cleaned hourly)                   |
| `outbox_events`                 | Transactional outbox, published by `OutboxRelay`                                             |

- UUID primary keys, UTC `timestamptz(3)` timestamps, explicit indexes, unique constraints on
  external identifiers (vendor slug, (vendor, product slug), CPE name, (identifier type, value),
  (CVE, product, source, source record)).
- Hand-written SQL at the end of the init migration adds `CHECK` constraints (slug and CVE ID
  formats, score ranges, counters) and `pg_trgm` GIN indexes for name search. Keep them when
  generating later migrations.
- `vendors.product_count`, `vendors.cve_count` and `products.cve_count` are denormalised for
  sorting; they are recomputed in the same transaction as every change that affects them and count
  distinct CVEs with an active `affected` association.

### Provenance and history

- Every vendor, product, CPE name and identifier records its `source` (`manual` or the
  intelligence source that reported it) and `origin`: `curated` (entered by an analyst) or
  `discovered` (created from CVE data). Editing a discovered entry makes it curated.
- Associations are owned by one **source item**: `nvd`/`mitre-cve` with the CVE ID, or
  `github-advisory` with the GHSA ID, or `manual` with the CVE ID. Each observation replaces its
  item's set of associations; data from different sources is never merged or overwritten.
- Associations are never deleted when a source stops reporting them: `withdrawn_at` is set and a
  `withdrawn` history entry is written. If the source reports them again they are `restored`.
- The history entry stores the ranges after the change (before it, for `withdrawn`), so
  `GET /products/:id/vulnerability-history` shows what each source said and when.

## Product resolution

Affected-product entries in CVE observations are matched to catalog products in this order:

1. A registered CPE name with the same part, vendor and product (any version).
2. A registered Package URL. For GitHub advisories the ecosystem and package name are mapped to a
   purl (`npm` → `pkg:npm/…`, `pip` → `pkg:pypi/…` with PEP 503 normalisation, `maven`
   `group:artifact` → `pkg:maven/group/artifact`, `go`, `rubygems`, `composer`, `rust`, `nuget`,
   `erlang`, `pub`, `swift`, `actions`).
3. Vendor and product slugs derived from the names.
4. Otherwise a `discovered` vendor and/or product is created, with the product-level CPE name
   (`cpe:2.3:<part>:<vendor>:<product>:*:…`) and the purl registered when they are not taken.

Entries whose vendor is a placeholder (`n/a`, `unknown`, `-`, …) or whose names yield no slug are
skipped and counted in the processing log; they are not catalogued.

## Version ranges

A range is an exact `version`, or any combination of `versionStartIncluding|Excluding` and
`versionEndIncluding|Excluding`, with a status (`affected`, `unaffected`, `unknown`) and an optional
matched CPE name. A range without bounds covers every version; a CPE-only range uses the CPE's
version component.

`?version=` on `GET /products/:id/vulnerabilities` evaluates the ranges with a comparator that
handles dotted numbers, letters and pre-releases (`1.0-rc1` < `1.0` < `1.0.1`; `v` prefixes and
`+build` metadata ignored). Version schemes differ between vendors, so the comparator returns
"cannot tell" instead of guessing: such associations are listed with `versionAffected: null`
rather than hidden. The filter evaluates up to 20,000 associations per product in memory.

## Events

Consumed (both handlers are idempotent and order-aware; at-least-once delivery is safe):

| Event                                   | Queue                                    | Effect                                                   |
| --------------------------------------- | ---------------------------------------- | -------------------------------------------------------- |
| `intelligence.cve-observation.recorded` | `asset-service.cve-observation-products` | Resolves products and reconciles the item's associations |
| `cve.record.created/updated/deleted`    | `asset-service.cve-record-facts`         | Updates `cve_facts`; deletion leaves a tombstone         |

Older observation revisions are ignored (`observation_cursors`). CVE facts are ordered by record
version, and by event time when a CVE was deleted and created again (new record ID).

Published through the outbox (payload schemas in `packages/contracts/src/asset/events.ts`):

| Event                                                   | When                                                     |
| ------------------------------------------------------- | -------------------------------------------------------- |
| `asset.vendor.created` / `updated` / `deleted`          | Vendor changes (also discovered vendors)                 |
| `asset.product.created` / `updated` / `deleted`         | Product, CPE name and identifier changes                 |
| `asset.cve-association.added` / `updated` / `withdrawn` | Association added or restored, ranges changed, withdrawn |

Changes made by the service itself carry the actor `{ type: 'service', id: 'asset-service' }`.

## API

All routes are under `/api/v1`, require a Keycloak access token and are reachable through the
gateway. Reads need `asset:read` (every role), writes `asset:manage` (Security Analyst,
Administrator, Super Admin).

| Method | Path                                          | Description                                                                                                                                                                               |
| ------ | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/vendors`                                    | Search (`q`, `origin`), sort (`name`, `productCount`, `cveCount`, …)                                                                                                                      |
| POST   | `/vendors`                                    | Create; slug derived from the name if omitted; `409` on duplicates                                                                                                                        |
| GET    | `/vendors/:vendorId`                          | Vendor with `ETag`                                                                                                                                                                        |
| PATCH  | `/vendors/:vendorId`                          | Update name, description, website (`If-Match` optional)                                                                                                                                   |
| DELETE | `/vendors/:vendorId`                          | Delete; `409` while the vendor has products                                                                                                                                               |
| GET    | `/vendors/:vendorId/products`                 | The vendor's products                                                                                                                                                                     |
| GET    | `/vendors/:vendorId/analytics`                | Vulnerability analytics (`topProducts=1–50`)                                                                                                                                              |
| GET    | `/products`                                   | Search (`q`, `vendorId`, `vendor` slug, `type`, `origin`, `cpe`, `identifier`)                                                                                                            |
| POST   | `/products`                                   | Create with optional CPE names and identifiers                                                                                                                                            |
| GET    | `/products/:productId`                        | Product with CPE names and identifiers, `ETag`                                                                                                                                            |
| PATCH  | `/products/:productId`                        | Update name, type, description, website                                                                                                                                                   |
| DELETE | `/products/:productId`                        | Delete; `409` if it has CVE associations (history is kept)                                                                                                                                |
| POST   | `/products/:productId/cpes`                   | Register a CPE name (`201`, `200` if already registered, `409` if another product has it)                                                                                                 |
| DELETE | `/products/:productId/cpes/:cpeId`            | Remove a CPE name                                                                                                                                                                         |
| POST   | `/products/:productId/identifiers`            | Add a purl, SWID tag ID, vendor SKU or other identifier                                                                                                                                   |
| DELETE | `/products/:productId/identifiers/:id`        | Remove an identifier                                                                                                                                                                      |
| GET    | `/products/:productId/vulnerabilities`        | Associations with ranges and CVE facts; filters `source`, `status`, `severity`, `kev`, `includeWithdrawn`, `version`; sort `cveId`, `cvssScore`, `epssScore`, `firstSeenAt`, `lastSeenAt` |
| PUT    | `/products/:productId/vulnerabilities/:cveId` | Set the analyst-maintained (`manual`) association and its ranges                                                                                                                          |
| DELETE | `/products/:productId/vulnerabilities/:cveId` | Withdraw the manual association (source associations are untouched)                                                                                                                       |
| GET    | `/products/:productId/vulnerability-history`  | Timeline; filters `cveId`, `change`; `order`                                                                                                                                              |
| GET    | `/cve-associations`                           | Associations across the catalog, e.g. `?cveId=` for every product a CVE affects                                                                                                           |

Lists use the standard `{ data, meta }` pagination envelope; unknown query parameters and body
fields are rejected with `400`. Slugs are immutable stable identifiers.

### Vendor analytics

`GET /vendors/:vendorId/analytics` is computed on request in one `REPEATABLE READ` snapshot from
active `affected` associations: product and affected-product counts, distinct CVEs, counts by
severity, KEV count, average and maximum CVSS score, maximum EPSS score, CVEs per CVE-ID year,
CVEs per source, top products (by CVE count, then critical count) and first/last association
times. Severity, CVSS, KEV and EPSS come from `cve_facts`; CVEs the CVE Service has not reported
yet count as `unknown` and are reported in `cvesWithoutFacts`. No figure is estimated.

## Configuration

Besides the common service variables (`DATABASE_URL`, `RABBITMQ_URL`, `REDIS_URL`, `PORT`, …):

| Variable                         | Default        | Description                                    |
| -------------------------------- | -------------- | ---------------------------------------------- |
| `KEYCLOAK_URL`                   | required       | Internal Keycloak URL (JWKS)                   |
| `KEYCLOAK_PUBLIC_URL`            | required       | Public Keycloak URL (token issuer)             |
| `KEYCLOAK_REALM`                 | `cve-platform` |                                                |
| `KEYCLOAK_AUDIENCE`              | `cve-api`      |                                                |
| `OUTBOX_RELAY_ENABLED`           | `true`         | Publish outbox events (disabled only in tests) |
| `EVENT_CONSUMERS_ENABLED`        | `true`         | Consume events (disabled only in tests)        |
| `PROCESSED_EVENT_RETENTION_DAYS` | `30`           | How long handled event IDs are remembered      |

The `asset-service-migrate` Compose job applies the Prisma migrations before the service starts.

## Tests

```bash
pnpm --filter @cve/asset-service test              # unit + HTTP (auth, RBAC, validation)
pnpm --filter @cve/asset-service test:integration  # PostgreSQL: API, consumers, analytics
```

The integration suite needs PostgreSQL: either the Compose stack (`compose.dev.yaml` publishes
it; credentials from the root `.env`) or any server via `ASSET_SERVICE_TEST_DATABASE_URL`. It only
uses synthetic data (vendor slugs `zz_test…`, CVE IDs `CVE-2026-9xxxxx`) and deletes exactly that
data before each test.

## Not done yet

- The CVE Service does not consume `intelligence.*` events yet, so in a live stack `cve_facts`
  stays empty until it does (or until CVE records are written through its API); analytics then
  report those CVEs as `unknown` severity.
- Affected products entered manually in the CVE Service API are not forwarded to this service
  (its events carry no product list); use the manual association endpoint here instead.
- Merging duplicate products (e.g. a discovered product that duplicates a curated one) and vendor
  aliases are not implemented.
- The consumers were tested against PostgreSQL with synthetic events, not against a live RabbitMQ
  broker; topology and delivery are covered by the `@cve/messaging` tests.
