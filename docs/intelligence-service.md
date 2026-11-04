# Intelligence Service

The Intelligence Service collects vulnerability intelligence from external sources, keeps a
per-source copy of every observation with its history, and announces changes to the rest of the
platform through RabbitMQ events. It owns the `intelligence_service` database and never writes
to another service's database.

## Sources

| Source            | Key               | Endpoint (default)                                  | Auth                     | Incremental strategy                                                                          |
| ----------------- | ----------------- | --------------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------------------- |
| NVD CVE API 2.0   | `nvd`             | `services.nvd.nist.gov/rest/json/cves/2.0`          | optional `apiKey` header | `lastModStartDate`/`lastModEndDate` windows of at most 120 days, 5-minute overlap             |
| MITRE CVE List    | `mitre-cve`       | `cveawg.mitre.org/api` + CVEProject `deltaLog.json` | none                     | delta log (conditional GET with ETag), then one request per changed CVE record                |
| CISA KEV          | `cisa-kev`        | `cisa.gov/.../known_exploited_vulnerabilities.json` | none                     | conditional GET; the full snapshot is diffed against stored entries (adds, updates, removals) |
| FIRST EPSS        | `first-epss`      | `api.first.org/data/v1/epss`                        | none                     | latest score date is discovered, missing dates are backfilled (max 7 days), offset pagination |
| GitHub advisories | `github-advisory` | `api.github.com/advisories`                         | optional `Bearer` token  | `type=reviewed`, `sort=updated`, `updated>=cursor`, `Link` header pagination                  |

Every adapter is an async generator that yields batches. Each batch carries a checkpoint, so an
interrupted run continues where it stopped instead of starting over.

### Quotas and terms

The rate limits below are enforced client side by a sliding-window limiter per source. Server
signals are honoured too: `Retry-After` on 429/503 (and on 403 for GitHub), and GitHub's
`x-ratelimit-remaining`/`x-ratelimit-reset`, which pause the source until the quota resets.

| Source            | Client-side limit                                           | License / terms                                          |
| ----------------- | ----------------------------------------------------------- | -------------------------------------------------------- |
| NVD               | 5 requests / 30 s, 6 s spacing (with key: 50 / 30 s, 0.6 s) | Public domain in the US; NVD attribution notice required |
| MITRE CVE         | `MITRE_CVE_REQUESTS_PER_MINUTE` (120)                       | CVE Program terms of use, attribution required           |
| CISA KEV          | one request per run                                         | CC0 1.0                                                  |
| FIRST EPSS        | `EPSS_REQUESTS_PER_MINUTE` (60)                             | Free to use with attribution (FIRST EPSS user guide)     |
| GitHub advisories | 60 / hour (with token: 4 500 / hour, below GitHub's 5 000)  | CC BY 4.0, attribution required                          |

The terms were reviewed in November 2026 and are recorded in `src/sources/catalog.ts`. Each
source's attribution string is included in every event derived from it and returned by
`GET /api/v1/sources`. Raw payloads are stored only when `STORE_RAW_PAYLOADS=true` and the
source's terms permit it (all five do today).

## Data model

| Table                     | Purpose                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------ |
| `source_sync_states`      | One row per source: cursor, last success, lease (owner and expiry) that prevents concurrent runs |
| `sync_runs`               | Synchronisation history: trigger, status, timings, statistics, checkpoint, error, resumed run    |
| `sync_run_issues`         | Invalid upstream items and notices per run (at most 200 stored per run, all counted)             |
| `source_records`          | Latest normalised content per `(source, external_id)` with its SHA-256 content hash and revision |
| `source_record_revisions` | Every distinct revision of a record (history; tombstones for removals and withdrawals)           |
| `epss_scores`             | EPSS score and percentile per `(cve_id, score_date)`; kept `EPSS_RETENTION_DAYS`                 |
| `outbox_events`           | Transactional outbox drained by the RabbitMQ relay                                               |

Hand-written constraints at the end of the migration add CHECK constraints on statuses and
ranges and a partial unique index that allows only one `running` run per source.

**Duplicate detection.** Content is normalised (text cleaned, identifiers validated, timestamps
converted to UTC), serialised as canonical JSON and hashed with SHA-256. An unchanged hash
counts as `unchanged` and produces no revision and no event. EPSS rows are inserted with
`skipDuplicates`, so re-reading a date has no effect.

**Source-specific observations.** Nothing is merged across sources: NVD, MITRE and GitHub each
keep their own record and history for the same CVE, and MITRE keeps the CNA container apart from
ADP containers. Each event carries its provenance (source, record ID, URL, revision, content
hash, observation time, source modification time, run ID), so a consumer can keep each source's
metrics with their source and observation time as CLAUDE.md §6 requires.

## Synchronisation and recovery

- **Scheduling.** A BullMQ job scheduler `scheduled.<source>` runs each enabled source on its
  cron (`*_SYNC_CRON`, evaluated in UTC). A `maintenance` scheduler runs every five minutes.
- **Leases.** A run takes a lease on its source and renews it with a heartbeat. A scheduled run
  that finds the source busy is skipped; a manual run gets `409 Conflict`.
- **Retries.** HTTP requests retry with exponential backoff and full jitter
  (`SOURCE_HTTP_MAX_ATTEMPTS`). A failed job is retried by BullMQ (`SYNC_JOB_ATTEMPTS`) with
  exponential backoff. Each attempt is a new run that resumes from the previous run's checkpoint.
  Non-retryable failures (for example a 4xx response, or a KEV snapshot that would remove more
  than max(10, 5 %) of the catalog) fail permanently without retries.
- **Failed job recovery.** Maintenance marks runs without a heartbeat for
  `SYNC_STALE_RUN_AFTER_MS` as `abandoned`, publishes `intelligence.sync-run.failed` for them and
  enqueues a `recovery` job that resumes from their checkpoint. Checkpoints older than
  `SYNC_RESUME_WINDOW_HOURS` are not resumed; the run starts from the stored cursor instead.
  Maintenance also purges old EPSS scores and published outbox rows (`OUTBOX_RETENTION_DAYS`).
- **Timeouts.** Each request has `SOURCE_HTTP_TIMEOUT_MS`; each run has `SYNC_JOB_TIMEOUT_MS`.

### Outbound HTTP safety

All upstream calls go through `SourceHttpClient`: an allowlist of the configured source hosts
(redirects are followed manually and re-checked, pagination links outside the allowlist are
refused), response size limits, content-type checks, timeouts, and credentials only in headers.
Logged URLs never include query secrets. Production requires `https` for every source URL.

## Events

Published through the outbox to the `cve.events` exchange (see [messaging.md](messaging.md)).
Payload schemas live in `@cve/contracts` (`packages/contracts/src/intelligence/events.ts`).

| Type                                    | When                                                                      |
| --------------------------------------- | ------------------------------------------------------------------------- |
| `intelligence.cve-observation.recorded` | A CVE record from NVD, MITRE or GitHub was created, changed or withdrawn  |
| `intelligence.kev-entry.added`          | A CVE was added to (or returned to) the KEV catalog                       |
| `intelligence.kev-entry.updated`        | A KEV entry changed                                                       |
| `intelligence.kev-entry.removed`        | A CVE disappeared from the KEV catalog                                    |
| `intelligence.epss-scores.published`    | New EPSS scores for a date (at most 1 000 scores per event)               |
| `intelligence.sync-run.completed`       | A run finished successfully, with statistics                              |
| `intelligence.sync-run.failed`          | A run failed or was abandoned; `willRetry` says whether BullMQ retries it |

Large CVE content is truncated to the contract limits; `truncated: true` tells the consumer to
fetch the full record from the source if needed.

## API

All routes are under `/api/v1` and are also exposed through the API Gateway.

| Method | Path                      | Permission           | Description                                                                                         |
| ------ | ------------------------- | -------------------- | --------------------------------------------------------------------------------------------------- |
| GET    | `/sources`                | `data-source:read`   | Status, cursor, last run, terms and attribution of every source                                     |
| GET    | `/sources/:source`        | `data-source:read`   | One source                                                                                          |
| POST   | `/sources/:source/sync`   | `data-source:manage` | Queue a manual run (`202`); `{ "fresh": true }` ignores checkpoints; `Idempotency-Key` deduplicates |
| GET    | `/sync-runs`              | `data-source:read`   | Paginated history, filters `source`, `status`, `trigger`                                            |
| GET    | `/sync-runs/:runId`       | `data-source:read`   | One run with its stored issues                                                                      |
| POST   | `/sync-runs/:runId/retry` | `data-source:manage` | Retry the latest failed run of a source from its checkpoint; `409` otherwise                        |

## Configuration

Beyond the common service variables (`DATABASE_URL`, `RABBITMQ_URL`, `REDIS_URL`, Keycloak):

| Variable                                               | Default              | Notes                                                                                               |
| ------------------------------------------------------ | -------------------- | --------------------------------------------------------------------------------------------------- |
| `NVD_API_KEY`                                          | unset                | Optional secret; raises the NVD quota                                                               |
| `GITHUB_TOKEN`                                         | unset                | Optional fine-grained token with no permissions                                                     |
| `<SOURCE>_ENABLED`                                     | `true`               | `NVD`, `MITRE_CVE`, `CISA_KEV`, `EPSS`, `GITHUB_ADVISORY`                                           |
| `<SOURCE>_SYNC_CRON`                                   | per source           | NVD `15 */2 * * *`, MITRE `5 * * * *`, KEV `30 */4 * * *`, EPSS `45 */6 * * *`, GitHub `20 * * * *` |
| `NVD_INITIAL_SYNC_FROM`                                | unset (full catalog) | First NVD run only                                                                                  |
| `MITRE_CVE_INITIAL_LOOKBACK_HOURS`                     | `24`                 | The delta log covers about 30 days                                                                  |
| `GITHUB_ADVISORY_INITIAL_LOOKBACK_DAYS`                | `30`                 |                                                                                                     |
| `EPSS_MAX_BACKFILL_DAYS` / `EPSS_RETENTION_DAYS`       | `7` / `30`           |                                                                                                     |
| `SOURCE_HTTP_TIMEOUT_MS` / `SOURCE_HTTP_MAX_ATTEMPTS`  | `60000` / `4`        |                                                                                                     |
| `SYNC_JOB_TIMEOUT_MS` / `SYNC_JOB_ATTEMPTS`            | 3 h / `4`            |                                                                                                     |
| `SYNC_STALE_RUN_AFTER_MS` / `SYNC_RESUME_WINDOW_HOURS` | 10 min / `24`        |                                                                                                     |
| `STORE_RAW_PAYLOADS`                                   | `true`               |                                                                                                     |

The full schema is `src/config/env.ts`. Secrets are read from the environment only and are
never logged or returned by the API.

## Testing

- `pnpm --filter @cve/intelligence-service test` runs adapter, HTTP client, engine, API and
  configuration tests. Upstream APIs are simulated by a local HTTP server (`test/mock-source.ts`)
  serving recorded-shape fixtures with synthetic identifiers; no test reaches the internet.
- `pnpm --filter @cve/intelligence-service test:integration` runs the Prisma repository and the
  BullMQ scheduler against real PostgreSQL and Redis. Set
  `INTELLIGENCE_SERVICE_TEST_DATABASE_URL` and `INTELLIGENCE_SERVICE_TEST_REDIS_URL`; the suite
  refuses to truncate a database that contains non-test data.

## Not implemented yet

- The CVE Service does not consume these events yet, so CVE records, KEV status and EPSS scores
  are not shown in the CVE Service until a consumer is added.
- Exploit-DB is listed in CLAUDE.md §5 but was not part of this phase.
- The adapters were tested against mocked responses only; they have not been run against the
  live APIs from this environment.
