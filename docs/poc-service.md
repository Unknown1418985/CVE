# PoC Service

The PoC Service (Phase 5) discovers public proof-of-concept (PoC) repositories, records their
metadata and links them to CVEs with a confidence score. It stores **metadata only**: repository
facts, the head commit, and the file listing (paths, modes, blob IDs and sizes). It never fetches
file contents, archives or clones, and nothing it receives is executed, extracted or rendered as
HTML. Downloading artifacts into MinIO is the [Download Service](download-service.md)'s job.

Package `@cve/poc-service`, port `4005`, database `poc_service` (role `poc_service`).

## Data flow

```
cve.record.*  ─────────────► CveTracker ──► tracked_cves ──(sweep, every 10 min)──┐
intelligence.cve-observation.recorded ─► ReferenceCollector ──► poc_references     │
                                                   │ unknown GitHub repos          ▼
                                                   └──────────► poc-inspection   poc-discovery
                                                                 (BullMQ)        (BullMQ)
                                                                     │               │
                                     GitHub REST API (metadata) ◄────┴───────────────┘
                                                                     │
                            poc_repositories, repository_owners, repository_commits,
                            poc_artifacts, artifact_files, poc_cve_associations
                                                                     │
                                                           outbox ──► poc.* events
```

- **Tracked CVEs.** `cve.record.created|updated|deleted` are projected into `tracked_cves`.
  Published CVEs are searched as soon as they are known and again when they enter the KEV
  catalog; later scans are spaced by importance (KEV or EPSS ≥ 0.1 daily, CVEs published in the
  last 30 days every 2 days, in the last year every 14 days, older ones every 60 days). Rejected or deleted CVEs are not searched.
- **CVE search.** The sweep job leases due CVEs (`FOR UPDATE SKIP LOCKED`, so replicas never pick
  the same CVE) and queues one `poc-discovery` job per CVE. The job searches GitHub repositories
  for `"CVE-…" in:name,description,topics,readme` (configurable), up to 3 pages of 100.
- **Recent sweep.** Every 30 minutes a job searches repositories mentioning `CVE` that were pushed
  since the last cursor (`connector_states`), in windows of one hour that are halved when GitHub
  reports more than 1 000 results (its per-query limit).
- **References.** CVE references published by the Intelligence Service that point to GitHub
  repositories, gists, Exploit-DB or Packet Storm, or are tagged as exploits, are stored as PoC
  references. A reference to a known repository rescores it; an unknown GitHub repository is
  looked up by a job.
- **Inspection.** A new or changed repository (its `pushed_at` moved) gets a `poc-inspection` job:
  it re-reads the metadata by stable repository ID (follows renames), reads the head commit of the
  default branch and, for a tree the repository has not had before, the recursive tree listing.

Every network call happens outside database transactions; every write about one repository
(metadata, associations, artifacts and their events) is one transaction with its outbox rows.

## Untrusted input

Repository names, descriptions, topics and paths are written by anyone. The service:

- validates every payload with zod and refuses private repositories, invalid logins or names and a
  `full_name` that does not match the owner and name;
- builds the canonical URL (`https://github.com/<owner>/<name>`) itself instead of trusting
  `html_url`; a database CHECK constraint enforces the prefix;
- strips control, bidirectional and zero-width characters and truncates text; the API marks
  descriptions as untrusted plain text (the UI must not render them as HTML or Markdown);
- never uses a path from a repository as a filesystem path or object key;
- only talks to the configured GitHub API origin: pagination links and redirects to other origins
  or other endpoints are refused (`@cve/source-http`).

A description is never enough for an association on its own: see the scoring below.

## Confidence scoring

Each (repository, CVE) pair is scored from evidence the service extracts itself
(`src/domain/scoring.ts`, `SCORING_VERSION = 1`):

| Signal                  | Weight | Evidence                                                      |
| ----------------------- | -----: | ------------------------------------------------------------- |
| `name`                  |   0.55 | The repository name contains the CVE ID                       |
| `topic`                 |   0.40 | A topic is the CVE ID                                         |
| `file-path`             |   0.35 | A file or directory name contains the CVE ID                  |
| `description`           |   0.25 | The description mentions the CVE ID                           |
| `cve-reference`         |   0.50 | The CVE record lists the repository as a reference            |
| `cve-exploit-reference` |   0.70 | …with an `Exploit` tag                                        |
| `search-match`          |   0.05 | Only GitHub's search matched (e.g. README text we never read) |
| `manual`                |   0.95 | An analyst created the association                            |

Signals are combined with a noisy-OR (`1 − Π(1 − wᵢ)`). Text signals are then multiplied by
penalties: fork `×0.85`, empty repository `×0.3`, no source files `×0.6`, created before the CVE
was published `×0.6`, and `max(0.25, 3/n)` when the text mentions `n > 3` CVEs (lists and
collections). Curated signals (CVE references, manual) are not penalised. Automatic scores are
capped at 0.99. Levels: `high` ≥ 0.7, `medium` ≥ 0.4, otherwise `low`. Pairs below
`POC_MIN_ASSOCIATION_CONFIDENCE` (0.15) are not stored, so a README-only match (0.05) never
becomes an association; at most `POC_MAX_ASSOCIATIONS_PER_REPOSITORY` (50) are kept per
repository. Signals and penalties are stored with each association and returned by the API.

Analysts review associations (`candidate` → `confirmed` or `rejected`). Rescoring updates the
score but never overrides a review; rejected associations are excluded from a repository's
`maxConfidence`.

## Artifacts and duplicates

An artifact is one Git tree of a repository (unique per repository and tree SHA). It records the
commit SHA, tree SHA, file count, total bytes, a SHA-256 fingerprint over the sorted listing
(path, mode, blob SHA), and risk indicators (`contains-executables`, `contains-archives`,
`contains-macro-documents`, `no-source-code`, `empty`, `listing-truncated`,
`duplicate-of-malicious`). Each new head commit is a new version; older versions are kept.

- **Exact duplicate:** another repository has an artifact with the same tree SHA
  (byte-identical content), similarity 1.
- **Near duplicate:** Jaccard similarity over the significant blob SHAs ≥
  `POC_NEAR_DUPLICATE_THRESHOLD` (0.8). Licences, `.gitignore`, other boilerplate and the empty
  blob are not significant.

The earliest discovered artifact is the original. A duplicate of an artifact judged malicious gets
the `duplicate-of-malicious` indicator.

## Verification states

`unverified` → `in-review` → `verified` | `rejected` | `malicious`
(`ARTIFACT_VERIFICATION_TRANSITIONS` in `@cve/contracts`). Every change needs `poc:manage`, an
`If-Match` version (optional) and a reason, and is recorded in the append-only
`artifact_verification_events` table (a trigger refuses updates). Artifacts judged `malicious` are
**hidden from users without `quarantine:read`** (they get 404, and lists omit them); leaving the
`malicious` state needs `quarantine:manage` (administrators).

## Events

Published through the outbox (payload schemas in `@cve/contracts`, `src/poc/events.ts`):

| Event                                    | When                                                  |
| ---------------------------------------- | ----------------------------------------------------- |
| `poc.repository.discovered`              | First time a repository is stored                     |
| `poc.repository.updated`                 | Metadata, status (unavailable) or head commit changed |
| `poc.cve-association.discovered`         | A new association passed the threshold                |
| `poc.cve-association.updated`            | Score, level or signals changed                       |
| `poc.cve-association.reviewed`           | An analyst confirmed or rejected it                   |
| `poc.artifact.discovered`                | A new tree (artifact version) was recorded            |
| `poc.artifact.verification-changed`      | Verification status changed                           |
| `poc.reference.discovered`               | A CVE record listed a new PoC reference               |
| `poc.discovery-run.completed` / `failed` | A discovery job finished                              |

Consumed: `cve.record.*` (consumer `cve-record-tracker`) and
`intelligence.cve-observation.recorded` (consumer `cve-observation-references`), both idempotent
(`processed_events` inbox in the handler's transaction) and order-aware (record versions and
observation revisions).

## Jobs (BullMQ)

| Queue             | Job                                                               | Schedule                    |
| ----------------- | ----------------------------------------------------------------- | --------------------------- |
| `poc-discovery`   | CVE search, recent sweep (concurrency 1)                          | recent sweep `*/30 * * * *` |
| `poc-inspection`  | Repository inspection, reference lookups                          | on demand                   |
| `poc-scheduling`  | Queue due tracked CVEs                                            | `*/10 * * * *`              |
| `poc-maintenance` | Fail stale runs, re-queue lost inspections and lookups, retention | `7 * * * *`                 |

Jobs retry with exponential backoff; HTTP 429/5xx and timeouts are retryable, a disabled
connector or an unknown repository is not. Job IDs are deterministic, so the same CVE slot,
inspection or idempotency key is never queued twice. The database is the source of truth:
maintenance re-queues work Redis may have lost.

## Connectors

Only approved connectors can be enabled (`POC_CONNECTORS_ENABLED`, unknown names are refused at
start-up):

- `github`: GitHub REST API, repository search, repository, commit and tree endpoints. Without a
  token: 10 search requests / min and 60 core requests / h; with a token (no scopes needed):
  30 / min and 5 000 / h. The client keeps below those limits and pauses on `x-ratelimit-*`.
- `cve-references`: references from CVE records (no network access of its own).

Exploit-DB is recognised as a reference kind but has no connector of its own yet.

## API

All routes are under `/api/v1` and also exposed by the API gateway. Reads need `poc:read`
(every role), writes `poc:manage` (vulnerability researchers and administrators).

| Method | Path                                             | Description                                                          |
| ------ | ------------------------------------------------ | -------------------------------------------------------------------- |
| GET    | `/poc-repositories`                              | Filter by `q`, `cveId`, `owner`, `status`, `minConfidence`, `isFork` |
| GET    | `/poc-repositories/:id`                          | One repository with its CVE IDs and head commit                      |
| GET    | `/poc-repositories/:id/commits`                  | Observed commits                                                     |
| GET    | `/poc-owners`, `/poc-owners/:id`                 | Repository owners                                                    |
| GET    | `/poc-associations`, `/poc-associations/:id`     | Scored associations with signals (ETag)                              |
| POST   | `/poc-associations`                              | Manual association (confirmed)                                       |
| PATCH  | `/poc-associations/:id`                          | Review (`If-Match` optional)                                         |
| GET    | `/poc-artifacts`, `/poc-artifacts/:id`           | Artifacts; the detail lists the files                                |
| GET    | `/poc-artifacts/:id/verification-history`        | Verification decisions, newest first                                 |
| POST   | `/poc-artifacts/:id/verification`                | Change the verification status                                       |
| GET    | `/poc-references`                                | PoC references from CVE records                                      |
| GET    | `/poc-connectors`                                | Connectors, approval, origins, cursor, last run                      |
| GET    | `/poc-discovery-runs`, `/poc-discovery-runs/:id` | Discovery history                                                    |
| POST   | `/poc-discovery-runs`                            | Queue a discovery (`Idempotency-Key` supported)                      |

## Configuration

Besides the common service variables (`DATABASE_URL`, `RABBITMQ_URL`, `REDIS_URL`, `PORT`, …) and
the Keycloak variables (`KEYCLOAK_URL`, `KEYCLOAK_PUBLIC_URL`, `KEYCLOAK_REALM`,
`KEYCLOAK_AUDIENCE`):

| Variable                                                                                  | Default                          | Description                               |
| ----------------------------------------------------------------------------------------- | -------------------------------- | ----------------------------------------- |
| `POC_CONNECTORS_ENABLED`                                                                  | `github,cve-references`          | Approved connectors to run, or `none`     |
| `GITHUB_API_URL`                                                                          | `https://api.github.com`         | Must be https in production               |
| `GITHUB_TOKEN`                                                                            | unset                            | Optional; higher quotas, no scopes needed |
| `POC_GITHUB_SEARCH_IN`                                                                    | `name,description,topics,readme` | Fields searched for a CVE ID              |
| `POC_GITHUB_MAX_SEARCH_PAGES`                                                             | `3`                              | Pages of 100 per CVE search               |
| `POC_GITHUB_RECENT_CRON`                                                                  | `*/30 * * * *`                   | Recent sweep schedule                     |
| `POC_GITHUB_RECENT_WINDOW_MINUTES`                                                        | `60`                             | Pushed-at window per query                |
| `POC_GITHUB_RECENT_INITIAL_LOOKBACK_HOURS`                                                | `24`                             | First sweep without a cursor              |
| `POC_GITHUB_RECENT_MAX_WINDOWS_PER_RUN`                                                   | `24`                             |                                           |
| `POC_DISCOVERY_SWEEP_CRON`                                                                | `*/10 * * * *`                   | Tracked-CVE sweep                         |
| `POC_DISCOVERY_BATCH_SIZE`                                                                | `20`                             | CVEs queued per sweep                     |
| `POC_MIN_ASSOCIATION_CONFIDENCE`                                                          | `0.15`                           | Pairs below are not stored                |
| `POC_MAX_ASSOCIATIONS_PER_REPOSITORY`                                                     | `50`                             |                                           |
| `POC_MAX_FILES_PER_ARTIFACT`                                                              | `2000`                           | Files stored per listing                  |
| `POC_NEAR_DUPLICATE_THRESHOLD`                                                            | `0.8`                            | Jaccard threshold                         |
| `POC_DISCOVERY_JOB_ATTEMPTS`                                                              | `4`                              |                                           |
| `POC_DISCOVERY_JOB_TIMEOUT_MS`                                                            | `1800000`                        |                                           |
| `POC_INSPECTION_CONCURRENCY`                                                              | `2`                              |                                           |
| `POC_MAINTENANCE_CRON`                                                                    | `7 * * * *`                      |                                           |
| `SOURCE_HTTP_TIMEOUT_MS`, `SOURCE_HTTP_MAX_ATTEMPTS`, `SOURCE_HTTP_USER_AGENT`            |                                  | Outbound HTTP                             |
| `OUTBOX_RELAY_ENABLED`, `EVENT_CONSUMERS_ENABLED`, `DISCOVERY_WORKER_ENABLED`             | `true`                           | Disabled only in tests                    |
| `PROCESSED_EVENT_RETENTION_DAYS`, `OUTBOX_RETENTION_DAYS`, `DISCOVERY_RUN_RETENTION_DAYS` | `30`, `7`, `90`                  | Retention                                 |

The `poc-service-migrate` Compose job applies the Prisma migrations before the service starts.

## Tests

```bash
pnpm --filter @cve/poc-service test              # unit, connector (mock GitHub) and HTTP (auth, RBAC, validation)
pnpm --filter @cve/poc-service test:integration  # PostgreSQL + Redis: discovery, duplicates, consumers, API, BullMQ
```

The integration suite needs PostgreSQL and Redis: either the Compose stack (`compose.dev.yaml`
publishes them; credentials from the root `.env`) or any servers via
`POC_SERVICE_TEST_DATABASE_URL` and `POC_SERVICE_TEST_REDIS_URL`. GitHub is replaced by a local
mock. It only uses synthetic data (owners `zz-test…`, CVE IDs `CVE-2026-9xxxxx`) and refuses to run
against a database that holds anything else.

## Not done yet

- No live GitHub calls were made while building this; the connector is tested against a mock that
  follows the documented REST API.
- Exploit-DB has no connector of its own (its URLs are collected as references), and gists are
  recorded as references but not inspected.
- Downloading, SHA-256 of downloaded content, malware scanning and quarantine storage belong to the
  [Download Service](download-service.md), which consumes this service's artifact and verification
  events. This service does not consume the `download.*` events yet, so it does not show download
  or scan status. The verification state here remains the analysts' judgement.
- The consumers were tested against PostgreSQL with synthetic events, not against a live RabbitMQ
  broker; topology and delivery are covered by the `@cve/messaging` tests.
