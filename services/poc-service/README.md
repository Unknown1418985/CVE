# PoC Service

Proof-of-Concept discovery and metadata management.

- Package: `@cve/poc-service`
- Default port: `4005`
- Database: `poc_service` (owned exclusively by this service, role `poc_service`)

## Responsibilities

- Discovers public PoC repositories on GitHub (CVE searches, a recent-push sweep) and PoC
  references listed in CVE records.
- Tracks repository owners, URLs, commits and file listings (metadata only; contents are never
  fetched or executed).
- Scores CVE associations, detects exact and near duplicates, and keeps artifact verification
  states with an append-only history.
- Publishes `poc.*` events through an outbox; runs discovery as BullMQ jobs.

See [docs/poc-service.md](../../docs/poc-service.md) for the design, scoring, API, events,
configuration and tests.

## Endpoints

| Method | Path                         | Description                                                     |
| ------ | ---------------------------- | --------------------------------------------------------------- |
| GET    | `/api/v1/health/live`        | Liveness probe                                                  |
| GET    | `/api/v1/health/ready`       | Readiness probe: PostgreSQL, RabbitMQ, Redis                    |
| GET    | `/api/v1/poc-*`              | Repositories, owners, associations, artifacts, references, runs |
| POST   | `/api/v1/poc-discovery-runs` | Queue a discovery job                                           |
| GET    | `/api/v1/docs`               | OpenAPI UI (only when `SWAGGER_ENABLED=true`)                   |

## Scripts

```bash
pnpm --filter @cve/poc-service dev        # watch mode (reads ../../.env)
pnpm --filter @cve/poc-service test
pnpm --filter @cve/poc-service test:integration   # PostgreSQL + Redis
pnpm --filter @cve/poc-service typecheck
```
