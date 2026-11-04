# Intelligence Service

Synchronises vulnerability intelligence from NVD, MITRE CVE, CISA KEV, FIRST EPSS and the GitHub
Advisory Database, keeps per-source observations with their history, and publishes changes as
RabbitMQ events. Design, quotas, terms, events and recovery are described in
[docs/intelligence-service.md](../../docs/intelligence-service.md).

- Package: `@cve/intelligence-service`
- Default port: `4003`
- Database: `intelligence_service` (owned exclusively by this service, role `intelligence_service`)

## Endpoints

| Method | Path                             | Permission           | Description                                      |
| ------ | -------------------------------- | -------------------- | ------------------------------------------------ |
| GET    | `/api/v1/sources`                | `data-source:read`   | Source status, cursor, terms and attribution     |
| GET    | `/api/v1/sources/:source`        | `data-source:read`   | One source                                       |
| POST   | `/api/v1/sources/:source/sync`   | `data-source:manage` | Queue a manual run (`Idempotency-Key` supported) |
| GET    | `/api/v1/sync-runs`              | `data-source:read`   | Synchronisation history                          |
| GET    | `/api/v1/sync-runs/:runId`       | `data-source:read`   | One run with its issues                          |
| POST   | `/api/v1/sync-runs/:runId/retry` | `data-source:manage` | Retry the latest failed run from its checkpoint  |
| GET    | `/api/v1/health/live`            | none                 | Liveness probe                                   |
| GET    | `/api/v1/health/ready`           | none                 | Readiness: PostgreSQL, RabbitMQ, Redis           |
| GET    | `/api/v1/docs`                   | none                 | OpenAPI UI (only when `SWAGGER_ENABLED=true`)    |

## Configuration

See `src/config/env.ts` and the configuration section of the design document. Optional secrets:
`NVD_API_KEY` and `GITHUB_TOKEN` (both raise upstream quotas).

## Scripts

```bash
pnpm --filter @cve/intelligence-service dev               # watch mode (reads ../../.env)
pnpm --filter @cve/intelligence-service test              # mocked upstream APIs
pnpm --filter @cve/intelligence-service test:integration  # needs PostgreSQL and Redis
pnpm --filter @cve/intelligence-service typecheck
pnpm --filter @cve/intelligence-service prisma:migrate:deploy
```
