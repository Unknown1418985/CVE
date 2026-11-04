# PoC Service

Proof-of-Concept discovery and metadata management.

- Package: `@cve/poc-service`
- Default port: `4005`
- Database: `poc_service` (owned exclusively by this service, role `poc_service`)

## Responsibilities

- PoC discovery from public sources and source repository tracking.
- CVE association, verification status and version tracking.
- Requests downloads from the Download Service; never executes PoC content.

## Current status (Phase 0)

Only the service skeleton exists: configuration validation, structured logging, security
headers, correlation IDs, the error envelope and health endpoints. No business features are
implemented yet.

## Endpoints

| Method | Path                   | Description                                                      |
| ------ | ---------------------- | ---------------------------------------------------------------- |
| GET    | `/api/v1/health/live`  | Liveness probe                                                   |
| GET    | `/api/v1/health/ready` | Readiness probe; TCP reachability of PostgreSQL, RabbitMQ, Redis |
| GET    | `/api/v1/health`       | Same as readiness                                                |
| GET    | `/api/v1/docs`         | OpenAPI UI (only when `SWAGGER_ENABLED=true`)                    |

## Configuration

| Variable                  | Required | Default       |
| ------------------------- | -------- | ------------- |
| `DATABASE_URL`            | yes      |               |
| `RABBITMQ_URL`            | yes      |               |
| `REDIS_URL`               | yes      |               |
| `PORT`                    | no       | `4005`        |
| `HOST`                    | no       | `0.0.0.0`     |
| `NODE_ENV`                | no       | `development` |
| `LOG_LEVEL`               | no       | `info`        |
| `CORS_ALLOWED_ORIGINS`    | no       | none          |
| `SWAGGER_ENABLED`         | no       | `false`       |
| `HEALTH_CHECK_TIMEOUT_MS` | no       | `2000`        |

## Scripts

```bash
pnpm --filter @cve/poc-service dev        # watch mode (reads ../../.env)
pnpm --filter @cve/poc-service test
pnpm --filter @cve/poc-service typecheck
```
