# Download Service

Secure, controlled artifact downloading and MinIO storage.

- Package: `@cve/download-service`
- Default port: `4006`
- Database: `download_service` (owned exclusively by this service, role `download_service`)

## Responsibilities

- Source allowlists, URL/redirect validation, DNS resolution and private-network blocking.
- Size limits, timeouts, content-type validation, SHA-256 hashing and duplicate detection.
- Malware scanning, quarantine before release and MinIO storage with generated keys.
- Never executes downloaded files and never extracts archives automatically.

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
| `PORT`                    | no       | `4006`        |
| `HOST`                    | no       | `0.0.0.0`     |
| `NODE_ENV`                | no       | `development` |
| `LOG_LEVEL`               | no       | `info`        |
| `CORS_ALLOWED_ORIGINS`    | no       | none          |
| `SWAGGER_ENABLED`         | no       | `false`       |
| `HEALTH_CHECK_TIMEOUT_MS` | no       | `2000`        |

## Scripts

```bash
pnpm --filter @cve/download-service dev        # watch mode (reads ../../.env)
pnpm --filter @cve/download-service test
pnpm --filter @cve/download-service typecheck
```
