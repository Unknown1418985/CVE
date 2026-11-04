# API Gateway

Public entry point of the platform. All public endpoints are served under `/api/v1`.

- Package: `@cve/api-gateway`
- Default port: `4000`
- Owns no database.

## Current status (Phase 0)

- Configuration validation (all backend service URLs are required and must be HTTP(S)).
- Global rate limiting (`@nestjs/throttler`, in-memory store; a Redis store is required before
  running more than one gateway replica).
- Security headers, strict CORS, correlation IDs, error envelope, optional OpenAPI UI.
- Health endpoints, including aggregated platform health.

Routing of business endpoints to backend services is added together with each feature.

## Endpoints

| Method | Path                      | Description                                                 |
| ------ | ------------------------- | ----------------------------------------------------------- |
| GET    | `/api/v1/health/live`     | Liveness probe                                              |
| GET    | `/api/v1/health/ready`    | Readiness probe                                             |
| GET    | `/api/v1/health`          | Same as readiness                                           |
| GET    | `/api/v1/health/services` | Readiness of every backend service (always 200, see status) |
| GET    | `/api/v1/docs`            | OpenAPI UI (only when `SWAGGER_ENABLED=true`)               |

## Configuration

| Variable                                                                      | Required | Default           |
| ----------------------------------------------------------------------------- | -------- | ----------------- |
| `IDENTITY_SERVICE_URL` … `NOTIFICATION_SERVICE_URL` (9 variables)             | yes      |                   |
| `PORT`                                                                        | no       | `4000`            |
| `RATE_LIMIT_TTL_MS`                                                           | no       | `60000`           |
| `RATE_LIMIT_MAX`                                                              | no       | `300`             |
| `CORS_ALLOWED_ORIGINS`                                                        | no       | none              |
| `SWAGGER_ENABLED`, `LOG_LEVEL`, `NODE_ENV`, `HOST`, `HEALTH_CHECK_TIMEOUT_MS` | no       | see `@cve/config` |
