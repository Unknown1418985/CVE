# API Gateway

Public entry point of the platform. All public endpoints are served under `/api/v1`.

- Package: `@cve/api-gateway`
- Default port: `4000`
- Owns no database.

## Current status (Phase 1)

- Keycloak access-token validation on every non-public route, Keycloak session introspection
  (cached 15 s, fail closed) and coarse permission checks before forwarding.
- Per-user rate limiting (per IP when anonymous; in-memory store, so a Redis store is required
  before running more than one gateway replica); stricter limit on logout.
- Forwards the Identity Service routes (`/me`, `/auth/logout`, `/users`, `/roles`, `/permissions`,
  `/audit-logs`) with the original bearer token; refuses dot segments and non-JSON bodies.
- Security headers, strict CORS, correlation IDs, error envelope, optional OpenAPI UI.
- Health endpoints, including aggregated platform health (details only with
  `platform-health:read`).

See [docs/identity.md](../../docs/identity.md).

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
| `KEYCLOAK_URL`, `KEYCLOAK_PUBLIC_URL`, `KEYCLOAK_INTROSPECTION_CLIENT_SECRET` | yes      | see identity.md   |
| `CORS_ALLOWED_ORIGINS`                                                        | no       | none              |
| `SWAGGER_ENABLED`, `LOG_LEVEL`, `NODE_ENV`, `HOST`, `HEALTH_CHECK_TIMEOUT_MS` | no       | see `@cve/config` |
