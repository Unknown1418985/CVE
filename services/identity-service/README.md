# Identity Service

Authentication and authorization: Keycloak integration, users, roles, permissions and audit logging.

- Package: `@cve/identity-service`
- Default port: `4001`
- Database: `identity_service` (owned exclusively by this service, role `identity_service`)

## Responsibilities

- Keycloak (OIDC) token validation and user synchronisation.
- Role-Based Access Control for Super Admin, Administrator, Security Analyst, Vulnerability Researcher and Viewer.
- Audit log storage and querying.

## Current status (Phase 1)

Implemented: Keycloak token validation on every route, profile management, session listing and
revocation, secure logout, user administration (roles, status, required password update) with
delegation rules, the append-only audit log (own actions, access denials and ingested Keycloak
events), and the transactional outbox for `identity.*` events. Passwords are never handled here;
Keycloak owns all credentials. See [docs/identity.md](../../docs/identity.md) for the full API,
rules and configuration.

## Endpoints

The business endpoints are listed in [docs/identity.md](../../docs/identity.md#identity-service-endpoints).

| Method | Path                   | Description                                                                     |
| ------ | ---------------------- | ------------------------------------------------------------------------------- |
| GET    | `/api/v1/health/live`  | Liveness probe                                                                  |
| GET    | `/api/v1/health/ready` | Readiness: PostgreSQL `SELECT 1`, Keycloak realm, AMQP connection, Redis `PING` |
| GET    | `/api/v1/health`       | Same as readiness                                                               |
| GET    | `/api/v1/docs`         | OpenAPI UI (only when `SWAGGER_ENABLED=true`)                                   |

## Configuration

Standard service variables (`DATABASE_URL`, `RABBITMQ_URL`, `REDIS_URL`, `PORT` = `4001`, …) plus the
Keycloak settings in [docs/identity.md](../../docs/identity.md#configuration).

## Scripts

```bash
pnpm --filter @cve/identity-service dev        # watch mode (reads ../../.env)
pnpm --filter @cve/identity-service test
pnpm --filter @cve/identity-service typecheck
pnpm --filter @cve/identity-service test:integration      # needs postgres + keycloak (compose.dev.yaml)
pnpm --filter @cve/identity-service prisma:migrate:deploy # DATABASE_URL required
```
