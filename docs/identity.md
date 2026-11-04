# Identity, authentication and authorization

Phase 1 of `CLAUDE.md`. Keycloak is the identity provider; the platform never receives, stores or
sets passwords. The Identity Service and the API Gateway build on the shared `@cve/auth` package.

```
Browser ──(OIDC code + PKCE)──▶ Keycloak (realm cve-platform)
   │ access token (aud=cve-api, roles claim)
   ▼
Nginx ──▶ API Gateway ── validate JWT (JWKS) ── introspect session (cached 15 s) ── rate limit per user
              │           ── coarse permission check ── forward with the same bearer token
              ▼
        Identity Service ── validate JWT again ── fine-grained rules ── Keycloak Admin API
              │                                                       (service account)
              ├── PostgreSQL identity_service: profiles, audit_events (append-only), outbox_events
              ├── RabbitMQ: identity.* domain events via the transactional outbox
              └── Redis/BullMQ: scheduled ingestion of Keycloak login and admin events
```

## Tokens

- Access tokens are RS256 JWTs from the `cve-platform` realm. They must carry `aud: cve-api`
  (added by the `cve-api` client scope), `typ: Bearer`, `sub`, `exp` and the flat `roles` claim.
- `@cve/auth` (`createTokenVerifier`) checks the signature against the realm JWKS (cached, refreshed
  on unknown `kid`), the algorithm allowlist (RSA/ECDSA only, never `none` or HMAC), issuer,
  audience, expiry (30 s skew) and token type. ID and refresh tokens are rejected.
- The issuer is the **public** Keycloak URL (`KEYCLOAK_PUBLIC_URL`, what browsers use); keys and
  introspection use the **internal** URL (`KEYCLOAK_URL`). Both must point at the same realm.
- Only the five platform roles are read from the token. Unknown roles grant nothing.

## Roles and permissions

Roles live in Keycloak as composite realm roles. Permissions are derived from roles by the
reviewed static mapping in `packages/contracts/src/permissions.ts`, so every service enforces the
same rules without calling the Identity Service per request.

| Permission                                                                           | Viewer | Researcher | Analyst | Administrator | Super Admin |
| ------------------------------------------------------------------------------------ | :----: | :--------: | :-----: | :-----------: | :---------: |
| `*:read` (CVE, analysis, PoC, exploit, asset, threat intel, report, platform health) |   ✓    |     ✓      |    ✓    |       ✓       |      ✓      |
| `analysis:write`, `artifact:download`, `download:read`                               |        |     ✓      |    ✓    |       ✓       |      ✓      |
| `poc:manage`, `exploit:manage`, `quarantine:read`, `download:schedule`               |        |     ✓      |         |       ✓       |      ✓      |
| `asset:manage`, `report:create`, `data-source:read`                                  |        |            |    ✓    |       ✓       |      ✓      |
| `cve:manage`, `quarantine:manage`, `data-source:manage`, `settings:*`                |        |            |         |       ✓       |      ✓      |
| `user:read`, `user:manage`, `role:assign`, `session:manage`, `audit:read`            |        |            |         |       ✓       |      ✓      |
| `role:assign-privileged`                                                             |        |            |         |               |      ✓      |

`GET /api/v1/roles` and `GET /api/v1/permissions` return the live catalog. Changing the mapping
is a code change (reviewed, tested in `permissions.test.ts`) rather than runtime configuration.

Delegation rules enforced by the Identity Service:

- Administrator and Super Admin can only be granted or revoked by a Super Admin
  (`role:assign-privileged`); administrators also cannot disable, log out or reset accounts that
  hold a privileged role.
- Nobody changes their own roles or account status.
- The last enabled Super Admin cannot be demoted or disabled (409).
- Removing a role, disabling a user or requiring a password update ends all of that user's
  sessions, so the change applies immediately instead of when the access token expires.

## NestJS guards

```ts
import { authGuards, AuthModule, CurrentPrincipal, RequirePermissions } from '@cve/auth';
import { Public } from '@cve/shared';

@Module({
  imports: [AuthModule.forRoot({ verifier, logger, sessionChecker /* optional */ })],
  providers: [...authGuards()], // AuthenticationGuard, then AuthorizationGuard, globally
})
class AppModule {}

@RequirePermissions('user:read') // class requirements are combined with handler ones
@Controller('users')
class UsersController {
  @Put(':id/roles')
  @RequirePermissions('role:assign') // all listed permissions are required
  setRoles(@CurrentPrincipal() principal: AuthenticatedPrincipal) {}
}
```

- Every route is **private by default**. `@Public()` (from `@cve/shared`) opts out; health
  endpoints are public.
- `401` carries `WWW-Authenticate: Bearer realm="cve-platform"[, error="invalid_token"]`; `403`
  means authenticated but not permitted; `503` means Keycloak could not be reached to validate.
- `@RequireRoles(...)` exists for the rare case where a role (any of) matters more than a
  permission.
- Authentication failures and access denials are logged with `audit: true`; the Identity Service
  also writes denials to its audit log.

## API Gateway

- Guard order: authentication → per-user rate limit → authorization.
- **Session liveness:** after local JWT validation the gateway introspects the token at Keycloak
  (`cve-api` confidential client) and caches "active" per session for
  `AUTH_SESSION_CACHE_TTL_MS` (default 15 s). A logged-out or revoked session is therefore rejected
  within that window, and immediately for a logout that passed through the gateway. If Keycloak
  cannot answer, requests fail closed with 503.
- **Rate limiting:** `RATE_LIMIT_MAX` per `RATE_LIMIT_TTL_MS` per user (`sub`), or per client IP
  for anonymous requests; `POST /auth/logout` is limited to 20 per minute. Nginx `limit_req`
  caps every IP in front of that. The store is in memory, so running several gateway replicas
  needs a Redis store first.
- **Routing:** the gateway forwards the Identity Service routes below with the original bearer
  token, the correlation ID and the client IP. It refuses dot segments and encoded separators in
  paths (so a path cannot be authorised as one route and resolved as another), accepts only JSON
  bodies, never forwards cookies, and answers 502/504 when the backend is down or slow.
- `GET /api/v1/health/services` stays public for the web overview, but anonymous callers only see
  each service's status; versions, dependency checks and error messages need
  `platform-health:read`.

## Identity Service endpoints

All under `/api/v1`, all require a bearer token.

| Method | Path                                                                                | Permission       | Description                                                     |
| ------ | ----------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------- |
| GET    | `/me`                                                                               | —                | Profile, roles and effective permissions                        |
| PATCH  | `/me`                                                                               | —                | Names (written to Keycloak), display name, job title, time zone |
| GET    | `/me/credentials/actions`                                                           | —                | Keycloak links to change the password or configure TOTP         |
| GET    | `/me/sessions`                                                                      | —                | Own Keycloak sessions, current one marked                       |
| DELETE | `/me/sessions/:sessionId`                                                           | —                | Revoke one own session                                          |
| POST   | `/auth/logout`                                                                      | —                | End the current session (`{ "allSessions": true }` for all)     |
| GET    | `/roles`, `/permissions`                                                            | —                | RBAC catalog                                                    |
| GET    | `/users?search=&page=&pageSize=`                                                    | `user:read`      | Users with effective roles                                      |
| GET    | `/users/:id`                                                                        | `user:read`      | One user                                                        |
| PUT    | `/users/:id/roles`                                                                  | `role:assign`    | Replace direct platform roles (`{ roles, reason? }`)            |
| PATCH  | `/users/:id/status`                                                                 | `user:manage`    | Enable or disable (`{ enabled, reason? }`)                      |
| POST   | `/users/:id/credentials/require-password-update`                                    | `user:manage`    | Keycloak `UPDATE_PASSWORD` required action + logout             |
| GET    | `/users/:id/sessions`                                                               | `session:manage` | Sessions of a user                                              |
| DELETE | `/users/:id/sessions/:sessionId`                                                    | `session:manage` | Revoke one session of a user                                    |
| POST   | `/users/:id/logout`                                                                 | `session:manage` | End every session of a user                                     |
| GET    | `/audit-logs?actorId=&action=&outcome=&source=&resourceType=&resourceId=&from=&to=` | `audit:read`     | Audit log, newest first, paginated                              |
| GET    | `/audit-logs/:id`                                                                   | `audit:read`     | One audit entry                                                 |

### Secure logout

`POST /api/v1/auth/logout` deletes the Keycloak session named by the token's `sid` (or every
session), which invalidates its refresh tokens. The gateway stops accepting the access token at
once. Clients must also discard their tokens. Logout is idempotent.

### Credentials

Passwords and second factors are only ever entered on Keycloak pages:

- Users start a Keycloak application-initiated action from the links of
  `GET /me/credentials/actions` (`kc_action=UPDATE_PASSWORD` / `CONFIGURE_TOTP`); the web client
  adds `state`, `nonce` and PKCE and redirects the browser.
- Administrators can only require a password change at the next login.
- The realm enforces the password policy (14+ characters, mixed classes, history) and brute-force
  protection.

## Audit log

- Table `audit_events` in the Identity Service database. A trigger rejects `UPDATE`, `DELETE` and
  `TRUNCATE`, so entries are append-only even for the service's own database role.
- Entries record actor, action (`<domain>.<entity>.<action>`), outcome (`success`, `failure`,
  `denied`), resource, client IP, user agent, correlation ID and non-sensitive details.
- Recorded today: profile updates, logouts and session revocations, role changes (including denied
  attempts), account status changes, password-update requirements, authorization denials, and
  Keycloak login/logout/credential events and admin events. Keycloak events are copied every
  `KEYCLOAK_EVENTS_SYNC_INTERVAL_MS` (default 60 s) by a BullMQ job, idempotently (keyed by
  Keycloak event ID, with a cursor in `sync_cursors`).
- State changes and their domain events (`identity.user.roles-changed`,
  `identity.user.status-changed`, `identity.session.revoked`) are written in the same transaction;
  `OutboxRelay` publishes them to RabbitMQ (`FOR UPDATE SKIP LOCKED` leasing).

## Keycloak realm

`infra/keycloak/import/cve-platform-realm.json` is imported on first start only.

- It defines the `basic`, `profile`, `email` and `web-origins` client scopes explicitly: a realm
  import creates only the scopes it lists, and without `basic` access tokens have no `sub`.
- The Identity Service service account holds `view-users`, `query-users`, `manage-users`,
  `view-realm` and `view-events` on `realm-management`.
- **Existing deployments** created before this change keep their old realm. Either delete the realm
  and restart Keycloak (development), or add the four client scopes, assign them as default scopes
  of `cve-web`, and grant `view-events` to `service-account-cve-identity-service` in the admin
  console.

## Configuration

Identity Service (in addition to the standard service variables):

| Variable                           | Required | Default                | Notes                                           |
| ---------------------------------- | -------- | ---------------------- | ----------------------------------------------- |
| `KEYCLOAK_URL`                     | yes      |                        | Internal base, e.g. `http://keycloak:8180/auth` |
| `KEYCLOAK_PUBLIC_URL`              | yes      |                        | Public base; defines the issuer                 |
| `KEYCLOAK_ADMIN_CLIENT_SECRET`     | yes      |                        | `cve-identity-service` client secret            |
| `ACCOUNT_REDIRECT_URI`             | yes      |                        | Where Keycloak returns after credential actions |
| `KEYCLOAK_REALM`                   | no       | `cve-platform`         |                                                 |
| `KEYCLOAK_AUDIENCE`                | no       | `cve-api`              |                                                 |
| `KEYCLOAK_ADMIN_CLIENT_ID`         | no       | `cve-identity-service` |                                                 |
| `KEYCLOAK_WEB_CLIENT_ID`           | no       | `cve-web`              |                                                 |
| `KEYCLOAK_TIMEOUT_MS`              | no       | `5000`                 |                                                 |
| `OUTBOX_RELAY_ENABLED`             | no       | `true`                 |                                                 |
| `KEYCLOAK_EVENTS_SYNC_ENABLED`     | no       | `true`                 |                                                 |
| `KEYCLOAK_EVENTS_SYNC_INTERVAL_MS` | no       | `60000`                |                                                 |

API Gateway:

| Variable                                                     | Required                    | Default   |
| ------------------------------------------------------------ | --------------------------- | --------- |
| `KEYCLOAK_URL`, `KEYCLOAK_PUBLIC_URL`                        | yes                         |           |
| `KEYCLOAK_INTROSPECTION_CLIENT_SECRET`                       | while session checks are on |           |
| `AUTH_SESSION_CHECK_ENABLED`                                 | no                          | `true`    |
| `AUTH_SESSION_CACHE_TTL_MS`                                  | no                          | `15000`   |
| `KEYCLOAK_INTROSPECTION_CLIENT_ID`                           | no                          | `cve-api` |
| `KEYCLOAK_REALM`, `KEYCLOAK_AUDIENCE`, `KEYCLOAK_TIMEOUT_MS` | no                          | as above  |
| `PROXY_TIMEOUT_MS`                                           | no                          | `15000`   |

Compose wires all of these from `.env` (`KEYCLOAK_API_CLIENT_SECRET`,
`KEYCLOAK_IDENTITY_SERVICE_CLIENT_SECRET`, optional `KEYCLOAK_PUBLIC_URL`, `PUBLIC_ORIGIN`);
`pnpm env:generate` writes them into the per-app `.env` files for `pnpm dev`.

## Migrations

Prisma schema and migrations: `services/identity-service/prisma`. Compose runs the one-shot
`identity-service-migrate` job (`prisma migrate deploy`) before the service starts. Locally:

```bash
DATABASE_URL=postgresql://identity_service:…@localhost:5432/identity_service \
  pnpm --filter @cve/identity-service prisma:migrate:deploy
```

## Testing

| Command                                                | Needs                                                                        |
| ------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `pnpm --filter @cve/auth test`                         | nothing (in-memory RS256 issuer)                                             |
| `pnpm --filter @cve/identity-service test`             | nothing (in-memory Keycloak and repositories)                                |
| `pnpm --filter @cve/api-gateway test`                  | nothing (fake backend and introspection)                                     |
| `pnpm --filter @cve/identity-service test:integration` | `docker compose -f compose.yaml -f compose.dev.yaml up -d postgres keycloak` |

The integration suite applies the migrations, checks the append-only trigger and outbox leasing on
PostgreSQL, and runs real Keycloak logins (through a temporary password-grant test client) against
the Identity Service: token validation, introspection after logout, profile updates in Keycloak,
role changes ending sessions, denied privileged grants in the audit log, and event ingestion.

## Not implemented yet

- Login in the web app (OIDC code flow with PKCE, token storage, refresh). The API is ready for it.
- A Redis store for the gateway rate limiter (needed before running several gateway replicas).
- Separate migration and runtime database roles (the service role currently owns its schema).
- Ingesting audit events from other services (they will publish them once they have features).
