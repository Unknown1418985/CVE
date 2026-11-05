# Architecture

This document describes the structure established in Phase 0. It is updated as each phase lands.

## Overview

```
                 ┌──────────┐
 Browser ───────▶│  Nginx   │──────────────┐
                 └────┬─────┘              │
                      │ /                  │ /api/v1
                 ┌────▼─────┐        ┌─────▼───────┐
                 │   Web    │──SSR──▶│ API Gateway │
                 │ (Next.js)│        │  (NestJS)   │
                 └──────────┘        └─────┬───────┘
                                           │ HTTP (internal)
        ┌───────────┬───────────┬──────────┼──────────┬───────────┬───────────┐
        ▼           ▼           ▼          ▼          ▼           ▼           ▼
    identity      cve     intelligence   asset       poc      download     exploit   reporting  notification
        │           │           │          │          │           │           │
        └───────────┴───── RabbitMQ (domain events) · Redis/BullMQ (jobs) ────┘
        each service ──▶ its own PostgreSQL database     download ──▶ MinIO     search ──▶ OpenSearch
```

- **Web** renders on the server and talks only to the API Gateway. It holds no secrets in client
  bundles; server-side configuration is validated in `apps/web/src/lib/env.ts`.
- **API Gateway** is the only public HTTP entry point. All public routes are versioned under
  `/api/v1`. It applies rate limiting and aggregates service health.
- **Backend services** are independent NestJS applications. Each owns its data and is
  deployable on its own.

## Service responsibilities

| Service              | Port | Owns                                                                 |
| -------------------- | ---- | -------------------------------------------------------------------- |
| api-gateway          | 4000 | No data. Authentication, routing, rate limiting, health aggregation  |
| identity-service     | 4001 | Users, roles, permissions, audit log (Keycloak as identity provider) |
| cve-service          | 4002 | CVE records, CVSS v3.1/v4.0, CWE, affected products, references      |
| intelligence-service | 4003 | Source adapters, synchronisation state and logs, raw source records  |
| asset-service        | 4004 | Vendors, products, CPE names, CVE-to-product associations, analytics |
| poc-service          | 4005 | PoC metadata, source repositories, CVE associations, verification    |
| download-service     | 4006 | Download jobs, artifacts, hashes, scan results, quarantine, MinIO    |
| exploit-service      | 4007 | Exploit records and CVE/exploit/PoC relationships                    |
| reporting-service    | 4008 | Read models for dashboards and generated reports                     |
| notification-service | 4009 | Notification rules, subscriptions, delivery history                  |

## Data ownership

- Every service has its own PostgreSQL database **and** login role with the same name
  (`cve-service` → `cve_service`). `infra/postgres/init/01-service-databases.sh` creates them,
  revokes `PUBLIC` access and gives each role ownership of only its own database.
- Services validate at startup that `DATABASE_URL` points to their own database with their own
  role (`assertServiceOwnsDatabase` in `@cve/database`), so a misconfiguration fails fast.
- Cross-service relationships use stable external identifiers (e.g. CVE IDs, artifact UUIDs),
  never foreign keys or joins across databases.
- Prisma schemas and migrations live inside each service (`services/<name>/prisma`) starting with
  the phase that introduces the service's first model.

## Communication

- **Synchronous:** HTTP/JSON between the gateway and services, using the envelopes from
  `@cve/contracts` (`{ data }`, `{ data, meta }` for pagination, `{ error, correlationId, timestamp }`).
- **Asynchronous:** RabbitMQ domain events using `domainEventEnvelopeSchema`
  (`eventType` = `<domain>.<entity>.<action>`, versioned, with producer and correlation ID),
  implemented by `@cve/messaging`: confirmed publishing to the `cve.events` topic exchange,
  per-consumer quorum queues with delayed retries and dead-letter queues, idempotent consumers and
  an outbox relay. Important events go through a per-service outbox table (the first store
  implementation arrives with the first event-producing feature). See [messaging.md](messaging.md).
- **Background jobs:** BullMQ on Redis for retryable and scheduled work (synchronisation,
  downloads, reports), implemented by `@cve/jobs` with service-scoped key prefixes that match each
  service's Redis ACL.

## Cross-cutting conventions (implemented in Phase 0)

| Concern          | Implementation                                                                              |
| ---------------- | ------------------------------------------------------------------------------------------- |
| Configuration    | `@cve/config`: Zod schemas, fail-fast `loadEnv`, error messages never include values        |
| Logging          | `@cve/logger`: Pino JSON with ISO time, service name, secret redaction, Nest adapter        |
| Correlation IDs  | `x-correlation-id` accepted when log-safe, otherwise generated; echoed and logged           |
| Security headers | helmet with a `default-src 'none'` CSP for APIs (relaxed only for `/api/v1/docs`)           |
| CORS             | Explicit origin allowlist; wildcards rejected at startup                                    |
| Rate limiting    | `@nestjs/throttler` at the gateway (defaults in `@cve/security`), plus Nginx `limit_req`    |
| Errors           | Global filter producing `{ error: { code, message, details? }, correlationId, timestamp }`  |
| Body size        | JSON bodies limited to 1 MB                                                                 |
| OpenAPI          | `@nestjs/swagger`, served at `/api/v1/docs` when `SWAGGER_ENABLED=true`                     |
| Health           | `HealthModule` with pluggable indicators; readiness returns 503 when a critical one is down |

Readiness indicators currently verify TCP reachability of PostgreSQL, RabbitMQ and Redis. They will
be replaced by protocol-level checks (`SELECT 1`, AMQP channel, `PING`) once each service owns real
clients for those dependencies.

## Shared packages

| Package          | Depends on                                         | Used by                   |
| ---------------- | -------------------------------------------------- | ------------------------- |
| `@cve/contracts` | zod                                                | everything                |
| `@cve/config`    | zod                                                | services, gateway         |
| `@cve/logger`    | pino                                               | shared, services, gateway |
| `@cve/security`  | helmet                                             | shared, gateway           |
| `@cve/database`  | —                                                  | services                  |
| `@cve/shared`    | contracts, config, logger, security, NestJS (peer) | services, gateway         |
| `@cve/testing`   | NestJS testing, supertest, unplugin-swc            | tests only                |
| `@cve/messaging` | contracts, logger, amqplib                         | services                  |
| `@cve/jobs`      | contracts, logger, bullmq, ioredis                 | services                  |
| `@cve/auth`      | contracts, logger, shared, jose, NestJS (peer)     | services, gateway         |

Packages are ESM, compiled with `tsc` to `dist/`, and built before dependants by Turborepo
(`dependsOn: ["^build"]`). Shared packages contain no business logic.

## TypeScript and tooling

- `tsconfig.base.json`: `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`,
  `noPropertyAccessFromIndexSignature`, `verbatimModuleSyntax`, NodeNext modules.
- `tsconfig.nest.json` adds decorator metadata for NestJS workspaces.
- ESLint uses `typescript-eslint` `strictTypeChecked` + `stylisticTypeChecked`, `no-explicit-any`,
  the Next.js plugin for the web app and Prettier compatibility.
- Vitest runs NestJS tests through SWC (`@cve/testing/vitest`) because esbuild does not emit
  decorator metadata.

## Security notes for later phases

Authentication, RBAC and audit logging (Phase 1) are described in [identity.md](identity.md): every
service validates Keycloak access tokens itself with `@cve/auth` (zero trust between the gateway and
services), routes are private by default, and permissions are derived from roles by a static mapping
in `@cve/contracts`.

The PoC Service (Phase 5, [poc-service.md](poc-service.md)) stores repository metadata and file
listings only: it never fetches file contents, clones or archives, scores CVE associations instead of
trusting repository text, and hides artifacts judged malicious from users without `quarantine:read`.

The following are specified in `CLAUDE.md` and are deliberately not implemented yet: web login, download hardening and
quarantine (Phase 6), TLS termination, metrics and backups (Phase 10). Downloaded PoC content will
never be executed or automatically extracted.
