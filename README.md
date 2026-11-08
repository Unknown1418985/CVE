# CVE Intelligence Platform

A self-hosted platform for vulnerability intelligence, exploit tracking, controlled
Proof-of-Concept collection and reporting. Everything is written in TypeScript and organised as a
pnpm + Turborepo monorepo of independently deployable services.

> **Status:** Keycloak authentication, RBAC and audit logging, the CVE, Intelligence, Asset, PoC,
> Download and Exploit services are implemented as APIs, and the web interface covers all of them
> (see [docs/web.md](docs/web.md)). The Reporting and Notification services have no API yet. See
> [Roadmap](#roadmap) and [`CLAUDE.md`](CLAUDE.md).

## Repository layout

```
apps/
  web/                    Next.js frontend (App Router, Tailwind CSS, shadcn/ui conventions)
  api-gateway/            NestJS public entry point (/api/v1, rate limiting, health aggregation)
services/
  identity-service/       Authentication, RBAC, audit logging
  cve-service/            CVE records, CVSS, CWE, affected products
  intelligence-service/   NVD, MITRE, CISA KEV, EPSS, GitHub, Exploit-DB adapters
  asset-service/          Vendor and product intelligence
  poc-service/            PoC discovery and metadata
  download-service/       Secure artifact downloads and MinIO storage
  exploit-service/        Exploit intelligence and CVE relationships
  reporting-service/      Dashboards, analytics, reports
  notification-service/   Notifications
packages/
  contracts/              Zod schemas: API envelopes, pagination, health, events, roles, permissions, identity API
  auth/                   Keycloak JWT validation, session introspection, NestJS authentication/RBAC guards
  config/                 Environment variable schemas and fail-fast validation
  logger/                 Pino structured logging with redaction + NestJS adapter
  security/               Security headers (helmet), strict CORS, correlation IDs, rate-limit defaults
  database/               Database ownership rules and connection helpers
  shared/                 NestJS runtime: bootstrap, HTTP conventions, health module, error filter
  testing/                Vitest presets (SWC for decorators), NestJS HTTP harness, integration helpers
  messaging/              RabbitMQ domain events: publisher, consumer with retries/DLQ, outbox relay
  jobs/                   BullMQ queues, workers and schedulers with validated payloads
tools/
  infra-provisioner/      RabbitMQ/OpenSearch provisioning, `env:generate`, `infra:wait`
  infra-tests/            Compose policy tests and live infrastructure tests
infra/                    Dockerfiles and configuration for every infrastructure component
docs/                     Architecture, infrastructure and messaging documentation
```

## Requirements

- Node.js 22.12+ (see `.nvmrc`)
- pnpm 10 (`corepack enable`)
- Docker with Compose v2 (for the infrastructure stack)

## Getting started

```bash
corepack enable
pnpm install
pnpm build
pnpm env:generate               # .env with random per-service secrets (never committed)
                      # build all packages and apps
pnpm typecheck
pnpm lint
pnpm test
```

### Run the infrastructure

```bash
docker compose up -d --build    # PostgreSQL, Redis, RabbitMQ, OpenSearch, MinIO, Keycloak + provisioning
pnpm infra:wait
```

Nothing but Nginx and Grafana is published to the host. For `pnpm dev`, add the development
override, which publishes the infrastructure ports on 127.0.0.1:
`docker compose -f compose.yaml -f compose.dev.yaml up -d --build`. See
[docs/infrastructure.md](docs/infrastructure.md).

### Run the applications

Either locally in watch mode (`pnpm env:generate` wrote each service's own `.env`):

```bash
pnpm dev
```

or fully containerised behind Nginx at <http://localhost:8080>:

```bash
docker compose --profile apps up -d --build
docker compose --profile observability up -d   # Prometheus, exporters, Grafana (127.0.0.1:3001)
```

## Health endpoints

Every NestJS service exposes:

| Path                   | Purpose                                                |
| ---------------------- | ------------------------------------------------------ |
| `/api/v1/health/live`  | Liveness (process is up)                               |
| `/api/v1/health/ready` | Readiness (dependencies reachable); HTTP 503 when down |
| `/api/v1/health`       | Same as readiness                                      |

The API Gateway also exposes `/api/v1/health/services`, which aggregates the readiness of every
backend service (status only for anonymous callers). Every other endpoint requires a Keycloak
access token; see [docs/identity.md](docs/identity.md). The web app exposes `/api/health` and signs
users in through its own backend-for-frontend routes; see [docs/web.md](docs/web.md). Default ports: gateway `4000`, services
`4001`–`4009` (see `packages/contracts/src/services.ts`), web `3000`.

## Workspace scripts

| Command                 | Description                                                    |
| ----------------------- | -------------------------------------------------------------- |
| `pnpm build`            | Build everything with Turborepo                                |
| `pnpm dev`              | Run all apps and services in watch mode                        |
| `pnpm typecheck`        | Strict TypeScript checks for every workspace                   |
| `pnpm lint`             | ESLint (typescript-eslint strict, type-aware)                  |
| `pnpm test`             | Vitest in every workspace                                      |
| `pnpm format`           | Prettier                                                       |
| `pnpm compose:config`   | Validate the Docker Compose file with `.env.example`           |
| `pnpm env:generate`     | Create `.env` and per-app dev `.env` files with random secrets |
| `pnpm infra:wait`       | Wait until the Compose stack is healthy and provisioned        |
| `pnpm test:integration` | Live tests against the running stack (see docs)                |

Run a single workspace with `pnpm --filter @cve/<name> <script>`.

## Documentation

- [Architecture](docs/architecture.md)
- [Infrastructure](docs/infrastructure.md)
- [Messaging and background jobs](docs/messaging.md)
- [Identity, authentication and authorization](docs/identity.md)
- [CVE Service](docs/cve-service.md)
- [Exploit Service](docs/exploit-service.md)
- [Development specification](CLAUDE.md)

## Roadmap

| Phase | Scope                                                | Status     |
| ----- | ---------------------------------------------------- | ---------- |
| 0     | Monorepo and infrastructure foundation               | Done       |
| 1     | Authentication, authorization, audit logging         | Done (API) |
| 2     | CVE Service and database                             | Done (API) |
| 3     | NVD, MITRE, CISA and EPSS integrations               | Done (API) |
| 4     | Asset and product intelligence                       | Done (API) |
| 5     | PoC discovery and metadata management                | Done (API) |
| 6     | Secure automated downloads and MinIO storage         | Done (API) |
| 7     | Exploit intelligence                                 | Done (API) |
| 8     | Dashboard and analytics                              | Web UI     |
| 9     | Reporting and notifications                          | Planned    |
| 10    | Production hardening, backup, monitoring, deployment | Planned    |
