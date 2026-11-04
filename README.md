# CVE Intelligence Platform

A self-hosted platform for vulnerability intelligence, exploit tracking, controlled
Proof-of-Concept collection and reporting. Everything is written in TypeScript and organised as a
pnpm + Turborepo monorepo of independently deployable services.

> **Status: Phase 0 (foundation).** The repository contains the monorepo, shared packages, service
> skeletons with health endpoints, the web shell and the local infrastructure stack. No business
> features exist yet. See [Roadmap](#roadmap) and [`CLAUDE.md`](CLAUDE.md) for the full specification.

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
  contracts/              Zod schemas: API envelopes, pagination, health, events, roles, service registry
  config/                 Environment variable schemas and fail-fast validation
  logger/                 Pino structured logging with redaction + NestJS adapter
  security/               Security headers (helmet), strict CORS, correlation IDs, rate-limit defaults
  database/               Database ownership rules and connection helpers
  shared/                 NestJS runtime: bootstrap, HTTP conventions, health module, error filter
  testing/                Vitest presets (SWC for decorators) and NestJS HTTP test harness
infra/                    Dockerfiles, PostgreSQL init, Nginx, Prometheus, Grafana
docs/                     Architecture and infrastructure documentation
```

## Requirements

- Node.js 22.12+ (see `.nvmrc`)
- pnpm 10 (`corepack enable`)
- Docker with Compose v2 (for the infrastructure stack)

## Getting started

```bash
corepack enable
pnpm install
cp .env.example .env            # then replace every change-me value

pnpm build                      # build all packages and apps
pnpm typecheck
pnpm lint
pnpm test
```

### Run the infrastructure

```bash
docker compose up -d            # PostgreSQL, Redis, RabbitMQ, OpenSearch, MinIO, Keycloak
```

### Run the applications

Either locally in watch mode (each service also needs its own `DATABASE_URL`, see `.env.example`):

```bash
pnpm dev
```

or fully containerised behind Nginx at <http://localhost:8080>:

```bash
docker compose --profile apps up -d --build
docker compose --profile observability up -d   # Prometheus (9090) and Grafana (3001)
```

## Health endpoints

Every NestJS service exposes:

| Path                   | Purpose                                                |
| ---------------------- | ------------------------------------------------------ |
| `/api/v1/health/live`  | Liveness (process is up)                               |
| `/api/v1/health/ready` | Readiness (dependencies reachable); HTTP 503 when down |
| `/api/v1/health`       | Same as readiness                                      |

The API Gateway also exposes `/api/v1/health/services`, which aggregates the readiness of every
backend service. The web app exposes `/api/health`. Default ports: gateway `4000`, services
`4001`–`4009` (see `packages/contracts/src/services.ts`), web `3000`.

## Workspace scripts

| Command               | Description                                          |
| --------------------- | ---------------------------------------------------- |
| `pnpm build`          | Build everything with Turborepo                      |
| `pnpm dev`            | Run all apps and services in watch mode              |
| `pnpm typecheck`      | Strict TypeScript checks for every workspace         |
| `pnpm lint`           | ESLint (typescript-eslint strict, type-aware)        |
| `pnpm test`           | Vitest in every workspace                            |
| `pnpm format`         | Prettier                                             |
| `pnpm compose:config` | Validate the Docker Compose file with `.env.example` |

Run a single workspace with `pnpm --filter @cve/<name> <script>`.

## Documentation

- [Architecture](docs/architecture.md)
- [Infrastructure](docs/infrastructure.md)
- [Development specification](CLAUDE.md)

## Roadmap

| Phase | Scope                                                | Status      |
| ----- | ---------------------------------------------------- | ----------- |
| 0     | Monorepo and infrastructure foundation               | In progress |
| 1     | Authentication, authorization, audit logging         | Planned     |
| 2     | CVE Service and database                             | Planned     |
| 3     | NVD, MITRE, CISA and EPSS integrations               | Planned     |
| 4     | Asset and product intelligence                       | Planned     |
| 5     | PoC discovery and metadata management                | Planned     |
| 6     | Secure automated downloads and MinIO storage         | Planned     |
| 7     | Exploit intelligence                                 | Planned     |
| 8     | Dashboard and analytics                              | Planned     |
| 9     | Reporting and notifications                          | Planned     |
| 10    | Production hardening, backup, monitoring, deployment | Planned     |
