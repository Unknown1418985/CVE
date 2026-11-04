# Infrastructure

The platform runs on Docker Compose ([`compose.yaml`](../compose.yaml)). Configuration and every
secret come from `.env`, which is generated locally and never committed.

```bash
pnpm install && pnpm build
pnpm env:generate                                          # .env with random secrets + per-app dev .env files
docker compose up -d --build                               # data stores, Keycloak, provisioning jobs
pnpm infra:wait                                            # blocks until healthy / provisioned
docker compose --profile apps up -d --build                # + gateway, 9 services, web, Nginx → http://localhost:8080
docker compose --profile observability up -d               # + Prometheus, Grafana → http://localhost:3001
```

`pnpm env:generate` keeps existing files; pass `-- --force` to regenerate. Compose refuses to start
when a required variable is missing.

## Components

| Component  | Image                                    | Role                                                          |
| ---------- | ---------------------------------------- | ------------------------------------------------------------- |
| PostgreSQL | `postgres:17-alpine`                     | One database and login role per service, plus Keycloak        |
| Redis      | `redis:7.4-alpine`                       | BullMQ queues, caches, idempotency keys (ACL users)           |
| RabbitMQ   | `rabbitmq:4.1-management-alpine`         | Domain events (`cve` vhost, quorum queues)                    |
| OpenSearch | `opensearchproject/opensearch:2.19.1`    | Search, TLS with a local CA, security plugin                  |
| MinIO      | `${MINIO_IMAGE}`                         | Artifact and report storage (see [MinIO image](#minio-image)) |
| Keycloak   | `keycloak/keycloak:26.4`                 | OIDC provider, realm `cve-platform`, served under `/auth`     |
| Nginx      | `nginx:1.28-alpine`                      | Reverse proxy for web, API and Keycloak; unprivileged         |
| Prometheus | `prom/prometheus:v3.5.0`                 | Metrics and alert rules                                       |
| Grafana    | `grafana/grafana:12.1.0`                 | Provisioned datasource and infrastructure dashboard           |
| Exporters  | postgres-exporter, redis_exporter, nginx | Metrics for components without a native endpoint              |

One-shot jobs run before the services start and exit with status 0:

| Job                 | Does                                                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `opensearch-init`   | Creates a local CA and node certificate (once), renders the security config with an `admin` hash                                |
| `minio-init`        | Creates buckets (versioned, private), per-service users and bucket policies (`infra/minio`)                                     |
| `infra-provisioner` | TypeScript (`tools/infra-provisioner`): RabbitMQ vhost, events exchange, users, permissions, limits; OpenSearch roles and users |

All jobs are idempotent, so rerunning them after changing `.env` rotates passwords (except the
PostgreSQL roles and the OpenSearch `admin` user, see [Rotating secrets](#rotating-secrets)).

## Network isolation

```
                 127.0.0.1:8080                                   127.0.0.1:3001
                      │                                                 │
   public ──────── nginx ─────────┐                          ops ── grafana
                      │           │                                     │
   frontend*   web · api-gateway · keycloak                              │
                         │            │                                 │
   backend*      api-gateway · services · keycloak                       │
                                 │      │                               │
   data*   postgres · redis · rabbitmq · opensearch · minio · keycloak   │
           services · provisioning jobs · exporters                      │
                                                                        │
   observability*  prometheus · grafana · exporters · every scrape target
   egress          intelligence · poc · download · exploit · notification services
                                                        * internal: no internet, no published ports
```

- Only Nginx and Grafana publish ports, and only on `127.0.0.1`. Data stores, brokers, Keycloak
  and Prometheus have no published port.
- `data`, `backend`, `frontend` and `observability` are `internal` networks: containers on them
  have no route to the internet. Only the five services that talk to external sources join
  `egress`. The web app and the gateway cannot reach any data store.
- The Nginx admin and metrics listener (`:8081`) is internal. Nginx does not proxy the Keycloak
  admin console or admin API (`/auth/admin` → 404), nor any `/metrics` endpoint.
- `compose.dev.yaml` is a development-only override that publishes the infrastructure ports on
  `127.0.0.1` (and Keycloak on 8180) so services can run on the host with `pnpm dev`.

These rules are enforced by static tests in `tools/infra-tests/test/static` (part of `pnpm test`).

## Credentials and least privilege

Every backend service gets its own credentials for each store, scoped to what it owns.

| Store      | Account                    | Scope                                                                                                                                 |
| ---------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| PostgreSQL | `<service>` (snake_case)   | Owns its database and `public` schema; no superuser/createdb/createrole; cannot connect to other databases, `postgres` or `template1` |
| PostgreSQL | `postgres_exporter`        | `pg_monitor`, connection limit 5                                                                                                      |
| PostgreSQL | `keycloak`                 | Owns the `keycloak` database                                                                                                          |
| Redis      | `<service>`                | Keys and channels `cve:<service>:*` only; no `@dangerous`/`@admin` commands (`KEYS`, `FLUSHALL`, `CONFIG`, `ACL`, …)                  |
| Redis      | `metrics` / `admin`        | Exporter introspection only / operators only; the `default` user is disabled                                                          |
| RabbitMQ   | `<service>` on vhost `cve` | Configure `^<service>\..*$`; write/read `cve.events` and its own resources; 10 connections, 200 channels; no management access        |
| RabbitMQ   | `${RABBITMQ_ADMIN_USER}`   | Administrator; `guest` does not exist                                                                                                 |
| MinIO      | `download-service`         | Put/get in `cve-poc-quarantine` only (cannot delete)                                                                                  |
| MinIO      | `poc-service`              | Read/delete quarantine, write `cve-poc-artifacts`                                                                                     |
| MinIO      | `reporting-service`        | `cve-reports` only                                                                                                                    |
| OpenSearch | `cve-service`              | `cve-*` indices (CRUD, create, manage); no security API                                                                               |
| Keycloak   | `cve-identity-service`     | Service account with `view-users`, `query-users`, `manage-users`, `view-realm`                                                        |

The API Gateway has no data store credentials. Passwords live only in `.env`; Redis receives SHA-256
hashes in a tmpfs ACL file generated at start (`infra/redis/entrypoint.sh`), PostgreSQL stores SCRAM
hashes, OpenSearch stores a bcrypt hash of the admin password.

## Container hardening

- `cap_drop: [ALL]` and `no-new-privileges` on every container (the cert job re-adds only
  `CHOWN`, `DAC_OVERRIDE`, `FOWNER` and runs without a network).
- Read-only root filesystems with `tmpfs` scratch space for everything except OpenSearch and
  Keycloak, whose images write to their install directories at start.
- Non-root users: PostgreSQL, Redis, RabbitMQ, Nginx (uid 101), OpenSearch, Keycloak, Grafana,
  Prometheus and all Node.js containers.
- CPU, memory and PID limits on every long-running container; JSON log rotation (3 × 10 MB).

## Persistent volumes

`postgres-data`, `redis-data` (AOF + snapshots), `rabbitmq-data`, `opensearch-data`, `minio-data`
(versioned buckets), `prometheus-data` (15 days / 4 GB), `grafana-data`, plus
`opensearch-certs` (keystores), `opensearch-security` (security bootstrap config) and `platform-ca`
(public CA certificate mounted read-only into clients). `docker compose down -v` deletes them all.

## Health checks

| Container                       | Check                                                                |
| ------------------------------- | -------------------------------------------------------------------- |
| PostgreSQL                      | `pg_isready`                                                         |
| Redis                           | `PING` as `admin`                                                    |
| RabbitMQ                        | `check_running` and `check_port_connectivity`                        |
| OpenSearch                      | Cluster health ≥ yellow over HTTPS, verified against the platform CA |
| MinIO                           | `mc ready local`                                                     |
| Keycloak                        | `/auth/health/ready` on the management port                          |
| Node.js services                | `/api/v1/health/live`; readiness at `/api/v1/health/ready`           |
| Web, Nginx, Prometheus, Grafana | HTTP health endpoints                                                |

Services start only after their stores are healthy and the provisioning jobs have completed
(`service_completed_successfully`). `pnpm infra:wait` waits for the same conditions (Compose's own
`--wait` treats finished jobs as failures).

## Service environment

Compose injects, per service:

| Variable                                                                             | Services                               |
| ------------------------------------------------------------------------------------ | -------------------------------------- |
| `DATABASE_URL`, `REDIS_URL`, `RABBITMQ_URL`                                          | all backend services (own credentials) |
| `S3_ENDPOINT`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`                            | poc, download, reporting               |
| `OPENSEARCH_URL`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD`, `OPENSEARCH_CA_FILE` | cve-service                            |
| `METRICS_PORT=9464`                                                                  | gateway and all services               |

Schemas live in `@cve/config` (`serviceEnvSchema`, `objectStorageEnvSchema`, `searchEnvSchema`)
and are validated at startup; error messages never contain values. Bucket names are constants in
`@cve/contracts` (`OBJECT_STORAGE_BUCKETS`).

For `pnpm dev`, `pnpm env:generate` writes `services/<name>/.env` and `apps/api-gateway/.env`
pointing at the ports published by `compose.dev.yaml`. The CVE Service additionally needs the CA:

```bash
mkdir -p .certs && docker compose exec -T opensearch cat config/certs/ca.pem > .certs/platform-ca.pem
```

## Messaging and jobs

- `@cve/messaging` — RabbitMQ publisher/consumer, retry topology and outbox relay.
- `@cve/jobs` — BullMQ queues, workers and schedulers.

See [messaging.md](messaging.md) for the topology and usage.

## Keycloak

The realm `cve-platform` is imported on first start from
`infra/keycloak/import/cve-platform-realm.json` (`${…}` placeholders are filled from the container
environment). It defines the platform roles as realm roles (composites: super-admin ⊃ administrator
⊃ security-analyst + vulnerability-researcher ⊃ viewer), a public `cve-web` client (authorization
code + PKCE S256 only), the `cve-api` audience with a `roles` claim, and the `cve-identity-service`
service account. Registration is disabled, brute-force protection and a strong password policy are
on, and login/admin events are recorded. The bootstrap admin (`KEYCLOAK_ADMIN_*`) uses the master
realm, which is reachable only from inside the networks (or via `compose.dev.yaml`).

Keycloak runs in production mode (`start`) with HTTP behind Nginx at `${KEYCLOAK_PUBLIC_URL}`
(default `http://localhost:8080/auth`). An existing realm is not re-imported; change it through
the admin API or recreate the `postgres-data` volume.

## Observability

Prometheus scrapes, over the internal network: itself, RabbitMQ (`:15692`, plus per-queue metrics
for the `cve` vhost), MinIO, Keycloak, postgres-exporter, redis-exporter, nginx-exporter and every
Node.js service on `:9464/metrics` (process metrics and `http_server_request_duration_seconds`).
Targets that are not running are reported as down, never hidden. OpenSearch has no built-in
Prometheus endpoint and is not scraped yet.

Alert rules (`infra/prometheus/rules`): target down, messages in any dead-letter queue, queue
backlog, RabbitMQ resource alarms, Redis memory (noeviction), PostgreSQL connection saturation and
service 5xx rate. Alertmanager is not deployed yet (Phase 10). Grafana provisions the Prometheus
datasource and the **CVE Platform — Infrastructure** dashboard; anonymous access and sign-up are
disabled.

## Rotating secrets

Change the value in `.env`, then:

- Redis, RabbitMQ service users, MinIO service users, OpenSearch service users: `docker compose up -d`
  (Redis regenerates its ACL on restart; the provisioning jobs re-apply passwords) and restart the
  affected services.
- PostgreSQL roles: `ALTER ROLE <name> PASSWORD '…'` as the superuser (init scripts only run on an
  empty volume).
- OpenSearch `admin`, Keycloak bootstrap admin, Grafana admin: change them in the respective admin
  API/UI; the environment values are only used on first initialisation.

## MinIO image

The MinIO project stopped publishing community images to Docker Hub. The default
`pgsty/minio` image is a community rebuild; set `MINIO_IMAGE` in `.env` to the image your
organisation has approved (for example an internally mirrored build) before relying on it. The
provisioning job uses the same image for `mc`.

## Testing

| Command                                                                      | Needs                                                     | Covers                                                                                                                                                                    |
| ---------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm test`                                                                  | nothing                                                   | Unit tests, including Compose policy checks and provisioning plans                                                                                                        |
| `pnpm compose:config`                                                        | Docker                                                    | Compose syntax for all profiles and the dev override                                                                                                                      |
| `pnpm test:integration`                                                      | stack with `compose.dev.yaml`                             | RabbitMQ publish/consume, retries, DLQ, dedup, reconnect, permissions; BullMQ retries, timeouts, schedules, Redis ACLs; PostgreSQL, MinIO, OpenSearch, Keycloak isolation |
| `INFRA_TEST_FULL_STACK=true pnpm --filter @cve/infra-tests test:integration` | `--profile apps --profile observability`, no dev override | Nothing but Nginx/Grafana reachable, routing, Keycloak through Nginx, all Prometheus targets up, dashboards and rules                                                     |

Example (development ports):

```bash
export COMPOSE_FILE=compose.yaml:compose.dev.yaml
docker compose up -d --build && pnpm infra:wait
mkdir -p .certs && docker compose exec -T opensearch cat config/certs/ca.pem > .certs/platform-ca.pem
pnpm test:integration
```

CI runs both modes in the `integration` job of `.github/workflows/ci.yml`.

## Known limitations

- No TLS on Nginx yet (Phase 10); it listens on `127.0.0.1` only. OpenSearch already uses TLS;
  PostgreSQL, Redis, RabbitMQ and MinIO traffic stays on internal networks without TLS.
- Single-node deployments of every store; no backups yet (Phase 10).
- OpenSearch needs `vm.max_map_count ≥ 262144` on the Docker host for production use and
  unlimited `memlock`; it logs a warning and continues when memory cannot be locked.
