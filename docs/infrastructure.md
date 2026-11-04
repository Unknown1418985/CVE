# Infrastructure

The local stack is defined in [`compose.yaml`](../compose.yaml) and configured through `.env`
(start from [`.env.example`](../.env.example)). Compose refuses to start when a required secret is
missing.

## Profiles

| Command                                        | Starts                                                        |
| ---------------------------------------------- | ------------------------------------------------------------- |
| `docker compose up -d`                         | PostgreSQL, Redis, RabbitMQ, OpenSearch, MinIO, Keycloak      |
| `docker compose --profile apps up -d --build`  | + API Gateway, 9 services, web, Nginx (http://localhost:8080) |
| `docker compose --profile observability up -d` | + Prometheus (9090), Grafana (3001)                           |

All published ports are bound to `127.0.0.1`. Application containers are not published; they are
reached through Nginx.

## Components

| Component  | Image                                 | Notes                                                        |
| ---------- | ------------------------------------- | ------------------------------------------------------------ |
| PostgreSQL | `postgres:17-alpine`                  | One database + role per service, created on first start      |
| Redis      | `redis:7.4-alpine`                    | Password required, AOF persistence                           |
| RabbitMQ   | `rabbitmq:4.1-management-alpine`      | Management UI on 15672                                       |
| OpenSearch | `opensearchproject/opensearch:2.19.1` | Single node, security plugin enabled (HTTPS, admin password) |
| MinIO      | `${MINIO_IMAGE}`                      | See the note below                                           |
| Keycloak   | `keycloak/keycloak:26.4`              | `start-dev`, stores data in its own `keycloak` database      |
| Nginx      | `nginx:1.28-alpine`                   | Reverse proxy; HTTP only until TLS is added in Phase 10      |
| Prometheus | `prom/prometheus:v3.5.0`              | Scrapes only itself until services expose metrics            |
| Grafana    | `grafana/grafana:12.1.0`              | Prometheus datasource provisioned                            |

### MinIO image

The MinIO project stopped publishing community images to Docker Hub. The default
`pgsty/minio` image is a community rebuild; set `MINIO_IMAGE` in `.env` to the image your
organisation has approved (for example an internally mirrored build) before relying on it.

## Application containers

- Built with `infra/docker/node-service.Dockerfile` (`--build-arg PACKAGE=@cve/<name>`) and
  `infra/docker/web.Dockerfile`. Builds use `turbo prune` and `pnpm deploy`, so each image only
  contains its own package and production dependencies.
- Containers run as the unprivileged `node` user under `tini`, with a read-only root filesystem,
  `no-new-privileges`, all Linux capabilities dropped, CPU/memory limits and health checks against
  `/api/v1/health/live` (web: `/api/health`).

## PostgreSQL least privilege

`infra/postgres/init/01-service-databases.sh` runs once when the data volume is initialised. For
each service it creates a `LOGIN` role without superuser, create-db, create-role or replication
rights, a database owned by that role, revokes `PUBLIC` access to the database and `CREATE` on its
`public` schema. Changing a password in `.env` later does not update an existing volume; use
`ALTER ROLE` or recreate the volume.

## Validation

```bash
pnpm compose:config     # docker compose --env-file .env.example config --quiet
```
