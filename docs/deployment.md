# Production deployment

The platform is deployed with Docker Compose on a single host: [`compose.yaml`](../compose.yaml)
plus the production overlay [`compose.prod.yaml`](../compose.prod.yaml). Read the
[production readiness report](production-readiness.md) first: it lists what still blocks a
production go-live.

## What the production overlay changes

| Area           | Development (`compose.yaml`)    | Production (`+ compose.prod.yaml`)                                                                 |
| -------------- | ------------------------------- | -------------------------------------------------------------------------------------------------- |
| Entry point    | Nginx, HTTP on `127.0.0.1:8080` | Nginx on 80 and 443 (`PUBLIC_BIND_ADDRESS`), TLS 1.2/1.3, HSTS, HTTP→HTTPS, unknown hosts rejected |
| Host name      | any                             | only `PUBLIC_HOSTNAME`; other `Host`/SNI values get no certificate (TLS) or a closed connection    |
| Images         | built locally, tagged `:local`  | `${IMAGE_REGISTRY}/cve-platform-<name>:${IMAGE_TAG}` pulled from your registry                     |
| Public URLs    | `localhost` defaults            | `PUBLIC_ORIGIN`, `KEYCLOAK_PUBLIC_URL` required (Compose refuses to start without them)            |
| OpenAPI docs   | `SWAGGER_ENABLED` from `.env`   | always off                                                                                         |
| Alerting       | webhook optional                | `ALERTMANAGER_WEBHOOK_URL` required                                                                |
| Restart policy | `unless-stopped`                | `always`                                                                                           |

Everything else (internal networks, least-privilege credentials, read-only containers, resource
limits, health checks) is identical; see [infrastructure.md](infrastructure.md).

## Host requirements

- Linux with Docker Engine 24+ and Docker Compose **2.24 or later** (the overlay uses `!override`).
- 4 vCPU, 12 GB RAM minimum for all profiles (the sum of the container memory limits is about 9 GB),
  SSD storage sized for PostgreSQL, MinIO artifacts and 15 days of Prometheus data.
- `sysctl vm.max_map_count=262144` (OpenSearch), persisted in `/etc/sysctl.d/`.
- Inbound 80/443 only. Grafana stays on `127.0.0.1:3001`; reach it through an SSH tunnel or a VPN.
- Outbound HTTPS for the source-synchronising services (NVD, MITRE, CISA, FIRST, GitHub, ClamAV
  signature updates). Restrict it at the host firewall or an egress proxy where possible.
- `age` for backups, Node.js 22 and pnpm only if you run `pnpm deploy:preflight` on the host
  (or run the preflight from a checkout on an admin machine with a copy of `.env`).
- Full-disk encryption for the Docker data root and the backup disk is strongly recommended
  (PostgreSQL, Redis, RabbitMQ and MinIO do not encrypt data at rest themselves).

## 1. Build and publish images

On CI or a build host, from a clean checkout of the release commit:

```bash
export COMPOSE_FILE=compose.yaml:compose.prod.yaml
export IMAGE_REGISTRY=registry.example.com/cve-platform IMAGE_TAG=$(git rev-parse --short=12 HEAD)
# Compose resolves every required variable even when only building; placeholders are fine here.
cp .env.example .env.build
cat >> .env.build <<EOF
PUBLIC_HOSTNAME=build.invalid
PUBLIC_ORIGIN=https://build.invalid
KEYCLOAK_PUBLIC_URL=https://build.invalid/auth
TLS_CERT_DIR=/nonexistent
ALERTMANAGER_WEBHOOK_URL=https://build.invalid/
EOF
docker compose --env-file .env.build --profile apps build
docker compose --env-file .env.build --profile apps push
```

Use an immutable tag (release version or commit SHA, never `latest`). Scan the images before
promoting them (for example `trivy image --severity HIGH,CRITICAL <image>`); the repository's CI
does not do this yet.

## 2. Prepare the host

```bash
git clone https://github.com/<org>/CVE.git /opt/cve-platform && cd /opt/cve-platform
git checkout <release commit>
pnpm install --frozen-lockfile && pnpm env:generate     # .env with random secrets (mode 600)
```

Edit `.env` and set at least:

| Variable                              | Value                                                              |
| ------------------------------------- | ------------------------------------------------------------------ |
| `PUBLIC_HOSTNAME`                     | `cve.example.com`                                                  |
| `PUBLIC_ORIGIN`                       | `https://cve.example.com`                                          |
| `KEYCLOAK_PUBLIC_URL`                 | `https://cve.example.com/auth`                                     |
| `CORS_ALLOWED_ORIGINS`                | `https://cve.example.com` (remove the localhost entries)           |
| `IMAGE_REGISTRY`, `IMAGE_TAG`         | as built above                                                     |
| `TLS_CERT_DIR`                        | directory with `fullchain.pem` and `privkey.pem`                   |
| `MINIO_IMAGE`                         | the MinIO image your organisation approved (see infrastructure.md) |
| `ALERTMANAGER_WEBHOOK_URL`            | your alert receiver (see [monitoring.md](monitoring.md))           |
| `BACKUP_AGE_RECIPIENTS`, `BACKUP_DIR` | see [disaster-recovery.md](disaster-recovery.md)                   |
| `NVD_API_KEY`, `GITHUB_TOKEN`         | optional source credentials (higher quotas)                        |

Keep `.env` readable by root (or the deployment user) only. It holds every secret of the
deployment; back it up only through `infra/backup/backup.sh` (encrypted).

## 3. TLS certificates

Nginx reads `TLS_CERT_DIR/fullchain.pem` and `TLS_CERT_DIR/privkey.pem` (read-only, as uid 101,
so the key must be readable by that uid, for example `chown root:101 privkey.pem && chmod 640`).

**Let's Encrypt (HTTP-01, webroot):** the HTTP server answers `/.well-known/acme-challenge/` from
`ACME_WEBROOT_DIR` (default `./acme-webroot`) and redirects everything else.

```bash
# First issuance, before Nginx runs: standalone mode on port 80
certbot certonly --standalone -d cve.example.com
# Renewals while Nginx runs:
certbot renew --webroot -w /opt/cve-platform/acme-webroot \
  --deploy-hook 'cp /etc/letsencrypt/live/cve.example.com/{fullchain,privkey}.pem /etc/cve-platform/tls/ && chown root:101 /etc/cve-platform/tls/privkey.pem && chmod 640 /etc/cve-platform/tls/privkey.pem && cd /opt/cve-platform && docker compose restart nginx'
```

**Corporate PKI:** place the full chain (leaf first) and the key in `TLS_CERT_DIR` and restart
Nginx when they change. `pnpm deploy:preflight` fails when the certificate does not cover
`PUBLIC_HOSTNAME` or expires within 7 days, and warns 21 days ahead.

## 4. Preflight

```bash
pnpm deploy:preflight
```

It fails on placeholder or short secrets, non-HTTPS or inconsistent public URLs, wildcard or
HTTP CORS origins, mutable image tags, a missing alert receiver, missing backup encryption, an
invalid or expiring certificate and an old Docker Compose; it warns about an unpinned MinIO image,
enabled Exploit-DB downloads, verbose logging and `vm.max_map_count`.

## 5. Start

```bash
export COMPOSE_FILE=compose.yaml:compose.prod.yaml
docker compose --profile apps --profile observability pull
docker compose --profile apps --profile observability up -d --no-build
pnpm infra:wait
docker compose ps
curl -fsS https://cve.example.com/api/v1/health/live
```

Database migrations run automatically (`<service>-migrate` jobs) before each service starts.

## 6. First sign-in

1. Open the Keycloak admin console through an SSH tunnel (Nginx does not route it). On the host,
   find the container address with
   `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' cve-platform-keycloak-1`,
   then from your machine run `ssh -L 8180:<address>:8180 <host>` and open
   `http://localhost:8180/auth/admin/`.
   Sign in with `KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASSWORD`, then **create a permanent
   admin user and delete the bootstrap admin**.
2. In realm `cve-platform`, create users and assign platform roles (`super-admin`,
   `administrator`, `security-analyst`, `vulnerability-researcher`, `viewer`).
3. Enable two-factor authentication: Authentication → Required actions → enable
   **Configure OTP** (or WebAuthn) and set it as a default action, or require it for
   administrator roles through a conditional flow. The realm import does not enforce MFA.
4. Change the Grafana admin password on first sign-in.

## 7. Operate

- Backups: schedule `infra/backup/backup.sh` hourly and `verify.sh` daily
  ([disaster-recovery.md](disaster-recovery.md)).
- Monitoring and alerts: [monitoring.md](monitoring.md).
- Logs: every container logs JSON to Docker's `json-file` driver (3 × 10 MB per container).
  Ship them to central storage (Loki, Elasticsearch, a SIEM) with your log agent; the audit events
  (`"audit": true`) should go to the SIEM.
- Secret rotation: [infrastructure.md](infrastructure.md#rotating-secrets).

## Upgrading

1. Take a backup and verify it.
2. Build and push the new images with a new `IMAGE_TAG`.
3. On the host: `git checkout <new release>`, update `IMAGE_TAG` in `.env`, `pnpm deploy:preflight`.
4. `docker compose --profile apps --profile observability pull && docker compose --profile apps --profile observability up -d --no-build`.
   Migrations run before the new service versions start. Services drain on shutdown: readiness
   turns `down` as soon as a service starts stopping.
5. Roll back by restoring the previous `IMAGE_TAG`. Prisma migrations are forward-only: if the
   new release migrated a database, roll back by restoring the backup taken in step 1.

## Known limitations of this deployment model

- Single host, single instance of every component: no high availability. A host failure means
  restoring from backup ([disaster-recovery.md](disaster-recovery.md)).
- The gateway's rate limiter keeps counters in memory; with several gateway replicas each enforces
  its own budget (Nginx's per-IP limits still apply).
- Internal traffic (PostgreSQL, Redis, RabbitMQ, MinIO) is not encrypted; it never leaves the
  host's internal Docker networks. Encrypt it before splitting the stack across hosts.
- Secrets reach containers as environment variables (visible to anyone with Docker access on the
  host, which is root-equivalent anyway). Docker secrets or an external secret manager are a
  planned improvement.
