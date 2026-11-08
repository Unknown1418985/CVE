# Production readiness report

Review date: 2026-11-08. Scope: the whole repository at the merge of PR #12 (Phases 0–8), plus
the Phase 10 hardening added with this report.

## Verdict

**Not ready for production.** The security controls around untrusted content, isolation and
authentication are strong, and this change closes the operational gaps (TLS, alerting, backups,
production configuration). Four findings still block a go-live:

| #   | Blocker                                                                                                                                         | Severity            | Why it blocks                                                                                              |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------- |
| B1  | Privileged accounts have no multi-factor authentication                                                                                         | High (security)     | Administrators can release quarantined malware and manage users; a phished password is enough today        |
| B2  | Container supply chain: MinIO runs from an unofficial community rebuild, base images are not pinned by digest, images are not scanned or signed | High (security)     | A compromised or unmaintained image would run with access to every stored artifact                         |
| B3  | The CVE Service does not consume Intelligence Service events, so NVD/MITRE/CISA/EPSS data never reaches the CVE database                        | Critical (function) | The platform's core data set stays empty unless CVEs are created through the API                           |
| B4  | No source adapter or download has run against the real external APIs (NVD, MITRE, CISA KEV, EPSS, GitHub, Exploit-DB)                           | High (verification) | Rate limits, pagination, payload drift and terms could fail on first contact; nothing in CI exercises them |

B1 and B2 need decisions (below). B3 and B4 are feature and verification work for separate
threads; they are not hardening tasks.

## What this change adds

| Area                     | Change                                                                                                                                                                                                                                                                                           | Verified by                                                                                                                                        |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| TLS and edge             | `compose.prod.yaml` + `infra/nginx/nginx.tls.conf`: TLS 1.2/1.3 (Mozilla intermediate), HSTS (2 years), HTTP→HTTPS redirect, ACME webroot, only `PUBLIC_HOSTNAME` served (unknown SNI rejected, unknown Host closed), shared route snippet for both configs                                      | `nginx -t` on both configs; live container: HSTS and security headers on HTTP/2, TLS 1.1 refused, unknown SNI refused, `/auth/admin` 404, redirect |
| Production configuration | Registry images with an immutable tag, required HTTPS public URLs (no localhost defaults), OpenAPI off, `restart: always`, required alert receiver                                                                                                                                               | `docker compose config` with the overlay; static policy tests                                                                                      |
| Preflight                | `pnpm deploy:preflight` (TypeScript): secrets, URL consistency, CORS, image tags, alerting, backup encryption, certificate host/expiry/key mode, Compose version, `vm.max_map_count`                                                                                                             | 6 unit tests; run against a failing and a passing configuration                                                                                    |
| Health                   | Readiness fails as soon as shutdown starts (drain); gateway readiness checks Keycloak's signing keys; readiness exported as `service_ready` / `service_dependency_up`                                                                                                                            | Unit and HTTP tests                                                                                                                                |
| Metrics                  | `@cve/metrics` (process-wide registry). Events published/consumed by outcome, handler latency, outbox backlog and age, relay results, BullMQ outcomes, durations and queue depth, auth rejections by reason, downloads by outcome and SSRF/policy code, scan results, source sync runs           | Unit tests per package; label values bounded                                                                                                       |
| Alerting                 | Alertmanager (internal, webhook from a private file), 21 new rules: readiness, dependencies, restarts, latency, outbox, dead letters, jobs, IdP outage, auth failure and 403 spikes, rate limiting, SSRF/policy blocks, malware, artifact integrity, scanner errors, source sync, alert delivery | `promtool check config` (28 rules), `amtool check-config`; live: Prometheus → Alertmanager → webhook delivered firing `TargetDown` alerts          |
| Dashboards               | Services, Events/Jobs/Sources, Security (plus the existing Infrastructure)                                                                                                                                                                                                                       | Provisioned in a live Grafana 12.1; static test that every panel queries metrics defined in code                                                   |
| Logging                  | Uncaught exceptions are logged as structured JSON before exit                                                                                                                                                                                                                                    | Code review                                                                                                                                        |
| Backups                  | `infra/backup/{backup,verify,restore}.sh`: age-encrypted sets of every database, all buckets, RabbitMQ definitions and `.env`; checksums; retention; restore re-creates databases with the original least-privilege grants and restores as the service role                                      | Live drill (below)                                                                                                                                 |
| Documentation            | [deployment.md](deployment.md), [monitoring.md](monitoring.md), [disaster-recovery.md](disaster-recovery.md), updates to architecture and infrastructure                                                                                                                                         | —                                                                                                                                                  |

## Findings by area

Severity: Critical, High, Medium, Low. Status: **Fixed** (in this change), **Open**, **Accepted**
(documented limitation of the single-host model).

### Architecture and service communication

| Finding                                                                                                                                      | Severity | Status                     |
| -------------------------------------------------------------------------------------------------------------------------------------------- | -------- | -------------------------- |
| Services own their databases, communicate through the gateway (HTTP) and RabbitMQ events with a transactional outbox and inbox deduplication | —        | Good                       |
| CVE Service has no consumer for `intelligence.*` events (B3); the Asset Service's `cve_facts` projection stays empty for the same reason     | Critical | Open                       |
| Reporting and Notification services are skeletons (Phase 9 not built); the Reports page exports in the browser                               | Medium   | Open (planned phase)       |
| OpenSearch is deployed, provisioned and secured, but no service reads or writes it: resources and attack surface without function            | Medium   | Open                       |
| Cross-service event flows have never run with the full application stack and a live broker (the messaging package has live broker tests)     | Medium   | Open                       |
| CVSS v4.0 base scores are not computed locally (source score required)                                                                       | Low      | Open                       |
| Outbox backlog was invisible                                                                                                                 | Medium   | Fixed (metrics and alerts) |

### Authentication and authorization

| Finding                                                                                                                                                                                                    | Severity | Status                                               |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | ---------------------------------------------------- |
| Every service validates tokens itself (zero trust): asymmetric algorithm allowlist, issuer, audience, expiry, `typ`, optional session introspection; routes private by default; static role→permission map | —        | Good                                                 |
| No MFA requirement for any role, including super-admin and administrator (B1)                                                                                                                              | High     | Open                                                 |
| Keycloak bootstrap admin from `.env` stays until removed manually                                                                                                                                          | Medium   | Open (deployment step documented)                    |
| Authentication failures were only visible in logs                                                                                                                                                          | Medium   | Fixed (`auth_requests_rejected_total`, spike alerts) |
| Gateway reported ready while Keycloak was unreachable                                                                                                                                                      | Medium   | Fixed                                                |
| Keycloak login-failure metrics (user event metrics) are not enabled                                                                                                                                        | Low      | Open                                                 |

### Database isolation

One database and role per service, `PUBLIC` connect revoked, the owner owns `public`, startup
assertion that `DATABASE_URL` belongs to the service. The restore drill confirmed the isolation
survives a restore (`cve_service` cannot connect to `download_service`). No findings.

### API security

Versioned under `/api/v1`, Zod validation, 1 MB bodies, helmet CSP for APIs, strict CORS,
idempotency keys and `If-Match` on mutations, correlation IDs, gateway refuses dot segments and
encoded separators, relays a fixed header allowlist and limits relayed bodies to 10 MB.

| Finding                                                                                                               | Severity | Status                                               |
| --------------------------------------------------------------------------------------------------------------------- | -------- | ---------------------------------------------------- |
| Web app CSP allows `'unsafe-inline'` scripts (Next.js bootstrap); a nonce-based CSP would remove XSS script injection | Medium   | Open                                                 |
| Gateway rate-limit counters are in memory, per instance                                                               | Low      | Accepted (one gateway instance; Nginx per-IP limits) |
| OpenAPI could be enabled in production through `.env`                                                                 | Low      | Fixed (forced off in the overlay)                    |

### SSRF protection and PoC download security

Reviewed `services/download-service/src/domain/ip-policy.ts` and `download/safe-fetcher.ts`:
source allowlist, canonical URLs built by the source, every DNS answer checked against IPv4/IPv6
special-purpose ranges (including IPv4 embedded in IPv6: mapped, NAT64, 6to4, Teredo), the socket
pinned to the checked address, every redirect re-validated from scratch, connect/idle/total
timeouts, declared and enforced size limits, content-type and magic-byte checks, staging on a
`noexec` tmpfs, SHA-256, ClamAV + YARA, quarantine, manual release with `quarantine:manage`,
database CHECK constraints that forbid releasing a non-clean artifact, nothing ever executed or
extracted. Source HTTP clients of the other services are origin-allowlisted.

| Finding                                                               | Severity | Status                                                      |
| --------------------------------------------------------------------- | -------- | ----------------------------------------------------------- |
| SSRF and policy blocks were not observable                            | Medium   | Fixed (`download_attempts_total{code}`, alert)              |
| Malicious or tampered artifacts raised no alert                       | Medium   | Fixed (MaliciousArtifactDetected, ArtifactIntegrityFailure) |
| No live download from GitHub or Exploit-DB has been made (part of B4) | High     | Open                                                        |

### MinIO permissions

Per-service users: download-service read/write on both artifact buckets, poc-service read-only on
released artifacts, reporting-service its bucket only; no anonymous access; versioning on.

| Finding                                                                                      | Severity | Status                                        |
| -------------------------------------------------------------------------------------------- | -------- | --------------------------------------------- |
| Image is `pgsty/minio`, an unofficial rebuild (part of B2)                                   | High     | Open (decision)                               |
| No server-side encryption at rest                                                            | Medium   | Open (use disk encryption; see deployment.md) |
| Metrics endpoint is public inside the internal network (`MINIO_PROMETHEUS_AUTH_TYPE=public`) | Low      | Accepted                                      |

### Container security

All containers: `cap_drop: ALL`, `no-new-privileges`, non-root, read-only root filesystems where
the image allows, CPU/memory/PID limits, log rotation, internal networks, egress only for the
services that need it. Enforced by static tests.

| Finding                                                                                                                                                            | Severity | Status   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------- | -------- |
| Base images use tags, not digests (`node:22-alpine`, data stores); application images are not scanned (Trivy/Grype), signed or accompanied by an SBOM (part of B2) | High     | Open     |
| OpenSearch and Keycloak root filesystems are writable (image constraint)                                                                                           | Low      | Accepted |

### Secret management

Secrets are generated randomly (`pnpm env:generate`), never committed (static test), hashed in
Redis/PostgreSQL/OpenSearch, and the Alertmanager URL never reaches its configuration.

| Finding                                                                                                            | Severity | Status                                    |
| ------------------------------------------------------------------------------------------------------------------ | -------- | ----------------------------------------- |
| Secrets reach containers as environment variables (readable through `docker inspect` by anyone with Docker access) | Medium   | Open (Docker secrets or a secret manager) |
| Production configuration was not validated before start                                                            | Medium   | Fixed (preflight)                         |
| Backups would contain every secret and malware samples                                                             | High     | Fixed (age encryption mandatory)          |

### Logging

Pino JSON with ISO timestamps, service name, correlation IDs and secret redaction; audit events
flagged `audit: true`; Nginx, Keycloak and Grafana log JSON.

| Finding                                                                        | Severity | Status            |
| ------------------------------------------------------------------------------ | -------- | ----------------- |
| Uncaught exceptions were printed as plain stack traces                         | Low      | Fixed             |
| No central log aggregation or SIEM forwarding (json-file, 30 MB per container) | Medium   | Open (documented) |

### Monitoring

| Finding                                                                                  | Severity | Status            |
| ---------------------------------------------------------------------------------------- | -------- | ----------------- |
| Alerts were evaluated but never delivered (no Alertmanager)                              | High     | Fixed             |
| Only infrastructure and HTTP metrics; no visibility into events, jobs, auth or downloads | Medium   | Fixed             |
| No external uptime or certificate-expiry probe; backup freshness is not a metric         | Low      | Open (documented) |

### Backup and restoration

| Finding                                                                              | Severity | Status                                           |
| ------------------------------------------------------------------------------------ | -------- | ------------------------------------------------ |
| No backups or restore procedure existed                                              | Critical | Fixed (scripts, runbook, drill)                  |
| RPO is the backup interval (1 h suggested); no point-in-time recovery or replication | Medium   | Accepted (single host; see disaster-recovery.md) |

### Error handling

Global exception filter with a stable envelope and correlation ID; source clients retry with
backoff and classify retryable errors; consumers dead-letter after bounded retries; jobs fail
permanently on invalid payloads; startup fails fast on invalid configuration. No findings beyond
the logging fix above.

### Performance

PostgreSQL connection limits (200) exceed the services' pools; queries are paginated; explicit
indexes exist (the outbox backlog query uses the existing `(published_at, next_attempt_at)`
index). No load test has been run.

| Finding                                                    | Severity | Status   |
| ---------------------------------------------------------- | -------- | -------- |
| No load or soak test; capacity of a single host is unknown | Medium   | Open     |
| Single instance of every component, no high availability   | Medium   | Accepted |

### Test coverage

| Suite                                                                               | Result                                                                                                                                                                                                     |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm typecheck`, `pnpm lint`, `pnpm format:check`                                  | Pass                                                                                                                                                                                                       |
| `pnpm test` (unit, HTTP, static policy)                                             | 1 050 tests in 25 workspaces pass                                                                                                                                                                          |
| Service integration suites run locally against PostgreSQL 17 and Redis from Compose | cve 12, asset 20, exploit 27, poc 21, intelligence 9: all pass                                                                                                                                             |
| Not run locally                                                                     | identity-service (needs Keycloak with development ports), download-service (needs ClamAV, YARA, MinIO), infrastructure live suites and the full-stack suite: they run in CI's `integration` job on this PR |
| Operational checks                                                                  | `promtool`, `amtool`, `nginx -t` (both configs), live TLS checks, live alert delivery, live backup → verify → restore drill                                                                                |

Gaps: no coverage measurement in CI, no load tests, no end-to-end test across services with a live
broker, no tests against real external APIs (B4).

## Decisions needed

1. **MFA (B1):** require TOTP or WebAuthn for `super-admin` and `administrator` (recommended), or
   for every user. Existing realms must be changed in the admin console because the realm is only
   imported once; the import file can be updated for new deployments.
2. **MinIO image (B2):** use an internally mirrored build you trust, the vendor's commercial image,
   or another S3-compatible store. Then pin every image by digest and add image scanning to CI.

## Go-live checklist

- [ ] B1–B4 resolved
- [ ] `pnpm deploy:preflight` passes on the production host
- [ ] Hourly backups scheduled, daily verification, off-host copies, a restore drill recorded
- [ ] Alert receiver tested (stop a service and confirm the alert arrives)
- [ ] Bootstrap Keycloak admin removed, Grafana admin password changed
- [ ] Logs forwarded to central storage, external uptime check on `/api/v1/health/live`
- [ ] Load test at the expected request and synchronisation volume
