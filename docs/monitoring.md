# Monitoring, health checks and alerting

## Health endpoints

Every NestJS process (API Gateway and the nine backend services) serves, without authentication:

| Endpoint                   | Purpose   | Behaviour                                                                                                                                                                                                              |
| -------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/v1/health/live`  | Liveness  | `200` while the process can serve requests. Never checks dependencies, so a database or Keycloak outage does not make the orchestrator restart healthy processes.                                                      |
| `GET /api/v1/health/ready` | Readiness | Checks every dependency concurrently (bounded by `HEALTH_CHECK_TIMEOUT_MS`). `503` when a critical dependency is down **or the process is shutting down**; `200` with `degraded` when only a non-critical one is down. |
| `GET /api/v1/health`       | Report    | Same as readiness.                                                                                                                                                                                                     |

The gateway additionally serves `GET /api/v1/health/services` (aggregated readiness of all
backends; details only for authenticated callers).

Readiness checks per service:

| Service                                   | Critical                                                     | Non-critical   |
| ----------------------------------------- | ------------------------------------------------------------ | -------------- |
| api-gateway                               | Keycloak signing keys (JWKS reachable and non-empty)         | —              |
| intelligence, poc, exploit                | PostgreSQL (`SELECT 1`), Redis (`PING`), RabbitMQ connection | —              |
| download                                  | PostgreSQL, MinIO bucket, Redis, RabbitMQ connection         | ClamAV, YARA   |
| identity                                  | PostgreSQL, RabbitMQ connection                              | Redis (`PING`) |
| cve, asset                                | PostgreSQL, RabbitMQ connection                              | Redis (TCP)    |
| reporting, notification (no domain logic) | TCP reachability of PostgreSQL, Redis, RabbitMQ              | —              |

RabbitMQ is checked on the live AMQP connection when the outbox relay or consumers are enabled,
otherwise by TCP reachability.

Compose uses liveness as the container health check and `depends_on: service_healthy` for start
order. Docker restarts a container when its process exits (a crash), not when it is merely
unhealthy; `ServiceNotReady` and `TargetDown` alert on the latter. On `SIGTERM` a service first reports not ready, then finishes
in-flight requests and closes its connections.

## Metrics

Prometheus scrapes every service on the internal port `9464` (`/metrics`, never routed through
Nginx), the infrastructure exporters, MinIO, Keycloak, RabbitMQ and Alertmanager. Every series
carries `service` and `version` labels. Label values are bounded (`boundedLabel`), so request or
event content can never create unbounded cardinality.

| Metric                                                                                                                | Source                              | Meaning                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `service_ready`, `service_dependency_up{dependency}`                                                                  | every service (readiness at scrape) | 1 ready / 0 not ready; dependency 1 ok, 0.5 degraded, 0 down                                                                                                      |
| `http_server_request_duration_seconds{method,route,status_code}`                                                      | every service                       | Request latency histogram (route template, never the raw path)                                                                                                    |
| `process_*`, `nodejs_*`                                                                                               | every service                       | CPU, memory, event loop lag, GC, file descriptors, restarts                                                                                                       |
| `auth_requests_rejected_total{reason}`                                                                                | every service (`@cve/auth`)         | 401/403/503 by reason: `missing-token`, `expired-token`, `invalid-token`, `wrong-issuer`, `wrong-audience`, `session-inactive`, `forbidden`, `idp-unavailable`, … |
| `messaging_events_published_total{event_type,outcome}`                                                                | `@cve/messaging`                    | Broker-confirmed or failed publications                                                                                                                           |
| `messaging_events_consumed_total{queue,event_type,outcome}`                                                           | `@cve/messaging`                    | `processed`, `duplicate`, `invalid`, `retry_scheduled`, `dead_lettered`, `requeued`                                                                               |
| `messaging_event_handler_duration_seconds{queue,event_type}`                                                          | `@cve/messaging`                    | Handler latency                                                                                                                                                   |
| `outbox_pending_events`, `outbox_oldest_pending_age_seconds`                                                          | services with an outbox             | Backlog of unpublished events (queried from the service database at scrape)                                                                                       |
| `outbox_events_relayed_total{outcome}`                                                                                | services with an outbox             | Relay results                                                                                                                                                     |
| `jobs_processed_total{queue,outcome}`, `job_duration_seconds{queue}`                                                  | `@cve/jobs`                         | BullMQ attempts: `completed`, `retrying`, `failed`, `stalled`                                                                                                     |
| `job_queue_jobs{queue,state}`                                                                                         | `@cve/jobs`                         | Waiting, active, delayed, prioritized and failed jobs (read at scrape)                                                                                            |
| `source_sync_runs_total{source,status}`, `source_sync_duration_seconds`, `source_sync_last_success_timestamp_seconds` | intelligence-service                | Synchronisation runs per source                                                                                                                                   |
| `download_attempts_total{source,outcome,code}`, `download_bytes_total{source}`                                        | download-service                    | Downloads by outcome and policy/SSRF error code                                                                                                                   |
| `artifact_scans_total{status}`, `artifact_scanner_verdicts_total{scanner,verdict}`                                    | download-service                    | Scan results (clean, suspicious, malicious, incomplete, integrity-failure)                                                                                        |

`source_sync_last_success_timestamp_seconds` only exists after a successful run since the
Intelligence Service last started.

## Dashboards

Grafana (`127.0.0.1:3001`, admin credentials from `.env`) provisions read-only dashboards in the
**CVE Platform** folder:

| Dashboard                             | Shows                                                                                                                                      |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| CVE Platform — Infrastructure         | Scrape targets, RabbitMQ, Redis, PostgreSQL connections, MinIO capacity, service RED summary                                               |
| CVE Platform — Services               | Readiness per service, dependency status table, request rate by status, 5xx ratio, p95/p99, runtime                                        |
| CVE Platform — Events, Jobs & Sources | Outbox backlog, event outcomes, dead-letter queues, BullMQ queues and jobs, source syncs, downloads, scans                                 |
| CVE Platform — Security               | Firing alerts, authentication rejections by reason, 403s, gateway 401/403/429, SSRF and policy blocks, malicious artifacts, scanner errors |

Panels only query metrics the platform exports; a panel without data means the component has not
produced that signal yet (for example no downloads), never estimated values.

## Alerting

Prometheus evaluates the rules in [`infra/prometheus/rules`](../infra/prometheus/rules) and sends
alerts to Alertmanager (observability profile, internal only), which delivers them to
`ALERTMANAGER_WEBHOOK_URL` (Alertmanager webhook JSON). The URL is written to a private tmpfs file
at container start and is never part of the configuration.

| Group                | Alerts                                                                                                                                                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| availability         | TargetDown                                                                                                                                                                                                                        |
| service-health       | ServiceNotReady (critical), ServiceDependencyDown, ServiceDependencyDegraded, ServiceRestarting, ServiceHighLatency                                                                                                               |
| services             | ServiceHighErrorRate                                                                                                                                                                                                              |
| events-and-jobs      | OutboxBacklog, OutboxStalled (critical), EventsDeadLettered, BackgroundJobsFailing, BackgroundJobBacklog                                                                                                                          |
| messaging            | RabbitMqDeadLetterMessages, RabbitMqQueueBacklog, RabbitMqResourceAlarm                                                                                                                                                           |
| security             | IdentityProviderUnavailable (critical), AuthenticationFailureSpike, AccessDeniedSpike, RateLimitingActive, DownloadPolicyViolations, MaliciousArtifactDetected (info), ArtifactIntegrityFailure (critical), ArtifactScannerErrors |
| intelligence-sources | SourceSyncFailing, SourceSyncStale                                                                                                                                                                                                |
| datastores           | RedisMemoryHigh, PostgresConnectionsHigh                                                                                                                                                                                          |
| alerting             | AlertNotificationsFailing (critical)                                                                                                                                                                                              |

Routing ([`infra/alertmanager/alertmanager.yml`](../infra/alertmanager/alertmanager.yml)): grouped
by alert and service, critical alerts repeat hourly, warnings every 4 hours, info daily.
`ServiceNotReady` inhibits the dependency alerts of the same service.

### Using another receiver

The webhook receiver works with any service that accepts Alertmanager's webhook payload (for
example an incident-management integration or a small relay to chat). For e-mail, Slack,
PagerDuty or Opsgenie, replace the `platform-webhook` receiver with the matching
`*_configs` block and keep secrets out of the file (use the `*_file` variants, such as
`api_url_file` or `routing_key_file`, mounted from a secret).

### Gaps

- No blackbox probing from outside the host (DNS, certificate expiry, public reachability). Add an
  external uptime check for `https://<host>/api/v1/health/live`.
- Backup success is not a metric; monitor the backup cron jobs' exit status.
- OpenSearch is not scraped (no built-in Prometheus endpoint).
- Logs are not aggregated centrally; see [deployment.md](deployment.md#7-operate).
