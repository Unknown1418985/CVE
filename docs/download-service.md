# Download Service

The Download Service (Phase 6) fetches PoC artifacts from approved sources, stores them in MinIO
quarantine, inspects them with ClamAV and YARA, and manages their lifecycle up to an explicit
release. All downloaded content is untrusted: it is streamed to disk, hashed, scanned as bytes
and stored. It is never executed, never extracted and never previewed.

A successful download only means the bytes arrived. It does not make an artifact verified,
clean or releasable:

- **Scan status** is the scanners' result: `pending`, `scanning`, `clean`, `suspicious`,
  `malicious`, `incomplete` or `integrity-failure`.
- **Verification status** is the analysts' judgement, projected from the PoC Service:
  `unverified`, `in-review`, `verified`, `rejected` or `malicious`.
- **Lifecycle status** is `quarantined`, `released` or `rejected`. Every artifact starts in
  quarantine. Release is a manual decision by a user with `quarantine:manage`.

## Data flow

1. The PoC Service publishes `poc.artifact.discovered` (a GitHub repository at a commit) and
   `poc.reference.discovered` (for example an Exploit-DB link). The consumers turn them into
   download requests. A user can also create a request through the API.
2. A request is unique per source and URL (`source`, `url_hash`). A second discovery of the same
   URL merges its CVE IDs and PoC artifact link into the existing request.
3. The scheduling job queues due requests (`FOR UPDATE SKIP LOCKED`). The download worker claims
   a request with a lease and records one `download_attempts` row per attempt.
4. The safe fetcher streams the response into a private staging file. It computes SHA-256 and the
   size while streaming and keeps only the first bytes for file type detection.
5. If the SHA-256 is already stored, the request becomes a `duplicate` of that artifact and a new
   provenance row is added. Nothing is uploaded again.
6. Otherwise the file is uploaded to `cve-poc-quarantine` under a generated key, and the artifact,
   its provenance, the lifecycle history and the outbox events are written in one transaction.
7. The scan job streams the object back out of quarantine, checks its SHA-256 again, runs every
   configured scanner and records each scanner's result.

## SSRF and download hardening

| Control              | Implementation                                                                                                                                                                                |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Source allowlist     | Each source has a base URL, allowed hosts and an allowed port. `github-archive` builds `codeload.github.com/<owner>/<repo>/tar.gz/<40-hex commit>`; `exploit-db` builds `/download/<id>`.     |
| User-submitted URLs  | Accepted only when they map to an enabled source (GitHub archive, commit or tree URLs with a full SHA; Exploit-DB exploit, download or raw URLs). Anything else is refused with 422.          |
| URL rules            | https only. No credentials, no IP literals, no non-default ports in production.                                                                                                               |
| DNS                  | Resolved by the service. Every answer is checked, and one blocked answer rejects the host.                                                                                                    |
| Blocked destinations | Private, loopback, link-local (cloud metadata), CGNAT, reserved, documentation, benchmarking, multicast, and IPv4 embedded in IPv6 (mapped, NAT64, 6to4, Teredo). IPv6 must be in `2000::/3`. |
| DNS rebinding        | The socket connects to the checked address through a pinned `lookup`. TLS still verifies the original host name.                                                                              |
| Redirects            | Followed manually, at most `DOWNLOAD_MAX_REDIRECTS` hops. Every hop is validated again (scheme, host allowlist, DNS, address). Each hop is recorded in the attempt history.                   |
| Timeouts             | Response timeout, idle timeout between chunks, and a total deadline.                                                                                                                          |
| Size                 | A declared `Content-Length` above the limit is refused before reading. The streamed byte count is enforced too. PoC artifacts whose listing is far above the limit are rejected unread.       |
| Encoding             | `Accept-Encoding: identity`. Any other `Content-Encoding` is refused, so nothing is decompressed.                                                                                             |
| Content type         | The declared type must be allowed for the source, and the type detected from the magic bytes must be allowed for the source (GitHub archives: gzip only).                                     |
| Filenames            | The original filename is stored as text for provenance only. Object keys are `quarantine/<yyyy>/<mm>/<uuid>` and `released/<uuid>`. Nothing from the source becomes a path or a key.          |

Policy failures (for example a blocked address or a disallowed type) mark the request `rejected`
and are not retried. Network failures and 5xx/429 responses are retried with exponential backoff
up to `DOWNLOAD_JOB_ATTEMPTS`.

## Storage

- Objects are always written as `application/octet-stream` with `Content-Disposition: attachment`.
- MinIO verifies the SHA-256 sent with every upload (`ChecksumSHA256`).
- The Download Service is the only writer of both artifact buckets. The PoC Service can only read
  released artifacts. See the MinIO policies in [infrastructure.md](infrastructure.md).

## Scanning

- **ClamAV**: `clamd` over TCP (`zINSTREAM`). The file is streamed to the daemon, which never
  sees a path. Signatures are kept current by freshclam in the `clamav` container.
- **YARA**: the `yara` command-line scanner run with `execFile`. There is no shell and the
  environment is empty. The rules are in `services/download-service/yara/index.yar`
  (download-and-execute pipes, encoded PowerShell, embedded PE files, miners, credential theft,
  exfiltration webhooks). A YARA match marks the artifact `suspicious`. The rules are heuristics,
  not proof of malware.
- YARA reads the bytes as stored. A gzip archive is therefore scanned compressed, because archives
  are never extracted. ClamAV unpacks archives inside its own engine.
- **Combining the results**:
  - `clean` only when every required scanner (`SCAN_REQUIRED_SCANNERS`) ran and reported clean.
  - Otherwise the worst result wins: malicious, then suspicious, then incomplete.
  - A required scanner that is missing or failed makes the result `incomplete`.
  - A scanner error is retried by the scan job.
- **Integrity**: if the stored object no longer matches its recorded SHA-256 or size, the artifact
  becomes `integrity-failure`.

## Lifecycle

| From          | To            | Rule                                                                                    |
| ------------- | ------------- | --------------------------------------------------------------------------------------- |
| `quarantined` | `released`    | `quarantine:manage`, scan `clean`, verification neither `malicious` nor `rejected`      |
| `quarantined` | `rejected`    | `quarantine:manage`                                                                     |
| `released`    | `quarantined` | Manual, or automatic when a rescan finds something or the verification becomes blocking |
| `released`    | `rejected`    | `quarantine:manage`                                                                     |
| `rejected`    | `quarantined` | `quarantine:manage` (reopens the decision)                                              |

How a release works:

- Releasing copies the object to `cve-poc-artifacts` and records `released_key`. Leaving `released`
  deletes the copy after the transaction commits. If that delete fails, maintenance retries it.
- Two database CHECK constraints enforce the rules: a released row must have a clean scan, a
  released key and a non-blocking verification.
- A revocation is written in the same update as the status that causes it.
- `artifact_lifecycle_events` is append-only (enforced by a trigger).

Quarantine is never exposed to ordinary users:

- Without `quarantine:read`, only released artifacts are visible. Every other artifact answers 404.
- Content is served only for released, clean artifacts, to users with `artifact:download`. It is
  sent as `application/octet-stream` with an attachment disposition and the headers `nosniff`,
  `Content-Security-Policy: sandbox` and `no-store`, plus `Repr-Digest` and `X-Artifact-SHA256`.
  The gateway streams it unchanged.

## Verification from the PoC Service

`poc.artifact.discovered` and `poc.artifact.verification-changed` keep a projection of each PoC
artifact's verification status (`poc_artifact_states`). The projection is ordered by the event
version, so a late, older event is ignored.

An artifact linked to several PoC artifacts takes the worst status among them, in this order:
malicious, rejected, in review, unverified, verified. A blocking status revokes an existing
release.

## Events

Published through the outbox on the `cve.events` exchange:

| Event                                 | When                                                 |
| ------------------------------------- | ---------------------------------------------------- |
| `download.request.completed`          | A request stored a new artifact or found a duplicate |
| `download.request.failed`             | A request failed or was rejected (final)             |
| `download.artifact.stored`            | A new artifact entered quarantine                    |
| `download.artifact.scanned`           | A scan finished (status, scanners, findings)         |
| `download.artifact.lifecycle-changed` | Release, rejection, reopening or revocation          |

Consumed: `poc.artifact.discovered` (queue `download-service.poc-artifact-downloads`),
`poc.artifact.verification-changed` (`download-service.poc-artifact-verification`) and
`poc.reference.discovered` (`download-service.poc-reference-downloads`). Duplicates are suppressed
through the `processed_events` inbox.

## Jobs (BullMQ)

| Queue                  | Purpose                                                                                                              |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `artifact-download`    | One job per request attempt. Rate limited across replicas.                                                           |
| `artifact-scan`        | Scan and rescan, retried on scanner errors.                                                                          |
| `download-scheduling`  | Every minute: queue due requests (scheduled time, retry backoff).                                                    |
| `download-maintenance` | Hourly: expired leases, lost jobs, unscanned or stalled artifacts, leftover released copies, inbox/outbox retention. |

## API

All routes are under `/api/v1`, through the API Gateway.

| Method | Path                                        | Permission          |
| ------ | ------------------------------------------- | ------------------- |
| GET    | `/download-sources`                         | `download:read`     |
| GET    | `/download-requests`                        | `download:read`     |
| POST   | `/download-requests`                        | `download:schedule` |
| GET    | `/download-requests/:id`                    | `download:read`     |
| POST   | `/download-requests/:id/retry`              | `download:schedule` |
| POST   | `/download-requests/:id/cancel`             | `download:schedule` |
| GET    | `/download-artifacts`                       | `download:read`     |
| GET    | `/download-artifacts/:id`                   | `download:read`     |
| GET    | `/download-artifacts/:id/scans`             | `quarantine:read`   |
| GET    | `/download-artifacts/:id/lifecycle-history` | `download:read`     |
| POST   | `/download-artifacts/:id/rescan`            | `quarantine:manage` |
| POST   | `/download-artifacts/:id/lifecycle`         | `quarantine:manage` |
| GET    | `/download-artifacts/:id/content`           | `artifact:download` |

A request is created with exactly one of `url` or `pocArtifactId`, plus optional `cveIds`,
`scheduledFor`, `priority` (1–10) and `reason`. Creating is idempotent per canonical source URL: a
repeated request returns the existing one. Lifecycle changes are checked against the current state
under a row lock, so a repeated decision is refused rather than applied twice.

## Configuration

Beyond the common service variables (`DATABASE_URL`, `REDIS_URL`, `RABBITMQ_URL`, `S3_*`,
`KEYCLOAK_*`):

| Variable                                                                  | Default                                                  |
| ------------------------------------------------------------------------- | -------------------------------------------------------- |
| `DOWNLOAD_SOURCES_ENABLED` / `DOWNLOAD_AUTOMATIC_SOURCES`                 | `github-archive`                                         |
| `DOWNLOAD_GITHUB_ARCHIVE_URL` / `_EXTRA_HOSTS`                            | `https://codeload.github.com`                            |
| `DOWNLOAD_EXPLOIT_DB_URL` / `_EXTRA_HOSTS`                                | `https://www.exploit-db.com`                             |
| `DOWNLOAD_MAX_BYTES`                                                      | 100 MiB                                                  |
| `DOWNLOAD_MAX_EXPECTED_RATIO`                                             | `4`                                                      |
| `DOWNLOAD_RESPONSE_TIMEOUT_MS` / `_IDLE_TIMEOUT_MS` / `_TOTAL_TIMEOUT_MS` | 15 s / 30 s / 10 min                                     |
| `DOWNLOAD_MAX_REDIRECTS`                                                  | `5`                                                      |
| `DOWNLOAD_STAGING_DIR`                                                    | `/tmp/download-staging`                                  |
| `DOWNLOAD_JOB_ATTEMPTS` / `DOWNLOAD_RETRY_BACKOFF_MS`                     | `4` / 1 min                                              |
| `DOWNLOAD_CONCURRENCY` / `DOWNLOAD_RATE_LIMIT_PER_MINUTE`                 | `2` / `30`                                               |
| `SCAN_REQUIRED_SCANNERS`                                                  | `clamav,yara`                                            |
| `CLAMAV_ENABLED` / `CLAMAV_HOST` / `CLAMAV_PORT` / `CLAMAV_TIMEOUT_MS`    | `true` / `clamav` / `3310` / 5 min                       |
| `YARA_ENABLED` / `YARA_BINARY` / `YARA_RULES_PATH` / `YARA_TIMEOUT_MS`    | `true` / `/usr/bin/yara` / `/app/yara/index.yar` / 2 min |

Exploit-DB is approved but disabled by default. Enable it only once its terms permit your use.

In Compose:

- The service gets a 512 MiB `noexec` tmpfs for staging.
- The image includes `yara`.
- `clamav` is reachable only on the internal `scanning` network.

## Tests

- **Unit and e2e** (`pnpm --filter @cve/download-service test`): the address policy, the URL rules
  and the source mapping, file type detection, filenames and keys, the lifecycle rules, the safe
  fetcher against a local HTTPS server (redirects, DNS answers, timeouts, sizes, encodings), the
  scanner adapters against a fake clamd and the real `yara` binary when it is installed, and the
  HTTP API with RBAC.
- **Integration** (`pnpm --filter @cve/download-service test:integration`): the full pipeline
  against real PostgreSQL, Redis, MinIO, clamd and YARA, with a mock HTTPS source. It covers
  events to download, quarantine and a clean scan, EICAR-style malware, YARA matches, duplicates,
  retries, blocked redirects, size and type rejections, Exploit-DB, release and attachment
  serving, and revocation on a malicious verification.
  - Point it at servers with the `DOWNLOAD_SERVICE_TEST_*` variables.
  - It refuses to reset a database holding non-test sources.

## Not done yet

- No live download from GitHub or Exploit-DB was made while building this. Sources are tested
  against a local HTTPS mock.
- The PoC Service does not consume the `download.*` events yet. It cannot show download or scan
  status next to its artifacts.
- Archives are not inspected beyond ClamAV's own unpacking. YARA scans the compressed bytes.
- There is no web UI (Download Manager) yet. It arrives with the frontend.
