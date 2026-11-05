# Download Service

Secure, controlled artifact downloading, scanning and MinIO storage (Phase 6).

- Package: `@cve/download-service`
- Default port: `4006`
- Database: `download_service` (owned exclusively by this service, role `download_service`)

## Responsibilities

- Downloads PoC artifacts from approved sources (GitHub archives, Exploit-DB). Downloads start
  automatically from PoC Service events, or a user requests one, possibly scheduled for later.
- Prevents SSRF:
  - source allowlists, https only;
  - DNS answers checked against private, loopback, link-local and reserved ranges;
  - sockets pinned to the checked address;
  - every redirect validated again.
- Enforces limits while streaming: timeouts, size limits, content-type and magic-byte checks. It
  computes SHA-256 and detects duplicates.
- Stores every artifact in MinIO quarantine under a generated key.
- Scans artifacts with ClamAV and YARA. It manages the lifecycle (quarantined, released, rejected)
  and keeps the full download provenance.
- Never executes downloaded files, never extracts archives and never previews content.
- A successful download is never reported as verified.

See [docs/download-service.md](../../docs/download-service.md) for the design, security controls,
lifecycle, API, events, configuration and tests.

## Endpoints

| Method   | Path                          | Description                                                |
| -------- | ----------------------------- | ---------------------------------------------------------- |
| GET      | `/api/v1/health/live`         | Liveness probe                                             |
| GET      | `/api/v1/health/ready`        | Readiness: PostgreSQL, MinIO, Redis, RabbitMQ (+ scanners) |
| GET      | `/api/v1/download-sources`    | Approved sources and their limits                          |
| GET/POST | `/api/v1/download-requests*`  | Download requests, attempts, retry, cancel                 |
| GET/POST | `/api/v1/download-artifacts*` | Artifacts, scans, lifecycle, rescan, released content      |
| GET      | `/api/v1/docs`                | OpenAPI UI (only when `SWAGGER_ENABLED=true`)              |

## Scripts

```bash
pnpm --filter @cve/download-service dev               # watch mode (needs clamd and yara for clean scans)
pnpm --filter @cve/download-service test
pnpm --filter @cve/download-service test:integration  # PostgreSQL, Redis, MinIO, clamd, yara
pnpm --filter @cve/download-service typecheck
```
