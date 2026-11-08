# Web frontend

`apps/web` is the English-language analyst interface of the platform: Next.js (App Router),
React, TypeScript, Tailwind CSS, shadcn/ui-style components on Radix primitives, TanStack Query,
Recharts, React Hook Form, Zod and Lucide icons. It has a single dark theme.

Every number and record on screen comes from a live API response that was validated against the
shared contracts in `@cve/contracts`. When an endpoint is missing, unreachable or forbidden, the
page shows an explicit loading, empty, "Unavailable" or "Access restricted" state. It never
fills in placeholder values.

## Authentication: backend-for-frontend

The browser never holds an access or refresh token.

| Route                      | Purpose                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------- |
| `GET /session/login`       | Starts the OIDC authorization code flow with PKCE (S256), `state` and `nonce`.              |
| `GET /session/callback`    | Checks `state`, exchanges the code, checks the ID token `nonce`, sets the session cookie.   |
| `POST /session/logout`     | Ends the Keycloak session through the gateway, clears cookies, returns the redirect target. |
| `/bff/api/v1/<resource>/…` | Proxies to the API Gateway with the session's bearer token.                                 |
| `GET /api/health`          | Liveness of the web server (no gateway dependency).                                         |

- The OIDC client is the public Keycloak client `cve-web`. With
  `?action=update-password|configure-totp`, `/session/login` starts a Keycloak
  application-initiated action (`kc_action`) for Settings.
- Tokens live in an AES-256-GCM sealed, `httpOnly`, `SameSite=Lax` cookie (`cve_session`, split
  into at most four chunks). The key is derived with HKDF from `WEB_SESSION_SECRET` and bound to
  its purpose, so a transaction cookie cannot be replayed as a session.
- The proxy refreshes the access token 30 seconds before it expires. Keycloak rotates refresh
  tokens and refuses reuse, so concurrent requests share one refresh (`refreshSession`).
- CSRF: every mutation through the proxy, and logout, requires the platform's `Origin` (or
  `Sec-Fetch-Site: same-origin`) and the `x-cve-client: web` header, which a cross-site form
  cannot send.
- The proxy only forwards an allowlist of top-level resources (`PROXIED_RESOURCES`), rejects dot
  segments, separators and encoded characters, accepts JSON bodies up to 1 MiB, and forwards
  `If-Match`, `Idempotency-Key` and the correlation ID.
- Artifact content (`download-artifacts/:id/content`) is always served as an
  `application/octet-stream` attachment with `nosniff`, a sandboxing CSP and a generated file
  name, whatever the upstream sends.
- `src/proxy.ts` sends requests without a session cookie to `/session/login`; the `(platform)`
  layout validates the session on the server.

The UI hides navigation and actions the user's permissions (from `GET /me`) do not allow. This is
a convenience only: the gateway and every service enforce the same permissions on each request.

## Pages

| Page                   | Route                                                               | Data                                                                  |
| ---------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Overview               | `/`                                                                 | CVE counts, severity distribution, exploitation statistics, health    |
| CVE Explorer / Details | `/cves`, `/cves/:cveId`                                             | CVE Service (search, filters, CVSS and EPSS history), PoCs, exploits  |
| Vulnerability Analysis | `/analysis`                                                         | Distributions computed from CVE Service counts and exploit statistics |
| PoC Repository         | `/pocs`, `/pocs/:id`, `/pocs/artifacts/:id`                         | PoC Service (repositories, associations, verification)                |
| Exploit Intelligence   | `/exploits`, `/exploits/:id`                                        | Exploit Service (assessments, catalog entries, evidence)              |
| Vendors & Products     | `/vendors`, `/vendors/:id`, `/products/:id`                         | Asset Service                                                         |
| Threat Intelligence    | `/threat-intelligence`                                              | KEV, EPSS, in-the-wild and ransomware views                           |
| Download Manager       | `/downloads`, `/downloads/requests/:id`, `/downloads/artifacts/:id` | Download Service                                                      |
| Data Sources           | `/data-sources`                                                     | Intelligence, PoC discovery, exploit catalog and download sources     |
| Reports                | `/reports`                                                          | Browser-side CSV/JSON exports of live data (see below)                |
| User Management        | `/users`, `/users/:id`                                              | Identity Service                                                      |
| Audit Logs             | `/audit-logs`                                                       | Identity Service                                                      |
| Settings               | `/settings`                                                         | Profile, credentials, own sessions, permission catalog                |

Global search (`Ctrl`/`⌘` + `K`) opens CVE IDs and CPE names directly and searches CVEs, vendors,
products, PoC repositories and exploits within the user's permissions.

Filters, sorting and pagination are kept in the URL, so every view can be bookmarked and shared.

### Artifact security status

A stored artifact always shows three independent facts side by side: lifecycle (quarantined,
released, rejected), scan result, and analyst verification. Release is not verification, and a
clean scan is not a verdict. Release, rejection, re-quarantine, rescans, verification changes,
role changes, user status changes and session revocations all need a confirmation dialog, and
most need a reason that the services record in the audit trail. Lifecycle and verification
changes send `If-Match` with the version the user saw, so concurrent changes fail instead of
overwriting each other.

Files are only downloadable when released and the user has `artifact:download`. The download
dialog warns that the content is untrusted. The interface never previews, renders, extracts or
runs artifact content.

### Reports

The Reporting Service does not expose an API yet. The Reports page therefore offers exports that
the browser builds from the same APIs as the rest of the interface (at most 5,000 rows per
export). CSV cells that a spreadsheet would evaluate as formulas (`=`, `+`, `-`, `@`, tab, CR) are
prefixed with an apostrophe, because the data comes from external sources. Stored, scheduled and
shared reports will appear once the Reporting Service ships them.

## Configuration

| Variable                   | Required | Default                      | Purpose                                                   |
| -------------------------- | -------- | ---------------------------- | --------------------------------------------------------- |
| `WEB_SESSION_SECRET`       | yes      |                              | Session cookie encryption key material (≥ 32 characters). |
| `PUBLIC_ORIGIN`            | no       | `http://localhost:3000`      | Origin users open; OIDC redirect URI and CSRF checks.     |
| `API_GATEWAY_INTERNAL_URL` | no       | `http://localhost:4000`      | Gateway address reachable from the web server.            |
| `KEYCLOAK_PUBLIC_URL`      | no       | `http://localhost:8180/auth` | Keycloak as browsers reach it (authorization endpoint).   |
| `KEYCLOAK_URL`             | no       | `KEYCLOAK_PUBLIC_URL`        | Keycloak as the web server reaches it (token endpoint).   |
| `KEYCLOAK_REALM`           | no       | `cve-platform`               |                                                           |
| `KEYCLOAK_WEB_CLIENT_ID`   | no       | `cve-web`                    |                                                           |
| `KEYCLOAK_TIMEOUT_MS`      | no       | `5000`                       | Token endpoint timeout.                                   |
| `API_PROXY_TIMEOUT_MS`     | no       | `20000`                      | Gateway request timeout for proxied calls.                |
| `LOG_LEVEL`                | no       | `info`                       | Pino log level.                                           |

`pnpm env:generate` writes `apps/web/.env` for `pnpm dev` (port 3000). `compose.dev.yaml` adds
`http://localhost:3000` (`KEYCLOAK_WEB_DEV_ORIGIN`) to the `cve-web` client next to
`PUBLIC_ORIGIN`, so the same realm serves `pnpm dev` and the stack behind Nginx. Keycloak only imports
the realm on first start, so an existing Keycloak volume keeps the previous redirect URIs:
recreate it (`docker compose down -v keycloak-db`) or add the URI in the admin console.

## Tests

| Command                           | Runs                                                                                                   |
| --------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `pnpm --filter @cve/web test`     | Vitest: session sealing, refresh sharing, CSRF guards, proxy path allowlist, OIDC, exports, formatting |
| `pnpm --filter @cve/web test:e2e` | Playwright: builds the app and runs it against `e2e/mock/server.ts`                                    |

The Playwright suite starts a mock Keycloak (authorization code + PKCE, refresh, logout) and a
mock API Gateway that serves synthetic fixtures (`CVE-2026-900xx`), checked against the shared
contracts when the mock starts. Covered journeys: sign-in and sign-out with an opaque `httpOnly`
cookie, cross-site mutation refused, CVE search with severity filter and pagination, empty and
error states (with correlation ID), global search to CVE details, artifact security statuses,
release with confirmation, reason and `If-Match`, release refused for a malicious artifact, and
navigation by role. It uses the Chromium that Playwright provides (`pnpm exec playwright install
chromium` on a fresh machine).
