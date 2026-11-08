/**
 * Mock identity provider (Keycloak OIDC endpoints) and API Gateway for the end-to-end suite.
 * It implements just enough of both to exercise the real web server: authorization code flow
 * with PKCE, refresh, and the gateway routes the tested journeys call. Data comes from
 * `fixtures.ts` and is validated against the shared contracts on start-up.
 *
 * Test-only controls live under `/__mock/*`.
 */
import { createHash, randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import {
  canTransitionLifecycle,
  cveRecordSchema,
  cveSummarySchema,
  downloadArtifactDetailSchema,
  userProfileSchema,
  type ArtifactLifecycleStatus,
  type DownloadArtifactDetail,
  type LifecycleEvent,
} from '@cve/contracts';

import {
  CVES,
  USERS,
  cveRecord,
  initialArtifacts,
  storedEvent,
  type MockUser,
} from './fixtures.ts';

const PORT = Number(process.env['MOCK_PORT'] ?? '4100');
const REALM_PATH = '/auth/realms/cve-platform/protocol/openid-connect';
const CLIENT_ID = 'cve-web';

interface PendingCode {
  readonly user: MockUser['key'];
  readonly nonce: string;
  readonly challenge: string;
  readonly redirectUri: string;
}

interface RecordedRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: unknown;
}

interface State {
  nextUser: MockUser['key'];
  codes: Map<string, PendingCode>;
  /** access/refresh token → user key */
  tokens: Map<string, MockUser['key']>;
  failing: Set<string>;
  artifacts: DownloadArtifactDetail[];
  lifecycle: Map<string, LifecycleEvent[]>;
  requests: RecordedRequest[];
}

function freshState(): State {
  const artifacts = initialArtifacts();
  return {
    nextUser: 'admin',
    codes: new Map(),
    tokens: new Map(),
    failing: new Set(),
    artifacts,
    lifecycle: new Map(artifacts.map((artifact) => [artifact.id, [storedEvent(artifact)]])),
    requests: [],
  };
}

let state = freshState();

// Fail fast when fixtures drift from the contracts the web app validates against.
for (const cve of CVES) {
  cveSummarySchema.parse(cve);
  cveRecordSchema.parse(cveRecord(cve));
}
for (const artifact of state.artifacts) downloadArtifactDetailSchema.parse(artifact);
for (const user of Object.values(USERS)) userProfileSchema.parse(user.profile);

// ------------------------------------------------------------------------------------- helpers

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/** Unsigned JWT: the web server only reads claims; signature checks belong to the gateway. */
function jwt(claims: Record<string, unknown>): string {
  return `${base64url({ alg: 'RS256', typ: 'JWT' })}.${base64url(claims)}.e2e`;
}

function send(
  res: ServerResponse,
  status: number,
  body?: unknown,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(body === undefined ? undefined : JSON.stringify(body));
}

function apiError(res: ServerResponse, status: number, code: string, message: string): void {
  const correlationId = `e2e-${randomUUID()}`;
  send(
    res,
    status,
    { error: { code, message }, correlationId, timestamp: new Date().toISOString() },
    { 'x-correlation-id': correlationId },
  );
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function parseJson(text: string): unknown {
  if (text === '') return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function page<T>(
  items: readonly T[],
  url: URL,
): { data: T[]; meta: { page: number; pageSize: number; totalItems: number; totalPages: number } } {
  const pageNumber = Math.max(1, Number(url.searchParams.get('page') ?? '1'));
  const pageSize = Math.min(100, Math.max(1, Number(url.searchParams.get('pageSize') ?? '25')));
  const start = (pageNumber - 1) * pageSize;
  return {
    data: items.slice(start, start + pageSize),
    meta: {
      page: pageNumber,
      pageSize,
      totalItems: items.length,
      totalPages: items.length === 0 ? 0 : Math.ceil(items.length / pageSize),
    },
  };
}

function listParam(url: URL, name: string): string[] {
  const value = url.searchParams.get(name);
  return value === null || value === '' ? [] : value.split(',');
}

function issueTokens(user: MockUser['key'], nonce: string | null): Record<string, unknown> {
  const sid = randomUUID();
  const subject = USERS[user].profile.id;
  const accessToken = jwt({
    sub: subject,
    preferred_username: USERS[user].profile.username,
    sid,
    iat: Date.now() / 1000,
    jti: randomUUID(),
  });
  const refreshToken = `refresh-${randomUUID()}`;
  state.tokens.set(accessToken, user);
  state.tokens.set(refreshToken, user);
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    id_token: jwt({ sub: subject, nonce, sid }),
    token_type: 'Bearer',
    expires_in: 300,
    refresh_expires_in: 1800,
  };
}

// ---------------------------------------------------------------------------------- identity

function authorize(url: URL, res: ServerResponse): void {
  const params = url.searchParams;
  const redirectUri = params.get('redirect_uri');
  if (
    params.get('client_id') !== CLIENT_ID ||
    redirectUri === null ||
    params.get('response_type') !== 'code' ||
    params.get('code_challenge_method') !== 'S256'
  ) {
    send(res, 400, { error: 'invalid_request' });
    return;
  }
  const code = randomUUID();
  state.codes.set(code, {
    user: state.nextUser,
    nonce: params.get('nonce') ?? '',
    challenge: params.get('code_challenge') ?? '',
    redirectUri,
  });
  const target = new URL(redirectUri);
  target.searchParams.set('code', code);
  target.searchParams.set('state', params.get('state') ?? '');
  res.writeHead(302, { location: target.href });
  res.end();
}

async function token(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const form = new URLSearchParams(await readBody(req));
  if (form.get('client_id') !== CLIENT_ID) {
    send(res, 401, { error: 'invalid_client' });
    return;
  }
  if (form.get('grant_type') === 'authorization_code') {
    const pending = state.codes.get(form.get('code') ?? '');
    state.codes.delete(form.get('code') ?? '');
    const verifier = form.get('code_verifier') ?? '';
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    if (pending?.challenge !== challenge || pending.redirectUri !== form.get('redirect_uri')) {
      send(res, 400, { error: 'invalid_grant' });
      return;
    }
    send(res, 200, issueTokens(pending.user, pending.nonce));
    return;
  }
  if (form.get('grant_type') === 'refresh_token') {
    const refresh = form.get('refresh_token') ?? '';
    const user = state.tokens.get(refresh);
    if (user === undefined) {
      send(res, 400, { error: 'invalid_grant' });
      return;
    }
    state.tokens.delete(refresh);
    send(res, 200, issueTokens(user, null));
    return;
  }
  send(res, 400, { error: 'unsupported_grant_type' });
}

// ----------------------------------------------------------------------------------- gateway

function filterCves(url: URL): typeof CVES {
  const severities = listParam(url, 'severity');
  const q = url.searchParams.get('q')?.toLowerCase();
  const kev = url.searchParams.get('kev');
  return CVES.filter(
    (cve) =>
      (severities.length === 0 || severities.includes(cve.severity)) &&
      (q === undefined ||
        q === '' ||
        cve.cveId.toLowerCase().includes(q) ||
        (cve.title ?? '').toLowerCase().includes(q)) &&
      (kev === null || String(cve.inKev) === kev),
  );
}

function listArtifacts(url: URL, permissions: readonly string[]): DownloadArtifactDetail[] {
  const lifecycle = listParam(url, 'lifecycleStatus');
  const scan = listParam(url, 'scanStatus');
  return state.artifacts.filter(
    (artifact) =>
      (permissions.includes('quarantine:read') || artifact.lifecycleStatus === 'released') &&
      (lifecycle.length === 0 || lifecycle.includes(artifact.lifecycleStatus)) &&
      (scan.length === 0 || scan.includes(artifact.scanStatus)),
  );
}

function summary(
  artifact: DownloadArtifactDetail,
): Omit<DownloadArtifactDetail, 'provenance' | 'latestScan'> {
  const { provenance: _provenance, latestScan: _latestScan, ...rest } = artifact;
  return rest;
}

async function gateway(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const authorization = req.headers.authorization ?? '';
  const userKey = state.tokens.get(authorization.replace(/^Bearer /, ''));
  if (userKey === undefined) {
    apiError(res, 401, 'unauthenticated', 'Missing or invalid access token');
    return;
  }
  const user = USERS[userKey].profile;
  const segments = url.pathname
    .replace(/^\/api\/v1\//, '')
    .split('/')
    .map(decodeURIComponent);
  const [resource, id, sub] = segments;
  const method = req.method ?? 'GET';
  const bodyText = method === 'GET' ? '' : await readBody(req);
  state.requests.push({
    method,
    path: url.pathname,
    headers: {
      'if-match': req.headers['if-match'],
      'x-correlation-id': req.headers['x-correlation-id'] as string | undefined,
    },
    body: parseJson(bodyText),
  });

  if (resource !== undefined && state.failing.has(resource)) {
    apiError(res, 500, 'internal_error', 'The service failed (simulated by the e2e mock)');
    return;
  }
  const can = (permission: string): boolean =>
    user.permissions.includes(permission as (typeof user.permissions)[number]);

  if (resource === 'auth' && id === 'logout' && method === 'POST') {
    send(res, 200, { data: { revokedSessions: 1 } });
    return;
  }
  if (resource === 'me' && id === undefined) {
    send(res, 200, { data: user });
    return;
  }
  if (resource === 'cves') {
    if (!can('cve:read')) {
      apiError(res, 403, 'forbidden', 'Missing permission cve:read');
      return;
    }
    if (id === undefined) {
      send(res, 200, page(filterCves(url), url));
      return;
    }
    const cve = CVES.find((entry) => entry.cveId === id);
    if (cve === undefined) {
      apiError(res, 404, 'not_found', 'CVE not found');
      return;
    }
    if (sub === undefined) send(res, 200, { data: cveRecord(cve) }, { etag: '"3"' });
    else if (sub === 'cvss-history') send(res, 200, { data: cveRecord(cve).cvssMetrics });
    else if (sub === 'epss-history')
      send(res, 200, page(cveRecord(cve).epss === null ? [] : [cveRecord(cve).epss], url));
    else apiError(res, 404, 'not_found', 'Unknown route');
    return;
  }
  if (resource === 'download-artifacts') {
    if (!can('download:read')) {
      apiError(res, 403, 'forbidden', 'Missing permission download:read');
      return;
    }
    if (id === undefined) {
      send(res, 200, page(listArtifacts(url, user.permissions).map(summary), url));
      return;
    }
    const artifact = state.artifacts.find((entry) => entry.id === id);
    if (
      artifact === undefined ||
      (!can('quarantine:read') && artifact.lifecycleStatus !== 'released')
    ) {
      apiError(res, 404, 'not_found', 'Artifact not found');
      return;
    }
    if (sub === undefined && method === 'GET') {
      send(res, 200, { data: artifact }, { etag: `"${String(artifact.version)}"` });
    } else if (sub === 'scans') {
      send(res, 200, { data: artifact.latestScan });
    } else if (sub === 'lifecycle-history') {
      send(res, 200, { data: [...(state.lifecycle.get(artifact.id) ?? [])].reverse() });
    } else if (sub === 'lifecycle' && method === 'POST') {
      if (!can('quarantine:manage')) {
        apiError(res, 403, 'forbidden', 'Missing permission quarantine:manage');
        return;
      }
      if (req.headers['if-match'] !== `"${String(artifact.version)}"`) {
        apiError(res, 412, 'precondition_failed', 'The artifact was changed by someone else');
        return;
      }
      const body = parseJson(bodyText) as
        { status?: ArtifactLifecycleStatus; reason?: string } | undefined;
      const target = body?.status;
      if (
        target === undefined ||
        typeof body?.reason !== 'string' ||
        body.reason === '' ||
        !canTransitionLifecycle(artifact.lifecycleStatus, target)
      ) {
        apiError(res, 400, 'validation_failed', 'Invalid lifecycle change');
        return;
      }
      if (target === 'released' && (!artifact.releasable || artifact.scanStatus !== 'clean')) {
        apiError(res, 409, 'not_releasable', 'Only clean artifacts can be released');
        return;
      }
      state.lifecycle.get(artifact.id)?.push({
        id: randomUUID(),
        fromStatus: artifact.lifecycleStatus,
        toStatus: target,
        reason: body.reason,
        actorId: user.id,
        actorUsername: user.username,
        createdAt: new Date().toISOString(),
      });
      artifact.lifecycleStatus = target;
      artifact.releasedAt = target === 'released' ? new Date().toISOString() : artifact.releasedAt;
      artifact.version += 1;
      send(res, 200, { data: summary(artifact) }, { etag: `"${String(artifact.version)}"` });
    } else {
      apiError(res, 404, 'not_found', 'Unknown route');
    }
    return;
  }
  if (resource === 'health' && id === 'services') {
    send(res, 200, {
      data: {
        status: 'ok',
        timestamp: new Date().toISOString(),
        services: [{ service: 'cve-service', status: 'ok', latencyMs: 4 }],
      },
    });
    return;
  }
  // Everything else behaves like a service that is not running, so pages show their
  // "unavailable" states instead of invented data.
  apiError(res, 503, 'service_unavailable', 'Not provided by the e2e mock');
}

// ------------------------------------------------------------------------------------ server

async function control(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
  const body = parseJson(await readBody(req)) as
    { user?: MockUser['key']; fail?: string[] } | undefined;
  if (url.pathname === '/__mock/reset') {
    state = freshState();
    if (body?.user !== undefined) state.nextUser = body.user;
    for (const resource of body?.fail ?? []) state.failing.add(resource);
    send(res, 200, { ok: true });
    return;
  }
  if (url.pathname === '/__mock/requests') {
    send(res, 200, { requests: state.requests });
    return;
  }
  send(res, 404, { error: 'unknown control' });
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${String(PORT)}`);
  const handle = async (): Promise<void> => {
    if (url.pathname.startsWith('/__mock/')) await control(req, res, url);
    else if (url.pathname === `${REALM_PATH}/auth`) authorize(url, res);
    else if (url.pathname === `${REALM_PATH}/token` && req.method === 'POST') await token(req, res);
    else if (url.pathname === `${REALM_PATH}/logout`) {
      const target = url.searchParams.get('post_logout_redirect_uri') ?? 'about:blank';
      res.writeHead(302, { location: target });
      res.end();
    } else if (url.pathname.startsWith('/api/v1/')) await gateway(req, res, url);
    else if (url.pathname === '/health') send(res, 200, { status: 'ok' });
    else send(res, 404, { error: 'not found' });
  };
  handle().catch((error: unknown) => {
    process.stderr.write(
      `mock server error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
    );
    if (!res.headersSent) send(res, 500, { error: 'mock failure' });
  });
});

server.listen(PORT, () => {
  process.stdout.write(
    `e2e mock (Keycloak + API Gateway) listening on http://localhost:${String(PORT)}\n`,
  );
});
