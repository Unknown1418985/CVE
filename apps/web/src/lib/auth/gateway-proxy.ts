import 'server-only';

import { randomUUID } from 'node:crypto';

import { API_PREFIX, CORRELATION_ID_HEADER, IDEMPOTENCY_KEY_HEADER } from '@cve/contracts';
import { NextResponse, type NextRequest } from 'next/server';

import { getServerEnv, type ServerEnv } from '@/lib/env';
import { logger } from '@/lib/logger';

import { CLIENT_HEADER, CLIENT_HEADER_VALUE, isSameOriginRequest } from './request-guards';
import {
  clearSession,
  needsRefresh,
  readSession,
  refreshSession,
  writeSession,
  type Session,
} from './session';

/** Top-level API Gateway resources the browser may reach through the BFF. */
export const PROXIED_RESOURCES: ReadonlySet<string> = new Set([
  'me',
  'roles',
  'permissions',
  'users',
  'audit-logs',
  'cves',
  'sources',
  'sync-runs',
  'vendors',
  'products',
  'cve-associations',
  'poc-repositories',
  'poc-owners',
  'poc-associations',
  'poc-artifacts',
  'poc-references',
  'poc-connectors',
  'poc-discovery-runs',
  'download-sources',
  'download-requests',
  'download-artifacts',
  'exploits',
  'exploit-associations',
  'exploit-assessments',
  'exploitation-evidence',
  'exploit-sources',
  'exploit-sync-runs',
  'health',
]);

const MAX_BODY_BYTES = 1_048_576;
const MAX_QUERY_LENGTH = 4_096;
const SEGMENT_PATTERN = /^[A-Za-z0-9._:@-]{1,200}$/;
const CORRELATION_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function errorResponse(
  status: number,
  code: string,
  message: string,
  correlationId: string,
): NextResponse {
  return NextResponse.json(
    { error: { code, message }, correlationId, timestamp: new Date().toISOString() },
    { status, headers: { 'cache-control': 'no-store', [CORRELATION_ID_HEADER]: correlationId } },
  );
}

/**
 * Validates the path segments: only known resources, no dot segments, no separators or
 * percent-encoded characters that could make the gateway resolve another route.
 */
export function buildGatewayPath(segments: readonly string[]): string | null {
  if (segments.length === 0 || segments.length > 8) return null;
  const [resource] = segments;
  if (resource === undefined || !PROXIED_RESOURCES.has(resource)) return null;
  for (const segment of segments) {
    if (!SEGMENT_PATTERN.test(segment) || segment === '.' || segment === '..') return null;
  }
  return segments.join('/');
}

function isContentRoute(segments: readonly string[]): boolean {
  return segments.length === 3 && segments[0] === 'download-artifacts' && segments[2] === 'content';
}

async function ensureFreshSession(
  env: ServerEnv,
  session: Session,
): Promise<{ session: Session; refreshed: boolean } | 'expired' | 'unavailable'> {
  if (!needsRefresh(session)) return { session, refreshed: false };
  const outcome = await refreshSession(env, session);
  if (outcome.kind === 'refreshed') return { session: outcome.session, refreshed: true };
  return outcome.kind;
}

/**
 * Backend-for-frontend proxy: attaches the session's access token (refreshing it when needed)
 * and forwards the call to the API Gateway. The gateway and every service validate the token
 * and permissions again; this layer only keeps tokens out of the browser.
 */
export async function forwardToGateway(
  request: NextRequest,
  segments: readonly string[],
): Promise<NextResponse> {
  const env = getServerEnv();
  const incomingCorrelation = request.headers.get(CORRELATION_ID_HEADER);
  const correlationId =
    incomingCorrelation !== null && CORRELATION_PATTERN.test(incomingCorrelation)
      ? incomingCorrelation
      : randomUUID();
  const method = request.method.toUpperCase();

  const path = buildGatewayPath(segments);
  if (path === null) return errorResponse(404, 'not_found', 'Unknown API route', correlationId);

  if (MUTATING.has(method)) {
    if (
      !isSameOriginRequest(request.headers, env.PUBLIC_ORIGIN) ||
      request.headers.get(CLIENT_HEADER) !== CLIENT_HEADER_VALUE
    ) {
      return errorResponse(403, 'forbidden', 'Cross-site request refused', correlationId);
    }
  }

  const search = request.nextUrl.search;
  if (search.length > MAX_QUERY_LENGTH) {
    return errorResponse(414, 'uri_too_long', 'Query string is too long', correlationId);
  }

  const stored = readSession(env, request.cookies);
  if (stored === null) {
    return errorResponse(401, 'unauthenticated', 'Sign in to continue', correlationId);
  }
  const fresh = await ensureFreshSession(env, stored);
  if (fresh === 'expired') {
    const response = errorResponse(401, 'session_expired', 'Your session has expired', correlationId);
    clearSession(env, response.cookies);
    return response;
  }
  if (fresh === 'unavailable') {
    return errorResponse(503, 'identity_unavailable', 'The identity provider is unavailable', correlationId);
  }

  const headers = new Headers({
    authorization: `Bearer ${fresh.session.accessToken}`,
    accept: isContentRoute(segments) ? 'application/octet-stream' : 'application/json',
    [CORRELATION_ID_HEADER]: correlationId,
  });
  for (const name of ['if-match', IDEMPOTENCY_KEY_HEADER]) {
    const value = request.headers.get(name);
    if (value !== null && value.length <= 128) headers.set(name, value);
  }

  let body: string | undefined;
  if (MUTATING.has(method)) {
    const contentType = request.headers.get('content-type');
    const text = await request.text();
    if (text.length > 0) {
      if (!contentType?.toLowerCase().startsWith('application/json')) {
        return errorResponse(415, 'unsupported_media_type', 'Only JSON bodies are accepted', correlationId);
      }
      if (Buffer.byteLength(text) > MAX_BODY_BYTES) {
        return errorResponse(413, 'payload_too_large', 'Request body is too large', correlationId);
      }
      headers.set('content-type', 'application/json');
      body = text;
    }
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${env.API_GATEWAY_INTERNAL_URL}/${API_PREFIX}/${path}${search}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body }),
      cache: 'no-store',
      redirect: 'manual',
      signal: AbortSignal.timeout(env.API_PROXY_TIMEOUT_MS),
    });
  } catch (error) {
    const timeout = error instanceof Error && error.name === 'TimeoutError';
    logger.warn(
      { event: 'bff.gateway.unreachable', correlationId, path: segments[0], timeout },
      'API Gateway request failed',
    );
    return errorResponse(
      timeout ? 504 : 502,
      timeout ? 'gateway_timeout' : 'bad_gateway',
      timeout ? 'The API Gateway did not respond in time' : 'The API Gateway is unreachable',
      correlationId,
    );
  }

  const responseHeaders = new Headers({
    'cache-control': 'no-store',
    [CORRELATION_ID_HEADER]: upstream.headers.get(CORRELATION_ID_HEADER) ?? correlationId,
  });
  const etag = upstream.headers.get('etag');
  if (etag !== null) responseHeaders.set('etag', etag);

  if (isContentRoute(segments) && upstream.ok) {
    // Artifact content is always an opaque attachment: never rendered, sniffed or cached.
    responseHeaders.set('content-type', 'application/octet-stream');
    responseHeaders.set('x-content-type-options', 'nosniff');
    responseHeaders.set('content-security-policy', "default-src 'none'; sandbox");
    const disposition = upstream.headers.get('content-disposition');
    responseHeaders.set(
      'content-disposition',
      disposition !== null && /^attachment; filename="artifact-[0-9a-f-]{36}(\.[a-z0-9.]{1,12})?"$/.test(disposition)
        ? disposition
        : 'attachment; filename="artifact.bin"',
    );
    for (const name of ['content-length', 'x-artifact-sha256', 'repr-digest']) {
      const value = upstream.headers.get(name);
      if (value !== null) responseHeaders.set(name, value);
    }
  } else {
    responseHeaders.set('content-type', upstream.headers.get('content-type') ?? 'application/json');
  }

  const response = new NextResponse(upstream.status === 204 ? null : upstream.body, {
    status: upstream.status,
    headers: responseHeaders,
  });
  if (fresh.refreshed) writeSession(env, response.cookies, fresh.session);
  return response;
}
