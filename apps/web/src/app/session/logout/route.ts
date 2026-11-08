import { API_PREFIX } from '@cve/contracts';
import { NextResponse, type NextRequest } from 'next/server';

import { endSessionUrl } from '@/lib/auth/oidc';
import { CLIENT_HEADER, CLIENT_HEADER_VALUE, isSameOriginRequest } from '@/lib/auth/request-guards';
import { clearSession, readSession } from '@/lib/auth/session';
import { getServerEnv } from '@/lib/env';
import { logger } from '@/lib/logger';

export const dynamic = 'force-dynamic';

/**
 * Secure logout: ends the Keycloak session through the API Gateway (which also stops accepting
 * the access token at once), then discards the cookies. If the gateway cannot be reached, the
 * browser is sent to Keycloak's own logout endpoint so the SSO session still ends.
 *
 * Called with `fetch` (custom header, same origin) and answers with the URL to navigate to, so
 * the cross-origin Keycloak redirect is a plain navigation rather than a form redirect.
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const env = getServerEnv();
  if (
    !isSameOriginRequest(request.headers, env.PUBLIC_ORIGIN) ||
    request.headers.get(CLIENT_HEADER) !== CLIENT_HEADER_VALUE
  ) {
    return NextResponse.json(
      {
        error: { code: 'forbidden', message: 'Cross-site logout refused' },
        timestamp: new Date().toISOString(),
      },
      { status: 403 },
    );
  }
  const session = readSession(env, request.cookies);
  let target = `${env.PUBLIC_ORIGIN}/signed-out`;
  if (session !== null) {
    try {
      const response = await fetch(`${env.API_GATEWAY_INTERNAL_URL}/${API_PREFIX}/auth/logout`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${session.accessToken}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify({}),
        cache: 'no-store',
        signal: AbortSignal.timeout(env.API_PROXY_TIMEOUT_MS),
      });
      // 401: the access token already expired; Keycloak must end the session itself.
      if (!response.ok) target = endSessionUrl(env, null);
    } catch {
      target = endSessionUrl(env, null);
    }
    logger.info({ event: 'session.logout', subject: session.subject }, 'user signed out');
  }
  const response = NextResponse.json(
    { redirectTo: target },
    { headers: { 'cache-control': 'no-store' } },
  );
  clearSession(env, response.cookies);
  return response;
}
