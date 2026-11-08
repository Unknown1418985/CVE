import { NextResponse, type NextRequest } from 'next/server';

import {
  buildAuthorizationUrl,
  isKeycloakActionName,
  randomToken,
  safeReturnTo,
} from '@/lib/auth/oidc';
import { writeTransaction } from '@/lib/auth/session';
import { getServerEnv } from '@/lib/env';

export const dynamic = 'force-dynamic';

/**
 * Starts the OIDC authorization code flow with PKCE (S256), `state` and `nonce`. With
 * `?action=update-password|configure-totp` it starts a Keycloak application-initiated action.
 */
export function GET(request: NextRequest): NextResponse {
  const env = getServerEnv();
  const actionParam = request.nextUrl.searchParams.get('action');
  const action =
    actionParam !== null && isKeycloakActionName(actionParam) ? actionParam : undefined;
  const transaction = {
    state: randomToken(),
    nonce: randomToken(),
    codeVerifier: randomToken(48),
    returnTo: safeReturnTo(request.nextUrl.searchParams.get('returnTo')),
    createdAt: Date.now(),
  };
  const response = NextResponse.redirect(
    buildAuthorizationUrl(env, { ...transaction, action }),
    303,
  );
  response.headers.set('cache-control', 'no-store');
  writeTransaction(env, response.cookies, transaction);
  return response;
}
