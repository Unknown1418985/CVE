import { NextResponse, type NextRequest } from 'next/server';

import { exchangeCode, OidcError, readClaims } from '@/lib/auth/oidc';
import {
  clearTransaction,
  readTransaction,
  sessionFromTokens,
  writeSession,
} from '@/lib/auth/session';
import { getServerEnv, type ServerEnv } from '@/lib/env';
import { logger } from '@/lib/logger';

export const dynamic = 'force-dynamic';

const FAILURES = {
  denied: 'access_denied',
  state: 'invalid_state',
  exchange: 'token_exchange_failed',
  unavailable: 'identity_provider_unavailable',
} as const;

function fail(env: ServerEnv, reason: (typeof FAILURES)[keyof typeof FAILURES]): NextResponse {
  const response = NextResponse.redirect(`${env.PUBLIC_ORIGIN}/signed-out?error=${reason}`, 303);
  clearTransaction(env, response.cookies);
  return response;
}

/** OIDC redirect URI: validates `state`, exchanges the code with the PKCE verifier, checks `nonce`. */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const env = getServerEnv();
  const params = request.nextUrl.searchParams;
  const transaction = readTransaction(env, request.cookies);

  if (params.get('error') !== null) {
    // Keycloak reports a cancelled application-initiated action as an error; the session stays.
    if (params.get('error') === 'access_denied' && transaction !== null) {
      const response = NextResponse.redirect(`${env.PUBLIC_ORIGIN}${transaction.returnTo}`, 303);
      clearTransaction(env, response.cookies);
      return response;
    }
    logger.warn({ event: 'oidc.callback.error', error: params.get('error') }, 'sign-in refused');
    return fail(env, FAILURES.denied);
  }

  const code = params.get('code');
  const state = params.get('state');
  if (transaction === null || code === null || state === null || state !== transaction.state) {
    logger.warn({ event: 'oidc.callback.invalid-state' }, 'sign-in callback without a matching transaction');
    return fail(env, FAILURES.state);
  }

  try {
    const tokens = await exchangeCode(env, code, transaction.codeVerifier);
    const idClaims = tokens.idToken === null ? null : readClaims(tokens.idToken);
    if (idClaims?.nonce !== transaction.nonce) {
      logger.warn({ event: 'oidc.callback.nonce-mismatch' }, 'ID token nonce does not match');
      return fail(env, FAILURES.exchange);
    }
    const session = sessionFromTokens(tokens);
    if (session === null) return fail(env, FAILURES.exchange);
    const response = NextResponse.redirect(`${env.PUBLIC_ORIGIN}${transaction.returnTo}`, 303);
    response.headers.set('cache-control', 'no-store');
    clearTransaction(env, response.cookies);
    writeSession(env, response.cookies, session);
    logger.info({ event: 'oidc.callback.signed-in', subject: session.subject }, 'user signed in');
    return response;
  } catch (error) {
    const unavailable = error instanceof OidcError && !error.invalidGrant;
    logger.error(
      { event: 'oidc.callback.exchange-failed', error: error instanceof Error ? error.message : 'unknown' },
      'authorization code exchange failed',
    );
    return fail(env, unavailable ? FAILURES.unavailable : FAILURES.exchange);
  }
}
