import 'server-only';

import { createHash, randomBytes } from 'node:crypto';

import { z } from 'zod';

import type { ServerEnv } from '@/lib/env';

/** Keycloak application-initiated actions the web client may start (see docs/identity.md). */
export const KEYCLOAK_ACTIONS = {
  'update-password': 'UPDATE_PASSWORD',
  'configure-totp': 'CONFIGURE_TOTP',
} as const;
export type KeycloakActionName = keyof typeof KEYCLOAK_ACTIONS;

export function isKeycloakActionName(value: string): value is KeycloakActionName {
  return Object.hasOwn(KEYCLOAK_ACTIONS, value);
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** RFC 7636 S256 code challenge. */
export function codeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

function realmUrl(base: string, realm: string): string {
  return `${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect`;
}

export function redirectUri(env: ServerEnv): string {
  return `${env.PUBLIC_ORIGIN}/session/callback`;
}

export function buildAuthorizationUrl(
  env: ServerEnv,
  params: {
    state: string;
    nonce: string;
    codeVerifier: string;
    action?: KeycloakActionName | undefined;
  },
): string {
  const url = new URL(`${realmUrl(env.KEYCLOAK_PUBLIC_URL, env.KEYCLOAK_REALM)}/auth`);
  url.searchParams.set('client_id', env.KEYCLOAK_WEB_CLIENT_ID);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('redirect_uri', redirectUri(env));
  url.searchParams.set('state', params.state);
  url.searchParams.set('nonce', params.nonce);
  url.searchParams.set('code_challenge', codeChallenge(params.codeVerifier));
  url.searchParams.set('code_challenge_method', 'S256');
  if (params.action !== undefined) {
    url.searchParams.set('kc_action', KEYCLOAK_ACTIONS[params.action]);
  }
  return url.href;
}

export function endSessionUrl(env: ServerEnv, idTokenHint: string | null): string {
  const url = new URL(`${realmUrl(env.KEYCLOAK_PUBLIC_URL, env.KEYCLOAK_REALM)}/logout`);
  url.searchParams.set('client_id', env.KEYCLOAK_WEB_CLIENT_ID);
  url.searchParams.set('post_logout_redirect_uri', `${env.PUBLIC_ORIGIN}/signed-out`);
  if (idTokenHint !== null) url.searchParams.set('id_token_hint', idTokenHint);
  return url.href;
}

const tokenResponseSchema = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1),
  id_token: z.string().min(1).optional(),
  token_type: z.string().refine((value) => value.toLowerCase() === 'bearer'),
  expires_in: z.number().int().positive(),
  refresh_expires_in: z.number().int().min(0).optional(),
});

export interface TokenSet {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly idToken: string | null;
  /** Epoch milliseconds. */
  readonly accessExpiresAt: number;
  /** Epoch milliseconds; `null` when Keycloak issued a token without idle expiry. */
  readonly refreshExpiresAt: number | null;
}

export class OidcError extends Error {
  constructor(
    message: string,
    /** True when the refresh token or code is no longer valid (the user must sign in again). */
    readonly invalidGrant: boolean,
  ) {
    super(message);
    this.name = 'OidcError';
  }
}

async function tokenRequest(
  env: ServerEnv,
  body: URLSearchParams,
  fetchFn: typeof fetch,
  now: () => number,
): Promise<TokenSet> {
  let response: Response;
  try {
    response = await fetchFn(`${realmUrl(env.KEYCLOAK_URL, env.KEYCLOAK_REALM)}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body,
      cache: 'no-store',
      signal: AbortSignal.timeout(env.KEYCLOAK_TIMEOUT_MS),
    });
  } catch {
    throw new OidcError('Keycloak is unreachable', false);
  }
  if (!response.ok) {
    let invalidGrant = false;
    try {
      const payload = (await response.json()) as { error?: unknown };
      invalidGrant = payload.error === 'invalid_grant';
    } catch {
      // Body is not JSON; treat as a server error.
    }
    throw new OidcError(`Keycloak token endpoint answered HTTP ${response.status}`, invalidGrant);
  }
  const parsed = tokenResponseSchema.safeParse(await response.json());
  if (!parsed.success) throw new OidcError('Keycloak returned an unexpected token response', false);
  const issuedAt = now();
  return {
    accessToken: parsed.data.access_token,
    refreshToken: parsed.data.refresh_token,
    idToken: parsed.data.id_token ?? null,
    accessExpiresAt: issuedAt + parsed.data.expires_in * 1000,
    refreshExpiresAt:
      parsed.data.refresh_expires_in === undefined || parsed.data.refresh_expires_in === 0
        ? null
        : issuedAt + parsed.data.refresh_expires_in * 1000,
  };
}

export function exchangeCode(
  env: ServerEnv,
  code: string,
  codeVerifier: string,
  fetchFn: typeof fetch = fetch,
  now: () => number = Date.now,
): Promise<TokenSet> {
  return tokenRequest(
    env,
    new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: env.KEYCLOAK_WEB_CLIENT_ID,
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri(env),
    }),
    fetchFn,
    now,
  );
}

export function refreshTokenSet(
  env: ServerEnv,
  refreshToken: string,
  fetchFn: typeof fetch = fetch,
  now: () => number = Date.now,
): Promise<TokenSet> {
  return tokenRequest(
    env,
    new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: env.KEYCLOAK_WEB_CLIENT_ID,
      refresh_token: refreshToken,
    }),
    fetchFn,
    now,
  );
}

const claimsSchema = z.looseObject({
  sub: z.string().min(1),
  preferred_username: z.string().optional(),
  sid: z.string().optional(),
  nonce: z.string().optional(),
});
export type TokenClaims = z.infer<typeof claimsSchema>;

/**
 * Reads the claims of a JWT received directly from Keycloak's token endpoint over the
 * back channel. The signature is verified by the API Gateway and every service on each call;
 * here the claims only identify the session and check the nonce.
 */
export function readClaims(jwt: string): TokenClaims | null {
  const segment = jwt.split('.')[1];
  if (segment === undefined) return null;
  try {
    const parsed = claimsSchema.safeParse(
      JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')),
    );
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/** Accepts only same-origin relative paths, so a crafted `returnTo` cannot redirect elsewhere. */
export function safeReturnTo(value: string | null | undefined): string {
  if (value === null || value === undefined || value === '') return '/';
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/';
  // eslint-disable-next-line no-control-regex -- rejecting control characters is the purpose
  if (/[\u0000-\u001F\u007F]/.test(value)) return '/';
  if (value.startsWith('/session/') || value.startsWith('/bff/')) return '/';
  return value.length > 2_000 ? '/' : value;
}
