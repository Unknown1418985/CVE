import {
  createTokenVerifier,
  IntrospectionSessionChecker,
  keycloakRealmUrls,
  type SessionChecker,
  type TokenVerifier,
} from '@cve/auth';

import type { Env } from '../config/env.js';

export interface GatewayAuth {
  readonly verifier: TokenVerifier;
  readonly sessionChecker: (SessionChecker & { invalidate?(sessionId: string): void }) | undefined;
}

/** Token validation against the realm JWKS (internal URL) with the public issuer. */
export function createGatewayAuth(env: Env, fetchFn?: typeof fetch): GatewayAuth {
  const internal = keycloakRealmUrls(env.KEYCLOAK_URL, env.KEYCLOAK_REALM);
  const publicUrls = keycloakRealmUrls(env.KEYCLOAK_PUBLIC_URL, env.KEYCLOAK_REALM);
  const verifier = createTokenVerifier({
    issuer: publicUrls.issuer,
    audience: env.KEYCLOAK_AUDIENCE,
    keys: { jwksUrl: internal.jwks, timeoutMs: env.KEYCLOAK_TIMEOUT_MS },
  });
  const sessionChecker =
    env.AUTH_SESSION_CHECK_ENABLED && env.KEYCLOAK_INTROSPECTION_CLIENT_SECRET !== undefined
      ? new IntrospectionSessionChecker({
          introspectionUrl: internal.introspection,
          clientId: env.KEYCLOAK_INTROSPECTION_CLIENT_ID,
          clientSecret: env.KEYCLOAK_INTROSPECTION_CLIENT_SECRET,
          cacheTtlMs: env.AUTH_SESSION_CACHE_TTL_MS,
          timeoutMs: env.KEYCLOAK_TIMEOUT_MS,
          ...(fetchFn ? { fetch: fetchFn } : {}),
        })
      : undefined;
  return { verifier, sessionChecker };
}
