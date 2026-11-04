import { createRemoteJWKSet, errors as joseErrors, jwtVerify, type JWTVerifyGetKey } from 'jose';

import { AuthenticationError, IdentityProviderUnavailableError } from './errors.js';
import {
  accessTokenClaimsSchema,
  principalFromClaims,
  type AuthenticatedPrincipal,
} from './principal.js';

/** Asymmetric algorithms Keycloak signs with. `none` and HMAC are never accepted. */
export const ACCEPTED_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
] as const;

export interface TokenVerifierOptions {
  /** Expected `iss`, e.g. `https://cve.example.com/auth/realms/cve-platform`. */
  readonly issuer: string;
  /** Expected `aud` (the `cve-api` resource server). */
  readonly audience: string;
  /** Signing keys: a JWKS URL (internal Keycloak address) or a key resolver (tests). */
  readonly keys: { readonly jwksUrl: string; readonly timeoutMs?: number } | JWTVerifyGetKey;
  /** Allowed clock skew. Default 30 seconds. */
  readonly clockToleranceSeconds?: number;
  /** Clients (`azp`) allowed to call the API; any client when omitted. */
  readonly allowedClients?: readonly string[];
}

export interface TokenVerifier {
  verify(token: string): Promise<AuthenticatedPrincipal>;
}

const MAX_TOKEN_LENGTH = 16_384;

/** Extracts the token from an `Authorization: Bearer …` header value. */
export function extractBearerToken(header: string | readonly string[] | undefined): string {
  if (header === undefined || header.length === 0) {
    throw new AuthenticationError('missing-token', 'Bearer token required');
  }
  if (typeof header !== 'string') {
    throw new AuthenticationError('malformed-header', 'Multiple Authorization headers');
  }
  const match = /^Bearer ([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)$/.exec(header.trim());
  if (match?.[1] === undefined || match[1].length > MAX_TOKEN_LENGTH) {
    throw new AuthenticationError(
      'malformed-header',
      'Authorization header must be "Bearer <jwt>"',
    );
  }
  return match[1];
}

function isNetworkFailure(error: unknown): boolean {
  return (
    error instanceof joseErrors.JWKSTimeout ||
    (error instanceof Error && !(error instanceof joseErrors.JOSEError))
  );
}

/**
 * Validates Keycloak access tokens locally: signature against the realm's JWKS (cached and
 * refreshed on unknown `kid`), algorithm allowlist, issuer, audience, expiry, `typ: Bearer`.
 */
export function createTokenVerifier(options: TokenVerifierOptions): TokenVerifier {
  const getKey: JWTVerifyGetKey =
    typeof options.keys === 'function'
      ? options.keys
      : createRemoteJWKSet(new URL(options.keys.jwksUrl), {
          timeoutDuration: options.keys.timeoutMs ?? 5_000,
          cooldownDuration: 30_000,
          cacheMaxAge: 10 * 60_000,
        });
  const allowedClients = options.allowedClients ? new Set(options.allowedClients) : undefined;

  return {
    async verify(token) {
      let payload: unknown;
      try {
        ({ payload } = await jwtVerify(token, getKey, {
          issuer: options.issuer,
          audience: options.audience,
          algorithms: [...ACCEPTED_ALGORITHMS],
          clockTolerance: options.clockToleranceSeconds ?? 30,
          requiredClaims: ['sub', 'exp'],
        }));
      } catch (error) {
        if (error instanceof joseErrors.JWTExpired) {
          throw new AuthenticationError('expired-token', 'Token has expired', { cause: error });
        }
        if (error instanceof joseErrors.JWTClaimValidationFailed) {
          if (error.claim === 'iss') {
            throw new AuthenticationError('wrong-issuer', 'Token issuer is not trusted', {
              cause: error,
            });
          }
          if (error.claim === 'aud') {
            throw new AuthenticationError('wrong-audience', 'Token is not intended for this API', {
              cause: error,
            });
          }
        }
        if (isNetworkFailure(error)) {
          throw new IdentityProviderUnavailableError('Signing keys could not be retrieved', {
            cause: error,
          });
        }
        throw new AuthenticationError('invalid-token', 'Token is invalid', { cause: error });
      }

      const claims = accessTokenClaimsSchema.safeParse(payload);
      if (!claims.success) {
        throw new AuthenticationError('invalid-token', 'Token claims are invalid');
      }
      // Keycloak marks access tokens `Bearer`; ID and refresh tokens use other types.
      if (claims.data.typ !== undefined && claims.data.typ !== 'Bearer') {
        throw new AuthenticationError('wrong-token-type', 'Only access tokens are accepted');
      }
      if (
        allowedClients &&
        (claims.data.azp === undefined || !allowedClients.has(claims.data.azp))
      ) {
        throw new AuthenticationError('wrong-audience', 'Token was issued to an unknown client');
      }
      return principalFromClaims(claims.data);
    },
  };
}
