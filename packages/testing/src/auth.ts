import { randomUUID } from 'node:crypto';

import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JSONWebKeySet,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose';

export const TEST_ISSUER = 'http://keycloak.test/auth/realms/cve-platform';
export const TEST_AUDIENCE = 'cve-api';

export interface TestTokenClaims extends JWTPayload {
  readonly roles?: readonly string[];
  readonly sid?: string;
  readonly preferred_username?: string;
  readonly email?: string;
  readonly typ?: string;
  readonly azp?: string;
}

export interface SignOptions {
  /** Lifetime in seconds (negative for an already expired token). Default 300. */
  readonly expiresInSeconds?: number;
  readonly issuer?: string;
  readonly audience?: string | readonly string[];
  /** Sign with a key that is not in the JWKS. */
  readonly untrustedKey?: boolean;
}

export interface TestTokenIssuer {
  readonly issuer: string;
  readonly audience: string;
  readonly jwks: JSONWebKeySet;
  readonly getKey: JWTVerifyGetKey;
  sign(claims: TestTokenClaims, options?: SignOptions): Promise<string>;
  /** A typical access token for a user with the given roles. */
  tokenFor(userId: string, roles: readonly string[], extra?: TestTokenClaims): Promise<string>;
}

/** Creates an in-memory RS256 issuer that mimics Keycloak access tokens for tests. */
export async function createTestTokenIssuer(): Promise<TestTokenIssuer> {
  const trusted = await generateKeyPair('RS256', { extractable: true });
  const untrusted = await generateKeyPair('RS256');
  const kid = randomUUID();
  const jwk = await exportJWK(trusted.publicKey);
  const jwks: JSONWebKeySet = { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] };

  const sign: TestTokenIssuer['sign'] = async (claims, options = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const { audience } = options;
    return new SignJWT({ typ: 'Bearer', azp: 'cve-web', ...claims })
      .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
      .setIssuer(options.issuer ?? TEST_ISSUER)
      .setAudience(
        audience === undefined
          ? TEST_AUDIENCE
          : typeof audience === 'string'
            ? audience
            : [...audience],
      )
      .setIssuedAt(now)
      .setExpirationTime(now + (options.expiresInSeconds ?? 300))
      .setJti(randomUUID())
      .sign(options.untrustedKey === true ? untrusted.privateKey : trusted.privateKey);
  };

  return {
    issuer: TEST_ISSUER,
    audience: TEST_AUDIENCE,
    jwks,
    getKey: createLocalJWKSet(jwks),
    sign,
    tokenFor: (userId, roles, extra = {}) =>
      sign({
        sub: userId,
        sid: randomUUID(),
        preferred_username: `user-${userId.slice(0, 8)}`,
        email: `${userId.slice(0, 8)}@example.com`,
        roles,
        ...extra,
      }),
  };
}
