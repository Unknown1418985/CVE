import { randomUUID } from 'node:crypto';

import { beforeAll, describe, expect, it } from 'vitest';

import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import {
  AuthenticationError,
  createTokenVerifier,
  extractBearerToken,
  IdentityProviderUnavailableError,
  keycloakRealmUrls,
  type TokenVerifier,
} from '../src/index.js';

let issuer: TestTokenIssuer;
let verifier: TokenVerifier;
const userId = randomUUID();

async function rejection(promise: Promise<unknown>): Promise<AuthenticationError> {
  const error: unknown = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(AuthenticationError);
  return error as AuthenticationError;
}

beforeAll(async () => {
  issuer = await createTestTokenIssuer();
  verifier = createTokenVerifier({
    issuer: issuer.issuer,
    audience: issuer.audience,
    keys: issuer.getKey,
  });
});

describe('extractBearerToken', () => {
  it('accepts a well-formed bearer header', () => {
    expect(extractBearerToken('Bearer a.b.c')).toBe('a.b.c');
  });

  it('rejects missing, repeated and malformed headers', () => {
    expect(() => extractBearerToken(undefined)).toThrow(/required/);
    expect(() => extractBearerToken(['Bearer a.b.c', 'Bearer d.e.f'])).toThrow(/Multiple/);
    expect(() => extractBearerToken('Basic dXNlcjpwYXNz')).toThrow(/Bearer <jwt>/);
    expect(() => extractBearerToken('Bearer not-a-jwt')).toThrow(/Bearer <jwt>/);
    expect(() => extractBearerToken(`Bearer ${'a'.repeat(20_000)}.b.c`)).toThrow();
  });
});

describe('createTokenVerifier', () => {
  it('maps a valid token to a principal with platform roles and permissions', async () => {
    const token = await issuer.tokenFor(userId, ['security-analyst', 'offline_access'], {
      email: 'analyst@example.com',
      email_verified: true,
    });
    const principal = await verifier.verify(token);
    expect(principal.subject).toBe(userId);
    expect(principal.roles).toEqual(['security-analyst']);
    expect(principal.permissions).toContain('asset:manage');
    expect(principal.permissions).not.toContain('user:manage');
    expect(principal.email).toBe('analyst@example.com');
    expect(principal.emailVerified).toBe(true);
    expect(principal.sessionId).toBeDefined();
    expect(principal.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it('falls back to realm_access.roles', async () => {
    const token = await issuer.sign({ sub: userId, realm_access: { roles: ['viewer'] } });
    expect((await verifier.verify(token)).roles).toEqual(['viewer']);
  });

  it('gives a token without platform roles no permissions', async () => {
    const token = await issuer.sign({ sub: userId, roles: ['root', 'uma_authorization'] });
    const principal = await verifier.verify(token);
    expect(principal.roles).toEqual([]);
    expect(principal.permissions).toEqual([]);
  });

  it('rejects expired tokens', async () => {
    const token = await issuer.sign({ sub: userId }, { expiresInSeconds: -120 });
    expect((await rejection(verifier.verify(token))).reason).toBe('expired-token');
  });

  it('rejects tokens from another issuer or for another audience', async () => {
    const foreign = await issuer.sign({ sub: userId }, { issuer: 'https://evil.example.com' });
    expect((await rejection(verifier.verify(foreign))).reason).toBe('wrong-issuer');
    const otherAudience = await issuer.sign({ sub: userId }, { audience: 'account' });
    expect((await rejection(verifier.verify(otherAudience))).reason).toBe('wrong-audience');
  });

  it('rejects tokens signed with an unknown key', async () => {
    const token = await issuer.sign({ sub: userId }, { untrustedKey: true });
    expect((await rejection(verifier.verify(token))).reason).toBe('invalid-token');
  });

  it('rejects tampered tokens and unsigned tokens', async () => {
    const token = await issuer.tokenFor(userId, ['viewer']);
    const [header, payload, signature] = token.split('.');
    const claims = JSON.parse(Buffer.from(payload!, 'base64url').toString()) as Record<
      string,
      unknown
    >;
    claims['roles'] = ['super-admin'];
    const forged = `${header!}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${signature!}`;
    expect((await rejection(verifier.verify(forged))).reason).toBe('invalid-token');

    const none = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${payload!}.`;
    expect((await rejection(verifier.verify(none))).reason).toBe('invalid-token');
  });

  it('rejects ID and refresh tokens', async () => {
    const token = await issuer.sign({ sub: userId, typ: 'ID' });
    expect((await rejection(verifier.verify(token))).reason).toBe('wrong-token-type');
  });

  it('restricts the requesting client when configured', async () => {
    const strict = createTokenVerifier({
      issuer: issuer.issuer,
      audience: issuer.audience,
      keys: issuer.getKey,
      allowedClients: ['cve-web'],
    });
    await expect(strict.verify(await issuer.sign({ sub: userId }))).resolves.toBeDefined();
    const other = await issuer.sign({ sub: userId, azp: 'admin-cli' });
    expect((await rejection(strict.verify(other))).reason).toBe('wrong-audience');
  });

  it('reports an unreachable JWKS endpoint as an identity provider outage', async () => {
    const remote = createTokenVerifier({
      issuer: issuer.issuer,
      audience: issuer.audience,
      keys: { jwksUrl: 'http://127.0.0.1:9/certs', timeoutMs: 500 },
    });
    await expect(remote.verify(await issuer.tokenFor(userId, ['viewer']))).rejects.toBeInstanceOf(
      IdentityProviderUnavailableError,
    );
  });
});

describe('keycloakRealmUrls', () => {
  it('builds realm endpoints and validates the realm name', () => {
    const urls = keycloakRealmUrls('http://keycloak:8180/auth/', 'cve-platform');
    expect(urls.issuer).toBe('http://keycloak:8180/auth/realms/cve-platform');
    expect(urls.jwks).toBe(
      'http://keycloak:8180/auth/realms/cve-platform/protocol/openid-connect/certs',
    );
    expect(urls.admin).toBe('http://keycloak:8180/auth/admin/realms/cve-platform');
    expect(() => keycloakRealmUrls('http://k', '../master')).toThrow();
  });
});
