import { describe, expect, it } from 'vitest';

import {
  AuthenticationError,
  IdentityProviderUnavailableError,
  IntrospectionSessionChecker,
  type AuthenticatedPrincipal,
} from '../src/index.js';

const principal = (overrides: Partial<AuthenticatedPrincipal> = {}): AuthenticatedPrincipal => ({
  subject: 'user-1',
  username: 'user',
  email: undefined,
  emailVerified: false,
  name: undefined,
  givenName: undefined,
  familyName: undefined,
  roles: ['viewer'],
  permissions: ['cve:read'],
  sessionId: 'session-1',
  tokenId: 'token-1',
  clientId: 'cve-web',
  issuedAt: new Date(),
  expiresAt: new Date(Date.now() + 300_000),
  ...overrides,
});

function checker(answers: (() => Promise<Response>)[], now = { value: Date.now() }) {
  const calls: RequestInit[] = [];
  const instance = new IntrospectionSessionChecker({
    introspectionUrl: 'http://keycloak.test/introspect',
    clientId: 'cve-api',
    clientSecret: 'secret-value-0000',
    cacheTtlMs: 10_000,
    now: () => now.value,
    fetch: (_input, init) => {
      calls.push(init ?? {});
      const answer = answers.shift();
      if (!answer) throw new Error('unexpected introspection call');
      return answer();
    },
  });
  return { instance, calls, now };
}

describe('IntrospectionSessionChecker', () => {
  it('accepts active sessions and caches the answer per session', async () => {
    const { instance, calls, now } = checker([
      () => Promise.resolve(Response.json({ active: true, sub: 'user-1' })),
      () => Promise.resolve(Response.json({ active: true, sub: 'user-1' })),
    ]);
    await instance.assertActive('token-a', principal());
    await instance.assertActive('token-b', principal());
    expect(calls).toHaveLength(1);
    const headers = calls[0]!.headers as Record<string, string>;
    expect(headers['authorization']).toMatch(/^Basic /);
    expect(calls[0]!.body as string).toContain('token=token-a');

    now.value += 11_000;
    await instance.assertActive('token-c', principal());
    expect(calls).toHaveLength(2);
  });

  it('rejects inactive sessions and remembers them', async () => {
    const { instance, calls } = checker([() => Promise.resolve(Response.json({ active: false }))]);
    await expect(instance.assertActive('t', principal())).rejects.toBeInstanceOf(
      AuthenticationError,
    );
    await expect(instance.assertActive('t', principal())).rejects.toBeInstanceOf(
      AuthenticationError,
    );
    expect(calls).toHaveLength(1);
  });

  it('rejects tokens whose introspected subject differs', async () => {
    const { instance } = checker([
      () => Promise.resolve(Response.json({ active: true, sub: 'someone-else' })),
    ]);
    await expect(instance.assertActive('t', principal())).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it('treats a locally revoked session as inactive without asking Keycloak', async () => {
    const { instance, calls } = checker([]);
    instance.invalidate('session-1');
    await expect(instance.assertActive('t', principal())).rejects.toBeInstanceOf(
      AuthenticationError,
    );
    expect(calls).toHaveLength(0);
  });

  it('fails closed when Keycloak is unavailable or answers unexpectedly', async () => {
    const { instance } = checker([
      () => Promise.reject(new Error('ECONNREFUSED')),
      () => Promise.resolve(new Response('nope', { status: 500 })),
      () => Promise.resolve(Response.json({ unexpected: true })),
    ]);
    for (let i = 0; i < 3; i += 1) {
      await expect(instance.assertActive('t', principal())).rejects.toBeInstanceOf(
        IdentityProviderUnavailableError,
      );
    }
  });
});
