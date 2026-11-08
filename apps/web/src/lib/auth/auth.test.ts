import { describe, expect, it, vi } from 'vitest';

import { parseServerEnv } from '@/lib/env';

import { buildGatewayPath } from './gateway-proxy';
import { buildAuthorizationUrl, codeChallenge, isKeycloakActionName, safeReturnTo } from './oidc';
import { isSameOriginRequest } from './request-guards';
import { deriveKey, seal, unseal } from './seal';
import {
  SESSION_COOKIE,
  clearSession,
  needsRefresh,
  readSession,
  readTransaction,
  refreshSession,
  writeSession,
  writeTransaction,
  type CookieOptions,
  type Session,
} from './session';

const env = parseServerEnv({
  WEB_SESSION_SECRET: 'test-secret-that-is-at-least-32-characters-long',
  PUBLIC_ORIGIN: 'https://cve.example.test',
  KEYCLOAK_PUBLIC_URL: 'https://cve.example.test/auth',
  KEYCLOAK_URL: 'http://keycloak:8180/auth',
});

class Jar {
  readonly values = new Map<string, { value: string; options: CookieOptions }>();
  get(name: string): { value: string } | undefined {
    const entry = this.values.get(name);
    return entry === undefined || entry.value === '' ? undefined : { value: entry.value };
  }
  set(name: string, value: string, options: CookieOptions): void {
    this.values.set(name, { value, options });
  }
}

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'RS256' })}.${encode(payload)}.signature`;
}

function session(overrides: Partial<Session> = {}): Session {
  return {
    accessToken: jwt({ sub: 'user-1' }),
    refreshToken: 'refresh-1',
    accessExpiresAt: Date.now() + 300_000,
    refreshExpiresAt: Date.now() + 1_800_000,
    subject: 'user-1',
    username: 'analyst',
    ...overrides,
  };
}

describe('seal', () => {
  const key = deriveKey('another-secret-with-enough-length-0000', 'test');

  it('round-trips a value', () => {
    expect(unseal(seal({ a: 1 }, key, 'p'), key, 'p')).toEqual({ a: 1 });
  });

  it('rejects another purpose, another key and tampering', () => {
    const token = seal({ a: 1 }, key, 'p');
    expect(unseal(token, key, 'q')).toBeNull();
    expect(
      unseal(token, deriveKey('different-secret-with-enough-length-1', 'test'), 'p'),
    ).toBeNull();
    const raw = Buffer.from(token, 'base64url');
    raw[14] = (raw[14] ?? 0) ^ 1;
    expect(unseal(raw.toString('base64url'), key, 'p')).toBeNull();
    expect(unseal('short', key, 'p')).toBeNull();
  });
});

describe('session cookies', () => {
  it('writes an encrypted, httpOnly, secure cookie that reads back', () => {
    const jar = new Jar();
    const value = session();
    writeSession(env, jar, value);
    const cookie = jar.values.get(SESSION_COOKIE);
    expect(cookie?.options).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
    });
    expect(cookie?.value).not.toContain('analyst');
    expect(cookie?.value).not.toContain('refresh-1');
    expect(readSession(env, jar)).toEqual(value);
  });

  it('chunks large sessions across cookies and clears unused chunks', () => {
    const jar = new Jar();
    writeSession(
      env,
      jar,
      session({ accessToken: jwt({ sub: 'user-1', padding: 'x'.repeat(5_000) }) }),
    );
    expect(jar.get(`${SESSION_COOKIE}.1`)).toBeDefined();
    expect(jar.values.get(`${SESSION_COOKIE}.3`)?.options.maxAge).toBe(0);
    expect(readSession(env, jar)?.subject).toBe('user-1');
  });

  it('treats an expired refresh token, a foreign secret or cleared cookies as signed out', () => {
    const jar = new Jar();
    writeSession(env, jar, session({ refreshExpiresAt: Date.now() + 1_000 }));
    expect(readSession(env, jar, Date.now() + 2_000)).toBeNull();
    expect(readSession({ ...env, WEB_SESSION_SECRET: 'x'.repeat(40) }, jar)).toBeNull();
    clearSession(env, jar);
    expect(readSession(env, jar)).toBeNull();
  });

  it('refreshes shortly before the access token expires', () => {
    const now = Date.now();
    expect(needsRefresh(session({ accessExpiresAt: now + 10_000 }), now)).toBe(true);
    expect(needsRefresh(session({ accessExpiresAt: now + 120_000 }), now)).toBe(false);
  });

  it('expires OIDC transactions after ten minutes', () => {
    const jar = new Jar();
    const tx = {
      state: 's'.repeat(43),
      nonce: 'n'.repeat(43),
      codeVerifier: 'v'.repeat(43),
      returnTo: '/cves',
      createdAt: Date.now(),
    };
    writeTransaction(env, jar, tx);
    expect(readTransaction(env, jar)).toEqual(tx);
    expect(readTransaction(env, jar, Date.now() + 11 * 60_000)).toBeNull();
  });
});

describe('refreshSession', () => {
  const tokenResponse = (refresh: string) =>
    new Response(
      JSON.stringify({
        access_token: jwt({ sub: 'user-1', preferred_username: 'analyst' }),
        refresh_token: refresh,
        token_type: 'Bearer',
        expires_in: 300,
        refresh_expires_in: 1800,
      }),
      {
        status: 200,
        headers: { 'content-type': 'application/json' },
      },
    );

  it('shares one refresh between concurrent requests (Keycloak rejects refresh token reuse)', async () => {
    const fetchFn = vi.fn(() => Promise.resolve(tokenResponse('refresh-2')));
    const current = session({ refreshToken: 'concurrent-token' });
    const [a, b] = await Promise.all([
      refreshSession(env, current, fetchFn),
      refreshSession(env, current, fetchFn),
    ]);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(a).toEqual(b);
    expect(a.kind === 'refreshed' ? a.session.refreshToken : null).toBe('refresh-2');
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, { body: URLSearchParams }];
    expect(url).toBe('http://keycloak:8180/auth/realms/cve-platform/protocol/openid-connect/token');
    expect(init.body.toString()).toContain('grant_type=refresh_token');
  });

  it('reports an invalid grant as expired and a network failure as unavailable', async () => {
    const invalid = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ error: 'invalid_grant' }), {
          status: 400,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );
    expect(await refreshSession(env, session({ refreshToken: 'revoked-token' }), invalid)).toEqual({
      kind: 'expired',
    });
    const down = vi.fn(() => Promise.reject(new TypeError('fetch failed')));
    expect(await refreshSession(env, session({ refreshToken: 'offline-token' }), down)).toEqual({
      kind: 'unavailable',
    });
  });
});

describe('oidc', () => {
  it('builds a PKCE authorization request for the public client', () => {
    const url = new URL(
      buildAuthorizationUrl(env, {
        state: 'state',
        nonce: 'nonce',
        codeVerifier: 'v'.repeat(43),
        action: 'configure-totp',
      }),
    );
    expect(url.origin + url.pathname).toBe(
      'https://cve.example.test/auth/realms/cve-platform/protocol/openid-connect/auth',
    );
    expect(url.searchParams.get('client_id')).toBe('cve-web');
    expect(url.searchParams.get('redirect_uri')).toBe('https://cve.example.test/session/callback');
    expect(url.searchParams.get('code_challenge')).toBe(codeChallenge('v'.repeat(43)));
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('kc_action')).toBe('CONFIGURE_TOTP');
  });

  it('computes the RFC 7636 S256 challenge', () => {
    expect(codeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });

  it('accepts only known Keycloak actions', () => {
    expect(isKeycloakActionName('update-password')).toBe(true);
    expect(isKeycloakActionName('delete-account')).toBe(false);
    expect(isKeycloakActionName('toString')).toBe(false);
  });

  it.each([
    [null, '/'],
    ['/cves?severity=critical', '/cves?severity=critical'],
    ['https://evil.example', '/'],
    ['//evil.example', '/'],
    ['/\\evil.example', '/'],
    ['/session/logout', '/'],
    ['/bff/api/v1/me', '/'],
    ['/cves\r\nSet-Cookie: x', '/'],
  ])('safeReturnTo(%j) is %j', (input, expected) => {
    expect(safeReturnTo(input)).toBe(expected);
  });
});

describe('request guards', () => {
  const headers = (values: Record<string, string>) => ({
    get: (name: string) => values[name] ?? null,
  });

  it('accepts the public origin and same-origin fetch metadata only', () => {
    expect(
      isSameOriginRequest(headers({ origin: 'https://cve.example.test' }), env.PUBLIC_ORIGIN),
    ).toBe(true);
    expect(
      isSameOriginRequest(headers({ origin: 'https://evil.example' }), env.PUBLIC_ORIGIN),
    ).toBe(false);
    expect(
      isSameOriginRequest(
        headers({ origin: 'https://evil.example', 'sec-fetch-site': 'same-origin' }),
        env.PUBLIC_ORIGIN,
      ),
    ).toBe(false);
    expect(
      isSameOriginRequest(headers({ 'sec-fetch-site': 'same-origin' }), env.PUBLIC_ORIGIN),
    ).toBe(true);
    expect(
      isSameOriginRequest(headers({ 'sec-fetch-site': 'cross-site' }), env.PUBLIC_ORIGIN),
    ).toBe(false);
    expect(isSameOriginRequest(headers({}), env.PUBLIC_ORIGIN)).toBe(false);
  });
});

describe('buildGatewayPath', () => {
  it('forwards known resources', () => {
    expect(buildGatewayPath(['cves', 'CVE-2026-0001'])).toBe('cves/CVE-2026-0001');
    expect(
      buildGatewayPath(['download-artifacts', '00000000-0000-4000-8000-000000000000', 'content']),
    ).toBe('download-artifacts/00000000-0000-4000-8000-000000000000/content');
  });

  it('refuses unknown resources, traversal and encoded separators', () => {
    expect(buildGatewayPath([])).toBeNull();
    expect(buildGatewayPath(['auth', 'logout'])).toBeNull();
    expect(buildGatewayPath(['internal'])).toBeNull();
    expect(buildGatewayPath(['cves', '..'])).toBeNull();
    expect(buildGatewayPath(['cves', '..', '..', 'admin'])).toBeNull();
    expect(buildGatewayPath(['cves', 'a/b'])).toBeNull();
    expect(buildGatewayPath(['cves', '%2e%2e'])).toBeNull();
    expect(buildGatewayPath(['cves', 'x?y'])).toBeNull();
    expect(buildGatewayPath(['cves', ...Array.from({ length: 8 }, () => 'a')])).toBeNull();
  });
});
