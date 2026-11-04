import { describe, expect, it } from 'vitest';

import { createLogger } from '@cve/logger';

import { IdentityProviderError } from '../src/keycloak/identity-provider.js';
import { KeycloakAdminClient } from '../src/keycloak/keycloak-admin.client.js';

const USER_ID = '6f1c3d2a-0000-4000-8000-000000000001';

type Handler = (url: URL, init: RequestInit) => Response | Promise<Response>;

function client(handler: Handler) {
  const requests: { method: string; url: URL; body: unknown }[] = [];
  const instance = new KeycloakAdminClient({
    baseUrl: 'http://keycloak.test/auth',
    realm: 'cve-platform',
    clientId: 'cve-identity-service',
    clientSecret: 'service-secret-0000',
    timeoutMs: 1_000,
    logger: createLogger({ service: 'test', level: 'silent' }),
    fetch: async (input, init = {}) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      requests.push({
        method: init.method ?? 'GET',
        url,
        body: typeof init.body === 'string' ? init.body : undefined,
      });
      if (url.pathname.endsWith('/protocol/openid-connect/token')) {
        return Response.json({ access_token: 'service-token', expires_in: 300 });
      }
      return handler(url, init);
    },
  });
  return { instance, requests };
}

describe('KeycloakAdminClient', () => {
  it('authenticates with client credentials and caches the token', async () => {
    const { instance, requests } = client(() =>
      Response.json({
        id: USER_ID,
        username: 'ada',
        enabled: true,
        createdTimestamp: 1_700_000_000_000,
      }),
    );
    const user = await instance.getUser(USER_ID);
    await instance.getUser(USER_ID);
    expect(user).toMatchObject({ id: USER_ID, username: 'ada', enabled: true, email: null });
    const tokenCalls = requests.filter((r) => r.url.pathname.endsWith('/token'));
    expect(tokenCalls).toHaveLength(1);
    expect(String(tokenCalls[0]!.body)).toContain('grant_type=client_credentials');
    expect(requests[1]!.url.pathname).toBe(`/auth/admin/realms/cve-platform/users/${USER_ID}`);
  });

  it('returns null for unknown users and rejects malformed IDs before calling Keycloak', async () => {
    const { instance, requests } = client(() => new Response(null, { status: 404 }));
    expect(await instance.getUser(USER_ID)).toBeNull();
    await expect(instance.getUser('../../master')).rejects.toBeInstanceOf(IdentityProviderError);
    expect(requests.some((r) => r.url.pathname.includes('master'))).toBe(false);
  });

  it('filters realm roles down to platform roles', async () => {
    const { instance } = client(() =>
      Response.json([
        { id: '1', name: 'administrator' },
        { id: '2', name: 'offline_access' },
        { id: '3', name: 'default-roles-cve-platform' },
      ]),
    );
    expect(await instance.getDirectRoles(USER_ID)).toEqual(['administrator']);
  });

  it('resolves role representations when assigning roles', async () => {
    const { instance, requests } = client((url, init) => {
      if (url.pathname.endsWith('/roles/security-analyst')) {
        return Response.json({ id: 'role-id', name: 'security-analyst' });
      }
      expect(init.method).toBe('POST');
      return new Response(null, { status: 204 });
    });
    await instance.addRoles(USER_ID, ['security-analyst']);
    const post = requests.find(
      (r) => r.method === 'POST' && r.url.pathname.includes('role-mappings'),
    );
    expect(JSON.parse(String(post?.body))).toEqual([{ id: 'role-id', name: 'security-analyst' }]);
  });

  it('maps upstream failures without leaking response bodies', async () => {
    const { instance } = client(() => new Response('stack trace with secrets', { status: 500 }));
    const error = await instance.listSessions(USER_ID).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IdentityProviderError);
    expect((error as Error).message).not.toContain('secrets');
    expect((error as IdentityProviderError).status).toBe(502);
  });

  it('rejects unexpected response shapes', async () => {
    const { instance } = client(() => Response.json({ not: 'a list' }));
    await expect(instance.listSessions(USER_ID)).rejects.toThrow(/unexpected response/);
  });

  it('merges user and admin events oldest first from the cursor', async () => {
    const since = new Date('2026-11-04T08:00:00Z');
    const { instance, requests } = client((url) => {
      if (url.pathname.endsWith('/admin-events')) {
        return Response.json([
          {
            id: 'adm-1',
            time: since.getTime() + 2_000,
            operationType: 'UPDATE',
            resourceType: 'USER',
          },
        ]);
      }
      return Response.json([
        { id: 'evt-2', time: since.getTime() + 3_000, type: 'LOGOUT', userId: USER_ID },
        { id: 'evt-1', time: since.getTime() + 1_000, type: 'LOGIN', userId: USER_ID },
        { id: 'evt-0', time: since.getTime() - 1_000, type: 'LOGIN', userId: USER_ID },
      ]);
    });
    const events = await instance.listEvents(since, 10);
    expect(events.map((e) => e.id)).toEqual(['evt-1', 'adm-1', 'evt-2']);
    const eventsCall = requests.find((r) => r.url.pathname.endsWith('/events'));
    expect(eventsCall?.url.searchParams.get('dateFrom')).toBe(String(since.getTime()));
  });
});
