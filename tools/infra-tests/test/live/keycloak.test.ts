import { integrationHost, requireEnv } from '@cve/testing/integration';
import { describe, expect, it } from 'vitest';

import { devPorts } from './mode.js';

const base = process.env['KEYCLOAK_TEST_URL'] ?? `http://${integrationHost()}:8180/auth`;
const realm = 'cve-platform';

async function adminToken(): Promise<string> {
  const res = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: requireEnv('KEYCLOAK_ADMIN_USER'),
      password: requireEnv('KEYCLOAK_ADMIN_PASSWORD'),
    }),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { access_token: string }).access_token;
}

async function adminGet<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`${base}/admin/realms/${realm}${path}`, {
    headers: { authorization: `Bearer ${token}` },
  });
  expect(res.status, path).toBe(200);
  return (await res.json()) as T;
}

describe.runIf(devPorts)('Keycloak realm', () => {
  it('publishes OIDC discovery for the platform realm', async () => {
    const res = await fetch(`${base}/realms/${realm}/.well-known/openid-configuration`);
    expect(res.status).toBe(200);
    const config = (await res.json()) as {
      issuer: string;
      code_challenge_methods_supported: string[];
    };
    expect(config.issuer).toMatch(new RegExp(`/auth/realms/${realm}$`));
    expect(config.code_challenge_methods_supported).toContain('S256');
  });

  it('imports the platform roles, hardened realm settings and clients', async () => {
    const token = await adminToken();
    const roles = await adminGet<{ name: string }[]>('/roles', token);
    expect(roles.map((role) => role.name)).toEqual(
      expect.arrayContaining([
        'super-admin',
        'administrator',
        'security-analyst',
        'vulnerability-researcher',
        'viewer',
      ]),
    );

    const settings = await adminGet<{
      registrationAllowed: boolean;
      bruteForceProtected: boolean;
      sslRequired: string;
    }>('', token);
    expect(settings).toMatchObject({
      registrationAllowed: false,
      bruteForceProtected: true,
      sslRequired: 'external',
    });

    const [web] = await adminGet<
      {
        publicClient: boolean;
        directAccessGrantsEnabled: boolean;
        redirectUris: string[];
        attributes: Record<string, string>;
      }[]
    >('/clients?clientId=cve-web', token);
    expect(web).toMatchObject({ publicClient: true, directAccessGrantsEnabled: false });
    expect(web?.attributes['pkce.code.challenge.method']).toBe('S256');
    // Placeholders from the import file were substituted with the configured origin.
    expect(web?.redirectUris.join(' ')).not.toContain('${');
  });

  it('issues service-account tokens to the Identity Service with its secret only', async () => {
    const tokenFor = (secret: string) =>
      fetch(`${base}/realms/${realm}/protocol/openid-connect/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: 'cve-identity-service',
          client_secret: secret,
        }),
      });
    expect((await tokenFor(requireEnv('KEYCLOAK_IDENTITY_SERVICE_CLIENT_SECRET'))).status).toBe(
      200,
    );
    expect((await tokenFor('wrong-secret')).status).toBe(401);
  });
});
