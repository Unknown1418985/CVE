import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

import { integrationHost, requireEnv } from '@cve/testing/integration';

export const KEYCLOAK_URL =
  process.env['KEYCLOAK_TEST_URL'] ?? `http://${integrationHost()}:8180/auth`;
/** Issuer base: compose.dev.yaml sets KC_HOSTNAME to this address. */
export const KEYCLOAK_PUBLIC_URL =
  process.env['KEYCLOAK_TEST_PUBLIC_URL'] ?? 'http://localhost:8180/auth';
export const REALM = 'cve-platform';

/** Database URL of the identity-service role on the dev-published PostgreSQL. */
export function identityDatabaseUrl(): string {
  const password = encodeURIComponent(requireEnv('IDENTITY_SERVICE_DB_PASSWORD'));
  return `postgresql://identity_service:${password}@${integrationHost()}:5432/identity_service`;
}

/** Applies the committed migrations exactly as the `identity-service-migrate` job does. */
export function migrate(databaseUrl: string): void {
  execFileSync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
    cwd: resolve(import.meta.dirname, '../..'),
    env: { ...process.env, DATABASE_URL: databaseUrl },
    stdio: 'pipe',
  });
}

async function json<T>(response: Response, context: string): Promise<T> {
  if (!response.ok) {
    throw new Error(`${context} failed: HTTP ${response.status} ${await response.text()}`);
  }
  return (await response.json()) as T;
}

/** Master-realm administrator, used only by tests to create fixtures. */
export async function masterAdminToken(): Promise<string> {
  const response = await fetch(`${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: requireEnv('KEYCLOAK_ADMIN_USER'),
      password: requireEnv('KEYCLOAK_ADMIN_PASSWORD'),
    }),
  });
  return (await json<{ access_token: string }>(response, 'master admin login')).access_token;
}

export async function adminRequest(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  return fetch(`${KEYCLOAK_URL}/admin/realms/${REALM}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

export interface TestUser {
  readonly id: string;
  readonly username: string;
  readonly password: string;
}

/** Creates a user with a password and direct realm roles. */
export async function createUser(
  token: string,
  username: string,
  roles: string[],
): Promise<TestUser> {
  const password = `Aa1!${crypto.randomUUID()}`;
  const created = await adminRequest(token, 'POST', '/users', {
    username,
    email: `${username}@example.com`,
    emailVerified: true,
    firstName: 'Test',
    lastName: 'User',
    enabled: true,
    credentials: [{ type: 'password', value: password, temporary: false }],
  });
  if (created.status !== 201) throw new Error(`create user failed: HTTP ${created.status}`);
  const location = created.headers.get('location') ?? '';
  const id = location.slice(location.lastIndexOf('/') + 1);
  const representations = await Promise.all(
    roles.map(async (role) =>
      json<{ id: string; name: string }>(
        await adminRequest(token, 'GET', `/roles/${role}`),
        `role ${role}`,
      ),
    ),
  );
  if (representations.length > 0) {
    const assigned = await adminRequest(
      token,
      'POST',
      `/users/${id}/role-mappings/realm`,
      representations,
    );
    if (assigned.status !== 204) throw new Error(`role assignment failed: ${assigned.status}`);
  }
  return { id, username, password };
}

export async function deleteUser(token: string, id: string): Promise<void> {
  await adminRequest(token, 'DELETE', `/users/${id}`);
}

/**
 * A confidential test client with direct access grants and the `cve-api` scope, so tests can
 * obtain real access tokens without a browser. Production clients never enable this grant.
 */
export async function createPasswordGrantClient(token: string, clientId: string): Promise<string> {
  const secret = crypto.randomUUID();
  const created = await adminRequest(token, 'POST', '/clients', {
    clientId,
    enabled: true,
    publicClient: false,
    secret,
    standardFlowEnabled: false,
    directAccessGrantsEnabled: true,
    serviceAccountsEnabled: false,
    defaultClientScopes: ['basic', 'profile', 'email', 'cve-api'],
  });
  if (created.status !== 201) throw new Error(`create client failed: HTTP ${created.status}`);
  return secret;
}

export async function deleteClient(token: string, clientId: string): Promise<void> {
  const [client] = await json<{ id: string }[]>(
    await adminRequest(token, 'GET', `/clients?clientId=${clientId}`),
    'find client',
  );
  if (client) await adminRequest(token, 'DELETE', `/clients/${client.id}`);
}

export async function passwordLogin(
  clientId: string,
  clientSecret: string,
  user: TestUser,
): Promise<{ accessToken: string; refreshToken: string }> {
  const response = await fetch(`${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: clientId,
      client_secret: clientSecret,
      username: user.username,
      password: user.password,
      scope: 'openid',
    }),
  });
  const body = await json<{ access_token: string; refresh_token: string }>(response, 'user login');
  return { accessToken: body.access_token, refreshToken: body.refresh_token };
}

export async function refresh(clientId: string, clientSecret: string, refreshToken: string) {
  return fetch(`${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
    }),
  });
}
