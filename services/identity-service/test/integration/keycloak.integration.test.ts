import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createTokenVerifier, IntrospectionSessionChecker, keycloakRealmUrls } from '@cve/auth';
import { auditEventSchema, userProfileSchema } from '@cve/contracts';
import { createLogger } from '@cve/logger';
import { configureServiceApp } from '@cve/shared';
import { buildServiceTestEnv, createHttpTestApp, type HttpTestApp } from '@cve/testing';
import { requireEnv } from '@cve/testing/integration';

import { AppModule } from '../../src/app.module.js';
import { KeycloakEventsSync } from '../../src/audit/keycloak-events.sync.js';
import { loadServiceEnv } from '../../src/config/env.js';
import { KeycloakAdminClient } from '../../src/keycloak/keycloak-admin.client.js';
import { createPrismaClient } from '../../src/persistence/prisma.js';
import { PrismaAuditRepository } from '../../src/persistence/prisma-audit.repository.js';
import { PrismaSyncCursorRepository } from '../../src/persistence/prisma-sync-cursor.repository.js';
import { createRuntimeDependencies } from '../../src/runtime.js';
import { SERVICE_NAME } from '../../src/service.js';
import {
  createPasswordGrantClient,
  createUser,
  deleteClient,
  deleteUser,
  identityDatabaseUrl,
  KEYCLOAK_PUBLIC_URL,
  KEYCLOAK_URL,
  masterAdminToken,
  migrate,
  passwordLogin,
  REALM,
  refresh,
  type TestUser,
} from './support.js';

const logger = createLogger({ service: SERVICE_NAME, level: 'silent' });
const suffix = randomUUID().slice(0, 8);
const clientId = `it-password-grant-${suffix}`;
let clientSecret: string;
let masterToken: string;
let admin: TestUser;
let analyst: TestUser;
let t: HttpTestApp;

const env = () =>
  loadServiceEnv(
    buildServiceTestEnv(SERVICE_NAME, {
      DATABASE_URL: identityDatabaseUrl(),
      KEYCLOAK_URL,
      KEYCLOAK_PUBLIC_URL,
      KEYCLOAK_ADMIN_CLIENT_SECRET: requireEnv('KEYCLOAK_IDENTITY_SERVICE_CLIENT_SECRET'),
      ACCOUNT_REDIRECT_URI: 'http://localhost:3000/settings',
      OUTBOX_RELAY_ENABLED: 'false',
      KEYCLOAK_EVENTS_SYNC_ENABLED: 'false',
    }),
  );

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

beforeAll(async () => {
  migrate(identityDatabaseUrl());
  masterToken = await masterAdminToken();
  clientSecret = await createPasswordGrantClient(masterToken, clientId);
  admin = await createUser(masterToken, `it-admin-${suffix}`, ['administrator']);
  analyst = await createUser(masterToken, `it-analyst-${suffix}`, ['viewer']);

  const config = env();
  t = await createHttpTestApp(
    AppModule.register(config, createRuntimeDependencies(config, logger)),
    (app) => {
      configureServiceApp(app, {
        service: SERVICE_NAME,
        version: '0.0.0-test',
        logger,
        corsAllowedOrigins: [],
        swaggerEnabled: false,
      });
    },
  );
});

afterAll(async () => {
  await t.close();
  await deleteUser(masterToken, admin.id);
  await deleteUser(masterToken, analyst.id);
  await deleteClient(masterToken, clientId);
});

describe('real Keycloak tokens', () => {
  it('are validated against the realm JWKS with platform roles mapped to permissions', async () => {
    const { accessToken } = await passwordLogin(clientId, clientSecret, admin);
    const verifier = createTokenVerifier({
      issuer: keycloakRealmUrls(KEYCLOAK_PUBLIC_URL, REALM).issuer,
      audience: 'cve-api',
      keys: { jwksUrl: keycloakRealmUrls(KEYCLOAK_URL, REALM).jwks },
    });
    const principal = await verifier.verify(accessToken);
    expect(principal.subject).toBe(admin.id);
    // Composite roles are expanded by Keycloak into the flat `roles` claim.
    expect(principal.roles).toEqual([
      'administrator',
      'security-analyst',
      'vulnerability-researcher',
      'viewer',
    ]);
    expect(principal.permissions).toContain('user:manage');
    expect(principal.sessionId).toBeDefined();
  });

  it('are introspected as active until their session is logged out', async () => {
    const { accessToken } = await passwordLogin(clientId, clientSecret, analyst);
    const checker = new IntrospectionSessionChecker({
      introspectionUrl: keycloakRealmUrls(KEYCLOAK_URL, REALM).introspection,
      clientId: 'cve-api',
      clientSecret: requireEnv('KEYCLOAK_API_CLIENT_SECRET'),
      cacheTtlMs: 1_000,
    });
    const verifier = createTokenVerifier({
      issuer: keycloakRealmUrls(KEYCLOAK_PUBLIC_URL, REALM).issuer,
      audience: 'cve-api',
      keys: { jwksUrl: keycloakRealmUrls(KEYCLOAK_URL, REALM).jwks },
    });
    const principal = await verifier.verify(accessToken);
    await expect(checker.assertActive(accessToken, principal)).resolves.toBeUndefined();

    const res = await t.http.post('/api/v1/auth/logout').set(bearer(accessToken)).expect(200);
    expect(res.body).toEqual({ data: { revokedSessions: 1 } });

    const fresh = new IntrospectionSessionChecker({
      introspectionUrl: keycloakRealmUrls(KEYCLOAK_URL, REALM).introspection,
      clientId: 'cve-api',
      clientSecret: requireEnv('KEYCLOAK_API_CLIENT_SECRET'),
    });
    await expect(fresh.assertActive(accessToken, principal)).rejects.toThrow(/no longer active/);
  });
});

describe('Identity Service against Keycloak and PostgreSQL', () => {
  it('serves the caller profile and updates names in Keycloak', async () => {
    const { accessToken } = await passwordLogin(clientId, clientSecret, analyst);
    const me = await t.http.get('/api/v1/me').set(bearer(accessToken)).expect(200);
    expect(userProfileSchema.parse((me.body as { data: unknown }).data)).toMatchObject({
      id: analyst.id,
      username: analyst.username,
      roles: ['viewer'],
    });
    await t.http
      .patch('/api/v1/me')
      .set(bearer(accessToken))
      .send({ lastName: 'Lovelace', timezone: 'Europe/Berlin' })
      .expect(200);
    const idp = new KeycloakAdminClient({
      baseUrl: KEYCLOAK_URL,
      realm: REALM,
      clientId: 'cve-identity-service',
      clientSecret: requireEnv('KEYCLOAK_IDENTITY_SERVICE_CLIENT_SECRET'),
      timeoutMs: 5_000,
      logger,
    });
    expect((await idp.getUser(analyst.id))?.lastName).toBe('Lovelace');
  });

  it('lets an administrator promote a user and demotion ends the user sessions', async () => {
    const adminLogin = await passwordLogin(clientId, clientSecret, admin);
    const target = await passwordLogin(clientId, clientSecret, analyst);

    const sessions = await t.http
      .get(`/api/v1/users/${analyst.id}/sessions`)
      .set(bearer(adminLogin.accessToken))
      .expect(200);
    expect((sessions.body as { data: unknown[] }).data.length).toBeGreaterThan(0);

    const promoted = await t.http
      .put(`/api/v1/users/${analyst.id}/roles`)
      .set(bearer(adminLogin.accessToken))
      .send({ roles: ['security-analyst'], reason: 'integration test' })
      .expect(200);
    expect((promoted.body as { data: { roles: string[] } }).data.roles).toEqual([
      'security-analyst',
      'viewer',
    ]);
    // viewer was a direct role and was removed: the user's refresh token stops working.
    const refreshed = await refresh(clientId, clientSecret, target.refreshToken);
    expect(refreshed.status).toBe(400);

    await t.http
      .put(`/api/v1/users/${analyst.id}/roles`)
      .set(bearer(adminLogin.accessToken))
      .send({ roles: ['super-admin'] })
      .expect(403);

    const audit = await t.http
      .get(`/api/v1/audit-logs?resourceId=${analyst.id}&action=identity.user.roles-changed`)
      .set(bearer(adminLogin.accessToken))
      .expect(200);
    const outcomes = (audit.body as { data: unknown[] }).data
      .map((entry) => auditEventSchema.parse(entry))
      .map((entry) => entry.outcome)
      .sort();
    expect(outcomes).toEqual(['denied', 'success']);
  });

  it('requires a password update through Keycloak without the platform seeing a password', async () => {
    const adminLogin = await passwordLogin(clientId, clientSecret, admin);
    const res = await t.http
      .post(`/api/v1/users/${analyst.id}/credentials/require-password-update`)
      .set(bearer(adminLogin.accessToken))
      .expect(200);
    expect((res.body as { data: { requiredActions: string[] } }).data.requiredActions).toContain(
      'UPDATE_PASSWORD',
    );
  });

  it('copies Keycloak login events into the audit log', async () => {
    await passwordLogin(clientId, clientSecret, admin);
    const prisma = createPrismaClient(identityDatabaseUrl());
    try {
      const idp = new KeycloakAdminClient({
        baseUrl: KEYCLOAK_URL,
        realm: REALM,
        clientId: 'cve-identity-service',
        clientSecret: requireEnv('KEYCLOAK_IDENTITY_SERVICE_CLIENT_SECRET'),
        timeoutMs: 5_000,
        logger,
      });
      const audit = new PrismaAuditRepository(prisma);
      const sync = new KeycloakEventsSync(
        idp,
        audit,
        new PrismaSyncCursorRepository(prisma),
        logger,
      );
      await sync.run();
      const logins = await audit.list({
        page: 1,
        pageSize: 5,
        actorId: admin.id,
        action: 'identity.keycloak-login.succeeded',
      });
      expect(logins.total).toBeGreaterThan(0);
      expect(logins.items[0]).toMatchObject({ source: 'keycloak', actorType: 'user' });
    } finally {
      await prisma.$disconnect();
    }
  });
});
