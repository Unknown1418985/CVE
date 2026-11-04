import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { Controller, Get, Module } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createLogger } from '@cve/logger';
import { configureServiceApp, Public } from '@cve/shared';
import { createHttpTestApp, type HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer, type TestTokenIssuer } from '@cve/testing/auth';

import {
  AuthenticationError,
  authGuards,
  AuthModule,
  createTokenVerifier,
  CurrentPrincipal,
  OptionalPrincipal,
  RequirePermissions,
  RequireRoles,
  type AccessDeniedEvent,
  type AuthenticatedPrincipal,
  type AuthenticationFailedEvent,
  type SessionChecker,
} from '../src/index.js';

@Controller('probe')
class ProbeController {
  @Public()
  @Get('public')
  open(@OptionalPrincipal() principal: AuthenticatedPrincipal | undefined) {
    return { data: { subject: principal?.subject ?? null } };
  }

  @Get('private')
  private(@CurrentPrincipal() principal: AuthenticatedPrincipal) {
    return { data: { subject: principal.subject, roles: principal.roles } };
  }

  @RequirePermissions('audit:read')
  @Get('audit')
  audit() {
    return { data: 'audit' };
  }

  @RequireRoles('super-admin')
  @Get('super')
  superOnly() {
    return { data: 'super' };
  }
}

@RequirePermissions('user:read')
@Controller('users')
class UsersController {
  @RequirePermissions('user:manage')
  @Get('manage')
  manage() {
    return { data: 'manage' };
  }
}

describe('authentication and authorization guards', () => {
  let issuer: TestTokenIssuer;
  let t: HttpTestApp;
  const revoked = new Set<string>();
  const denied: AccessDeniedEvent[] = [];
  const failed: AuthenticationFailedEvent[] = [];
  const sessionChecker: SessionChecker = {
    assertActive: (_token, principal) =>
      principal.sessionId !== undefined && revoked.has(principal.sessionId)
        ? Promise.reject(new AuthenticationError('session-inactive', 'Session is no longer active'))
        : Promise.resolve(),
  };

  beforeAll(async () => {
    issuer = await createTestTokenIssuer();
    const logger = createLogger({ service: 'auth-test', level: 'silent' });

    @Module({
      imports: [
        AuthModule.forRoot({
          verifier: createTokenVerifier({
            issuer: issuer.issuer,
            audience: issuer.audience,
            keys: issuer.getKey,
          }),
          sessionChecker,
          logger,
          listener: {
            onAccessDenied: (event) => {
              denied.push(event);
            },
            onAuthenticationFailed: (event) => {
              failed.push(event);
            },
          },
        }),
      ],
      controllers: [ProbeController, UsersController],
      providers: authGuards(),
    })
    class TestModule {}

    t = await createHttpTestApp(TestModule, (app) => {
      configureServiceApp(app, {
        service: 'auth-test',
        version: '0.0.0',
        logger,
        corsAllowedOrigins: [],
        swaggerEnabled: false,
      });
    });
  });

  afterAll(async () => {
    await t.close();
  });

  const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

  it('allows public routes anonymously and attaches valid principals', async () => {
    const anonymous = await t.http.get('/api/v1/probe/public').expect(200);
    expect(anonymous.body).toEqual({ data: { subject: null } });
    const id = randomUUID();
    const res = await t.http
      .get('/api/v1/probe/public')
      .set(bearer(await issuer.tokenFor(id, ['viewer'])))
      .expect(200);
    expect(res.body).toEqual({ data: { subject: id } });
    await t.http.get('/api/v1/probe/public').set(bearer('a.b.c')).expect(200);
  });

  it('rejects private routes without a valid token', async () => {
    const res = await t.http.get('/api/v1/probe/private').expect(401);
    expect(res.headers['www-authenticate']).toBe('Bearer realm="cve-platform"');
    expect(res.body).toMatchObject({ error: { code: 'UNAUTHORIZED' } });

    const expired = await issuer.sign({ sub: randomUUID() }, { expiresInSeconds: -300 });
    const res2 = await t.http.get('/api/v1/probe/private').set(bearer(expired)).expect(401);
    expect(res2.headers['www-authenticate']).toContain('error="invalid_token"');
    expect(failed.map((event) => event.reason)).toContain('expired-token');
  });

  it('accepts a valid token on private routes', async () => {
    const id = randomUUID();
    const res = await t.http
      .get('/api/v1/probe/private')
      .set(bearer(await issuer.tokenFor(id, ['security-analyst'])))
      .expect(200);
    expect(res.body).toEqual({ data: { subject: id, roles: ['security-analyst'] } });
  });

  it('enforces permissions and roles', async () => {
    const viewer = await issuer.tokenFor(randomUUID(), ['viewer']);
    const admin = await issuer.tokenFor(randomUUID(), ['administrator']);
    const superAdmin = await issuer.tokenFor(randomUUID(), ['super-admin']);

    const res = await t.http.get('/api/v1/probe/audit').set(bearer(viewer)).expect(403);
    expect(res.body).toMatchObject({ error: { code: 'FORBIDDEN' } });
    expect(denied.at(-1)?.missingPermissions).toEqual(['audit:read']);
    await t.http.get('/api/v1/probe/audit').set(bearer(admin)).expect(200);

    await t.http.get('/api/v1/probe/super').set(bearer(admin)).expect(403);
    await t.http.get('/api/v1/probe/super').set(bearer(superAdmin)).expect(200);
  });

  it('combines class and handler permissions', async () => {
    const analyst = await issuer.tokenFor(randomUUID(), ['security-analyst']);
    const admin = await issuer.tokenFor(randomUUID(), ['administrator']);
    await t.http.get('/api/v1/users/manage').set(bearer(analyst)).expect(403);
    await t.http.get('/api/v1/users/manage').set(bearer(admin)).expect(200);
  });

  it('rejects tokens whose session is no longer active', async () => {
    const sid = randomUUID();
    const token = await issuer.tokenFor(randomUUID(), ['viewer'], { sid });
    await t.http.get('/api/v1/probe/private').set(bearer(token)).expect(200);
    revoked.add(sid);
    await t.http.get('/api/v1/probe/private').set(bearer(token)).expect(401);
    expect(failed.map((event) => event.reason)).toContain('session-inactive');
  });
});
