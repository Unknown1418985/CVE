import 'reflect-metadata';

import { randomUUID } from 'node:crypto';

import { afterEach, describe, expect, it } from 'vitest';

import { createTokenVerifier } from '@cve/auth';

import { platformHealthSchema, type HealthReport } from '@cve/contracts';
import { createLogger } from '@cve/logger';
import { configureServiceApp } from '@cve/shared';
import { createHttpTestApp, type HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer } from '@cve/testing/auth';

import { AppModule } from '../src/app.module.js';
import { loadGatewayEnv } from '../src/config/env.js';
import type { HttpFetch } from '../src/services-health/services-health.constants.js';
import { gatewayTestEnv } from './support.js';

function report(service: string, status: HealthReport['status']): HealthReport {
  return {
    service,
    version: '0.1.0',
    status,
    uptimeSeconds: 1,
    timestamp: new Date().toISOString(),
    checks: [],
  };
}

async function start(fetchFn: HttpFetch, env = gatewayTestEnv()): Promise<HttpTestApp> {
  return createHttpTestApp(
    AppModule.register(loadGatewayEnv(env), {
      fetch: fetchFn,
      sessionChecker: null,
      logger: createLogger({ service: 'api-gateway', level: 'silent' }),
    }),
    (app) => {
      configureServiceApp(app, {
        service: 'api-gateway',
        version: '0.0.0-test',
        logger: createLogger({ service: 'api-gateway', level: 'silent' }),
        corsAllowedOrigins: [],
        swaggerEnabled: false,
      });
    },
  );
}

describe('api-gateway health', () => {
  let t: HttpTestApp | undefined;

  afterEach(async () => {
    await t?.close();
    t = undefined;
  });

  it('GET /api/v1/health/live returns ok', async () => {
    t = await start(() => Promise.reject(new Error('unused')));
    const res = await t.http.get('/api/v1/health/live').expect(200);
    expect((res.body as { data: HealthReport }).data.service).toBe('api-gateway');
  });

  it('GET /api/v1/health/ready is ready only while Keycloak serves signing keys', async () => {
    let jwks: () => Promise<Response> = () =>
      Promise.resolve(Response.json({ keys: [{ kid: 'k' }] }));
    const requested: string[] = [];
    t = await start((input) => {
      const url = input instanceof Request ? input.url : input.toString();
      requested.push(url);
      return jwks();
    });
    const ready = await t.http.get('/api/v1/health/ready').expect(200);
    expect((ready.body as { data: HealthReport }).data.checks).toMatchObject([
      { name: 'keycloak', status: 'ok' },
    ]);
    expect(requested).toContain(
      'http://keycloak.internal:8180/auth/realms/cve-platform/protocol/openid-connect/certs',
    );

    jwks = () => Promise.resolve(Response.json({ keys: [] }));
    await t.http.get('/api/v1/health/ready').expect(503);
    jwks = () => Promise.reject(new Error('ECONNREFUSED'));
    const down = await t.http.get('/api/v1/health/ready').expect(503);
    expect((down.body as { data: HealthReport }).data.checks[0]?.message).toContain('ECONNREFUSED');
    // Liveness never depends on other systems, so a Keycloak outage does not restart the gateway.
    await t.http.get('/api/v1/health/live').expect(200);
  });

  it('GET /api/v1/health/services aggregates backend readiness for authorised callers', async () => {
    const requested: string[] = [];
    const fetchFn: HttpFetch = (input) => {
      const url = input instanceof Request ? input.url : input.toString();
      requested.push(url);
      if (url.includes('poc-service')) {
        return Promise.reject(new Error('ECONNREFUSED'));
      }
      if (url.includes('cve-service')) {
        return Promise.resolve(
          Response.json({ data: report('cve-service', 'down') }, { status: 503 }),
        );
      }
      if (url.includes('asset-service')) {
        return Promise.resolve(Response.json({ unexpected: true }));
      }
      return Promise.resolve(Response.json({ data: report('x', 'ok') }));
    };

    t = await start(fetchFn);
    const issuer = await createTestTokenIssuer();
    await t.close();
    t = await createHttpTestApp(
      AppModule.register(loadGatewayEnv(gatewayTestEnv()), {
        fetch: fetchFn,
        sessionChecker: null,
        verifier: createTokenVerifier({
          issuer: issuer.issuer,
          audience: issuer.audience,
          keys: issuer.getKey,
        }),
        logger: createLogger({ service: 'api-gateway', level: 'silent' }),
      }),
      (app) => {
        configureServiceApp(app, {
          service: 'api-gateway',
          version: '0.0.0-test',
          logger: createLogger({ service: 'api-gateway', level: 'silent' }),
          corsAllowedOrigins: [],
          swaggerEnabled: false,
        });
      },
    );
    const token = await issuer.tokenFor(randomUUID(), ['viewer']);
    const anonymous = await t.http.get('/api/v1/health/services').expect(200);
    const reduced = platformHealthSchema.parse((anonymous.body as { data: unknown }).data);
    expect(reduced.services.every((s) => s.report === undefined && s.message === undefined)).toBe(
      true,
    );
    const res = await t.http
      .get('/api/v1/health/services')
      .set('authorization', `Bearer ${token}`)
      .expect(200);
    const health = platformHealthSchema.parse((res.body as { data: unknown }).data);

    expect(requested).toContain('http://cve-service.internal:4000/api/v1/health/ready');
    expect(health.status).toBe('down');
    expect(health.services).toHaveLength(9);
    const byName = Object.fromEntries(health.services.map((s) => [s.service, s]));
    expect(byName['cve-service']?.status).toBe('down');
    expect(byName['poc-service']).toMatchObject({ status: 'down' });
    expect(byName['poc-service']?.message).toContain('ECONNREFUSED');
    expect(byName['asset-service']?.message).toContain('invalid health response');
    expect(byName['identity-service']?.status).toBe('ok');
  });

  it('applies rate limiting', async () => {
    t = await start(
      () => Promise.reject(new Error('unused')),
      gatewayTestEnv({ RATE_LIMIT_MAX: '2' }),
    );
    await t.http.get('/api/v1/health/live').expect(200);
    await t.http.get('/api/v1/health/live').expect(200);
    const res = await t.http.get('/api/v1/health/live').expect(429);
    expect(res.body).toMatchObject({ error: { code: 'TOO_MANY_REQUESTS' } });
  });
});
