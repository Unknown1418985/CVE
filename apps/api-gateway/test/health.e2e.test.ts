import 'reflect-metadata';

import { afterEach, describe, expect, it } from 'vitest';

import { platformHealthSchema, type HealthReport } from '@cve/contracts';
import { createLogger } from '@cve/logger';
import { configureServiceApp } from '@cve/shared';
import { createHttpTestApp, type HttpTestApp } from '@cve/testing';

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
  return createHttpTestApp(AppModule.register(loadGatewayEnv(env), { fetch: fetchFn }), (app) => {
    configureServiceApp(app, {
      service: 'api-gateway',
      version: '0.0.0-test',
      logger: createLogger({ service: 'api-gateway', level: 'silent' }),
      corsAllowedOrigins: [],
      swaggerEnabled: false,
    });
  });
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

  it('GET /api/v1/health/services aggregates backend readiness', async () => {
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
    const res = await t.http.get('/api/v1/health/services').expect(200);
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
