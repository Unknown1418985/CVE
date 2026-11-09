import { createServer, type Server } from 'node:net';

import { Module, type DynamicModule } from '@nestjs/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { healthReportSchema } from '@cve/contracts';
import { createLogger } from '@cve/logger';
import { createHttpTestApp, type HttpTestApp } from '@cve/testing';

import { configureServiceApp } from '../bootstrap/configure-service-app.js';
import { createTcpHealthIndicator, type HealthIndicator } from './health-indicator.js';
import { HealthModule } from './health.module.js';
import { HealthService } from './health.service.js';

const logger = createLogger({ service: 'test', level: 'silent' });

function appModule(indicators: HealthIndicator[]): DynamicModule {
  @Module({})
  class TestAppModule {}
  return {
    module: TestAppModule,
    imports: [
      HealthModule.forRoot({ service: 'test', version: '0.0.0', indicators, timeoutMs: 500 }),
    ],
  };
}

async function start(indicators: HealthIndicator[]): Promise<HttpTestApp> {
  return createHttpTestApp(appModule(indicators), (app) => {
    configureServiceApp(app, {
      service: 'test',
      version: '0.0.0',
      logger,
      corsAllowedOrigins: ['https://ui.example.test'],
      swaggerEnabled: false,
    });
  });
}

const fixed = (status: 'ok' | 'down', critical = true): HealthIndicator => ({
  name: `fixed-${status}`,
  critical,
  check: () => Promise.resolve({ name: `fixed-${status}`, status }),
});

describe('health endpoints', () => {
  it('serves liveness under /api/v1 with a valid report', async () => {
    const t = await start([fixed('down')]);
    const res = await t.http.get('/api/v1/health/live').expect(200);
    const body = res.body as { data: unknown };
    expect(healthReportSchema.parse(body.data)).toMatchObject({ service: 'test', status: 'ok' });
    await t.close();
  });

  it('returns 503 when a critical dependency is down', async () => {
    const t = await start([fixed('ok'), fixed('down')]);
    const res = await t.http.get('/api/v1/health/ready').expect(503);
    expect((res.body as { data: { status: string } }).data.status).toBe('down');
    await t.close();
  });

  it('reports degraded (200) when only a non-critical dependency is down', async () => {
    const t = await start([fixed('ok'), fixed('down', false)]);
    const res = await t.http.get('/api/v1/health').expect(200);
    expect((res.body as { data: { status: string } }).data.status).toBe('degraded');
    await t.close();
  });

  it('turns a throwing indicator into a down check', async () => {
    const t = await start([
      { name: 'broken', critical: true, check: () => Promise.reject(new Error('boom')) },
    ]);
    const res = await t.http.get('/api/v1/health/ready').expect(503);
    expect((res.body as { data: { checks: unknown[] } }).data.checks).toEqual([
      { name: 'broken', status: 'down', message: 'boom' },
    ]);
    await t.close();
  });
});

describe('shutdown', () => {
  it('fails readiness once shutdown begins while liveness stays ok', async () => {
    const t = await start([fixed('ok')]);
    await t.http.get('/api/v1/health/ready').expect(200);
    t.app.get(HealthService).markShuttingDown();
    const res = await t.http.get('/api/v1/health/ready').expect(503);
    expect((res.body as { data: { checks: unknown[] } }).data.checks).toEqual([
      { name: 'shutdown', status: 'down', message: 'service is shutting down' },
    ]);
    await t.http.get('/api/v1/health/live').expect(200);
    await t.close();
  });
});

describe('HTTP conventions', () => {
  it('sets correlation IDs, security headers and the error envelope', async () => {
    const t = await start([]);
    const res = await t.http
      .get('/api/v1/does-not-exist')
      .set('x-correlation-id', 'client-req-0001')
      .expect(404);
    expect(res.headers['x-correlation-id']).toBe('client-req-0001');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.body).toMatchObject({
      error: { code: 'NOT_FOUND' },
      correlationId: 'client-req-0001',
    });
    await t.close();
  });

  it('does not expose routes outside the versioned prefix', async () => {
    const t = await start([]);
    await t.http.get('/health/live').expect(404);
    await t.close();
  });

  it('rejects disallowed CORS origins', async () => {
    const t = await start([]);
    const allowed = await t.http
      .get('/api/v1/health/live')
      .set('origin', 'https://ui.example.test');
    expect(allowed.headers['access-control-allow-origin']).toBe('https://ui.example.test');
    const denied = await t.http.get('/api/v1/health/live').set('origin', 'https://evil.test');
    expect(denied.headers['access-control-allow-origin']).toBeUndefined();
    await t.close();
  });
});

describe('createTcpHealthIndicator', () => {
  let server: Server;
  let port: number;

  beforeAll(async () => {
    server = createServer((socket) => socket.end());
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('no port');
    port = address.port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) =>
      server.close(() => {
        resolve();
      }),
    );
  });

  it('reports ok for a reachable port', async () => {
    const check = await createTcpHealthIndicator('svc', `redis://127.0.0.1:${port}`).check(500);
    expect(check.status).toBe('ok');
  });

  it('reports down for an unreachable port', async () => {
    const check = await createTcpHealthIndicator('svc', 'redis://127.0.0.1:9').check(500);
    expect(check.status).toBe('down');
  });

  it('rejects URLs without a resolvable port', () => {
    expect(() => createTcpHealthIndicator('svc', 'ftp://host')).toThrow(/port/);
  });
});
