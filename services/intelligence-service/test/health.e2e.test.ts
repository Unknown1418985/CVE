import 'reflect-metadata';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { healthReportSchema } from '@cve/contracts';
import { createTcpHealthIndicator } from '@cve/shared';

import { startApp, type AppContext } from './app-support.js';
import { intelligenceTestEnv } from './support.js';

describe('intelligence-service health endpoints', () => {
  let ctx: AppContext;

  beforeAll(async () => {
    const env = intelligenceTestEnv(null);
    ctx = await startApp(null, {
      env,
      healthIndicators: [
        createTcpHealthIndicator('postgres', env.DATABASE_URL),
        createTcpHealthIndicator('rabbitmq', env.RABBITMQ_URL),
        createTcpHealthIndicator('redis', env.REDIS_URL),
      ],
    });
  });

  afterAll(async () => {
    await ctx.t.close();
  });

  it('GET /api/v1/health/live returns ok without a token', async () => {
    const res = await ctx.t.http.get('/api/v1/health/live').expect(200);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.service).toBe('intelligence-service');
    expect(report.status).toBe('ok');
  });

  it('GET /api/v1/health/ready returns 503 when dependencies are unreachable', async () => {
    const res = await ctx.t.http.get('/api/v1/health/ready').expect(503);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.checks.map((check) => check.name).sort()).toEqual([
      'postgres',
      'rabbitmq',
      'redis',
    ]);
    expect(report.checks.every((check) => check.status === 'down')).toBe(true);
  });
});
