import 'reflect-metadata';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { healthReportSchema } from '@cve/contracts';
import { createTcpHealthIndicator } from '@cve/shared';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer } from '@cve/testing/auth';

import { downloadTestEnv, startDownloadApp } from './support.js';

describe('download-service health endpoints', () => {
  let t: HttpTestApp;

  beforeAll(async () => {
    const env = downloadTestEnv();
    t = await startDownloadApp(await createTestTokenIssuer(), {
      env,
      healthIndicators: [
        createTcpHealthIndicator('postgres', env.DATABASE_URL),
        createTcpHealthIndicator('redis', env.REDIS_URL),
      ],
    });
  });

  afterAll(async () => {
    await t.close();
  });

  it('GET /api/v1/health/live returns ok without a token', async () => {
    const res = await t.http.get('/api/v1/health/live').expect(200);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.service).toBe('download-service');
    expect(report.status).toBe('ok');
  });

  it('GET /api/v1/health/ready returns 503 when dependencies are unreachable', async () => {
    const res = await t.http.get('/api/v1/health/ready').expect(503);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.checks.map((check) => check.name).sort()).toEqual(['postgres', 'redis']);
  });
});
