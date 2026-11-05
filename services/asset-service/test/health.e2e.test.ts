import 'reflect-metadata';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { healthReportSchema } from '@cve/contracts';
import { createTcpHealthIndicator } from '@cve/shared';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer } from '@cve/testing/auth';

import { loadServiceEnv } from '../src/config/env.js';
import { assetTestEnv, startAssetApp } from './support.js';

describe('asset-service health endpoints', () => {
  let t: HttpTestApp;

  beforeAll(async () => {
    const env = loadServiceEnv(assetTestEnv());
    t = await startAssetApp(await createTestTokenIssuer(), {
      healthIndicators: [
        createTcpHealthIndicator('postgres', env.DATABASE_URL),
        createTcpHealthIndicator('rabbitmq', env.RABBITMQ_URL),
      ],
    });
  });

  afterAll(async () => {
    await t.close();
  });

  it('GET /api/v1/health/live is public and returns ok', async () => {
    const res = await t.http.get('/api/v1/health/live').expect(200);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.service).toBe('asset-service');
    expect(report.status).toBe('ok');
  });

  it('GET /api/v1/health/ready returns 503 when dependencies are unreachable', async () => {
    const res = await t.http.get('/api/v1/health/ready').expect(503);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.checks.map((check) => check.name).sort()).toEqual(['postgres', 'rabbitmq']);
    expect(report.checks.every((check) => check.status === 'down')).toBe(true);
  });
});
