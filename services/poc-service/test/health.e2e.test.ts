import 'reflect-metadata';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { healthReportSchema } from '@cve/contracts';
import type { HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer } from '@cve/testing/auth';

import { startPocApp } from './support.js';

describe('poc-service health endpoints', () => {
  let t: HttpTestApp;

  beforeAll(async () => {
    t = await startPocApp(await createTestTokenIssuer(), {
      healthIndicators: [
        {
          name: 'postgres',
          critical: true,
          check: () =>
            Promise.resolve({
              name: 'postgres',
              status: 'down',
              latencyMs: 0,
              message: 'unreachable',
            }),
        },
      ],
    });
  });

  afterAll(async () => {
    await t.close();
  });

  it('GET /api/v1/health/live returns ok without a token', async () => {
    const res = await t.http.get('/api/v1/health/live').expect(200);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.service).toBe('poc-service');
    expect(report.status).toBe('ok');
  });

  it('GET /api/v1/health/ready returns 503 when a critical dependency is down', async () => {
    const res = await t.http.get('/api/v1/health/ready').expect(503);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.checks.map((check) => check.name)).toEqual(['postgres']);
  });
});
