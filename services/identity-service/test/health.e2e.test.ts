import 'reflect-metadata';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { healthReportSchema } from '@cve/contracts';
import { createLogger } from '@cve/logger';
import { configureServiceApp, createTcpHealthIndicator } from '@cve/shared';
import { createHttpTestApp, type HttpTestApp } from '@cve/testing';
import { createTestTokenIssuer } from '@cve/testing/auth';

import { createTokenVerifier } from '@cve/auth';

import { AppModule } from '../src/app.module.js';
import { loadServiceEnv } from '../src/config/env.js';
import { SERVICE_NAME } from '../src/service.js';
import {
  FakeIdentityProvider,
  identityTestEnv,
  InMemoryAuditRepository,
  InMemoryProfileRepository,
} from './support.js';

describe('identity-service health endpoints', () => {
  let t: HttpTestApp;

  beforeAll(async () => {
    const env = loadServiceEnv(identityTestEnv());
    const issuer = await createTestTokenIssuer();
    const logger = createLogger({ service: SERVICE_NAME, level: 'silent' });
    t = await createHttpTestApp(
      AppModule.register(env, {
        logger,
        verifier: createTokenVerifier({
          issuer: issuer.issuer,
          audience: issuer.audience,
          keys: issuer.getKey,
        }),
        identityProvider: new FakeIdentityProvider(),
        auditRepository: new InMemoryAuditRepository(),
        profileRepository: new InMemoryProfileRepository(),
        healthIndicators: [
          createTcpHealthIndicator('postgres', env.DATABASE_URL),
          createTcpHealthIndicator('rabbitmq', env.RABBITMQ_URL),
        ],
      }),
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
  });

  it('GET /api/v1/health/live is public and returns ok', async () => {
    const res = await t.http.get('/api/v1/health/live').expect(200);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.service).toBe('identity-service');
    expect(report.status).toBe('ok');
  });

  it('GET /api/v1/health/ready returns 503 when dependencies are unreachable', async () => {
    const res = await t.http.get('/api/v1/health/ready').expect(503);
    const report = healthReportSchema.parse((res.body as { data: unknown }).data);
    expect(report.checks.map((check) => check.name).sort()).toEqual(['postgres', 'rabbitmq']);
    expect(report.checks.every((check) => check.status === 'down')).toBe(true);
  });
});
