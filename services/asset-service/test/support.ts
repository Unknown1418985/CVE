import type { INestApplication } from '@nestjs/common';

import { createTokenVerifier } from '@cve/auth';
import { createLogger } from '@cve/logger';
import { configureServiceApp, type HealthIndicator } from '@cve/shared';
import { buildServiceTestEnv, createHttpTestApp, type HttpTestApp } from '@cve/testing';
import type { TestTokenIssuer } from '@cve/testing/auth';

import { AppModule } from '../src/app.module.js';
import { loadServiceEnv } from '../src/config/env.js';
import { createPrismaClient, type PrismaClient } from '../src/persistence/prisma.js';
import { SERVICE_NAME } from '../src/service.js';

export function assetTestEnv(overrides: Record<string, string> = {}) {
  return buildServiceTestEnv(SERVICE_NAME, {
    KEYCLOAK_URL: 'http://keycloak.test/auth',
    KEYCLOAK_PUBLIC_URL: 'http://keycloak.test/auth',
    OUTBOX_RELAY_ENABLED: 'false',
    EVENT_CONSUMERS_ENABLED: 'false',
    ...overrides,
  });
}

/**
 * A Prisma client for a server that does not exist. HTTP tests that stop at authentication,
 * authorization or validation never reach it; persistence is covered by the integration suite.
 */
export function unreachablePrisma(): PrismaClient {
  return createPrismaClient('postgresql://asset_service:unused@127.0.0.1:9/asset_service');
}

export async function startAssetApp(
  issuer: TestTokenIssuer,
  options: { prisma?: PrismaClient; healthIndicators?: readonly HealthIndicator[] } = {},
): Promise<HttpTestApp> {
  const env = loadServiceEnv(assetTestEnv());
  const logger = createLogger({ service: SERVICE_NAME, level: 'silent' });
  return createHttpTestApp(
    AppModule.register(env, {
      logger,
      verifier: createTokenVerifier({
        issuer: issuer.issuer,
        audience: issuer.audience,
        keys: issuer.getKey,
      }),
      prisma: options.prisma ?? unreachablePrisma(),
      healthIndicators: options.healthIndicators ?? [],
    }),
    (app: INestApplication) => {
      configureServiceApp(app, {
        service: SERVICE_NAME,
        version: '0.0.0-test',
        logger,
        corsAllowedOrigins: [],
        swaggerEnabled: false,
      });
    },
  );
}
