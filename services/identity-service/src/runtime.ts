import { z } from 'zod';

import { createTokenVerifier, keycloakRealmUrls } from '@cve/auth';
import { pingDatabase } from '@cve/database';
import {
  createRedisConnection,
  createRedisHealthIndicator,
  defineJob,
  JobQueue,
  JobWorker,
} from '@cve/jobs';
import type { Logger } from '@cve/logger';
import {
  createRabbitMqHealthIndicator,
  EventPublisher,
  OutboxRelay,
  RabbitMqConnection,
} from '@cve/messaging';
import { createTcpHealthIndicator, type HealthIndicator } from '@cve/shared';

import type { IdentityDependencies } from './app.module.js';
import { KeycloakEventsSync } from './audit/keycloak-events.sync.js';
import type { ManagedResource } from './common/lifecycle.js';
import type { Env } from './config/env.js';
import { KeycloakAdminClient } from './keycloak/keycloak-admin.client.js';
import { PrismaOutboxStore } from './outbox/prisma-outbox.store.js';
import { createPrismaClient } from './persistence/prisma.js';
import { PrismaAuditRepository } from './persistence/prisma-audit.repository.js';
import { PrismaProfileRepository } from './persistence/prisma-profile.repository.js';
import { PrismaSyncCursorRepository } from './persistence/prisma-sync-cursor.repository.js';
import { SERVICE_NAME } from './service.js';

export const keycloakEventsSyncJob = defineJob({
  queue: 'keycloak-events',
  name: 'sync',
  payloadSchema: z.object({}),
  retry: { attempts: 3, backoffDelayMs: 5_000 },
  timeoutMs: 120_000,
});

/** Builds the production dependencies: PostgreSQL, Keycloak, RabbitMQ (outbox) and Redis (jobs). */
export function createRuntimeDependencies(env: Env, logger: Logger): IdentityDependencies {
  const prisma = createPrismaClient(env.DATABASE_URL);
  const internal = keycloakRealmUrls(env.KEYCLOAK_URL, env.KEYCLOAK_REALM);
  const publicUrls = keycloakRealmUrls(env.KEYCLOAK_PUBLIC_URL, env.KEYCLOAK_REALM);

  const identityProvider = new KeycloakAdminClient({
    baseUrl: env.KEYCLOAK_URL,
    realm: env.KEYCLOAK_REALM,
    clientId: env.KEYCLOAK_ADMIN_CLIENT_ID,
    clientSecret: env.KEYCLOAK_ADMIN_CLIENT_SECRET,
    timeoutMs: env.KEYCLOAK_TIMEOUT_MS,
    logger: logger.child({ component: 'keycloak-admin' }),
  });
  const auditRepository = new PrismaAuditRepository(prisma);

  const healthIndicators: HealthIndicator[] = [
    {
      name: 'postgres',
      critical: true,
      check: async () => {
        const result = await pingDatabase(prisma);
        return {
          name: 'postgres',
          status: result.ok ? 'ok' : 'down',
          latencyMs: result.latencyMs,
          ...(result.error === undefined ? { message: 'SELECT 1' } : { message: result.error }),
        };
      },
    },
    {
      name: 'keycloak',
      critical: true,
      check: async (timeoutMs) => {
        const started = performance.now();
        try {
          await identityProvider.ping(timeoutMs);
          return {
            name: 'keycloak',
            status: 'ok',
            latencyMs: Math.round(performance.now() - started),
          };
        } catch (error) {
          return {
            name: 'keycloak',
            status: 'down',
            latencyMs: Math.round(performance.now() - started),
            message: error instanceof Error ? error.message : 'unreachable',
          };
        }
      },
    },
  ];
  const resources: ManagedResource[] = [
    { name: 'prisma', start: () => prisma.$connect(), stop: () => prisma.$disconnect() },
  ];

  if (env.OUTBOX_RELAY_ENABLED) {
    const connection = new RabbitMqConnection({
      url: env.RABBITMQ_URL,
      connectionName: SERVICE_NAME,
      logger,
    });
    const publisher = new EventPublisher({ connection, producer: SERVICE_NAME, logger });
    const relay = new OutboxRelay({ store: new PrismaOutboxStore(prisma), publisher, logger });
    healthIndicators.push(createRabbitMqHealthIndicator(connection));
    resources.push(
      { name: 'rabbitmq', start: () => connection.connect(), stop: () => connection.close() },
      { name: 'event-publisher', start: () => publisher.start(), stop: () => publisher.close() },
      {
        name: 'outbox-relay',
        start: () => {
          relay.start();
          return Promise.resolve();
        },
        stop: () => relay.stop(),
      },
    );
  } else {
    healthIndicators.push(createTcpHealthIndicator('rabbitmq', env.RABBITMQ_URL));
  }

  if (env.KEYCLOAK_EVENTS_SYNC_ENABLED) {
    const redis = createRedisConnection({
      url: env.REDIS_URL,
      connectionName: `${SERVICE_NAME}:jobs`,
      logger,
      role: 'worker',
    });
    const sync = new KeycloakEventsSync(
      identityProvider,
      auditRepository,
      new PrismaSyncCursorRepository(prisma),
      logger.child({ component: 'keycloak-events-sync' }),
    );
    const queue = new JobQueue(keycloakEventsSyncJob, {
      connection: redis,
      service: SERVICE_NAME,
      logger,
    });
    const worker = new JobWorker(
      keycloakEventsSyncJob,
      async () => {
        await sync.run();
      },
      { connection: redis, service: SERVICE_NAME, logger },
    );
    healthIndicators.push(createRedisHealthIndicator(redis, { critical: false }));
    resources.push(
      // Started first and stopped last: the queue and worker use this connection.
      {
        name: 'redis',
        stop: async () => {
          await redis.quit();
        },
      },
      {
        name: 'keycloak-events-schedule',
        start: () =>
          queue.schedule(
            'keycloak-events-sync',
            { everyMs: env.KEYCLOAK_EVENTS_SYNC_INTERVAL_MS },
            {},
          ),
        stop: () => queue.close(),
      },
      { name: 'keycloak-events-worker', start: () => worker.start(), stop: () => worker.close() },
    );
  } else {
    healthIndicators.push(createTcpHealthIndicator('redis', env.REDIS_URL, { critical: false }));
  }

  return {
    logger,
    verifier: createTokenVerifier({
      issuer: publicUrls.issuer,
      audience: env.KEYCLOAK_AUDIENCE,
      keys: { jwksUrl: internal.jwks, timeoutMs: env.KEYCLOAK_TIMEOUT_MS },
    }),
    identityProvider,
    auditRepository,
    profileRepository: new PrismaProfileRepository(prisma),
    healthIndicators,
    resources,
  };
}
