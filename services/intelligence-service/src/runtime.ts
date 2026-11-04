import { hostname } from 'node:os';

import { createTokenVerifier, keycloakRealmUrls } from '@cve/auth';
import { pingDatabase } from '@cve/database';
import { createRedisConnection, createRedisHealthIndicator } from '@cve/jobs';
import type { Logger } from '@cve/logger';
import {
  createRabbitMqHealthIndicator,
  EventPublisher,
  OutboxRelay,
  RabbitMqConnection,
} from '@cve/messaging';
import { createTcpHealthIndicator, type HealthIndicator } from '@cve/shared';

import type { IntelligenceDependencies } from './app.module.js';
import type { ManagedResource } from './common/lifecycle.js';
import type { Env } from './config/env.js';
import { PrismaOutboxStore } from './outbox/prisma-outbox.store.js';
import { createPrismaClient } from './persistence/prisma.js';
import { PrismaIntelligenceRepository } from './persistence/prisma-intelligence.repository.js';
import { SERVICE_NAME } from './service.js';
import { createSourceRegistry, enabledAdapters } from './sources/registry.js';
import { SyncEngine } from './sync/sync-engine.js';
import { SyncScheduler, type SyncJobQueue } from './sync/sync-jobs.js';

/**
 * Builds the production dependencies: PostgreSQL, Keycloak JWKS, RabbitMQ (outbox relay),
 * Redis (BullMQ schedules and workers) and the five source adapters.
 */
export function createRuntimeDependencies(env: Env, logger: Logger): IntelligenceDependencies {
  const prisma = createPrismaClient(env.DATABASE_URL);
  const repository = new PrismaIntelligenceRepository(prisma);
  const internal = keycloakRealmUrls(env.KEYCLOAK_URL, env.KEYCLOAK_REALM);
  const publicUrls = keycloakRealmUrls(env.KEYCLOAK_PUBLIC_URL, env.KEYCLOAK_REALM);
  const registry = createSourceRegistry(env, { logger });
  const engine = new SyncEngine({
    repository,
    adapters: enabledAdapters(registry),
    logger: logger.child({ component: 'sync-engine' }),
    instanceId: `${hostname()}:${process.pid}`,
    resumeWindowMs: env.SYNC_RESUME_WINDOW_HOURS * 60 * 60_000,
    storeRawPayloads: env.STORE_RAW_PAYLOADS,
  });

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
  ];
  const resources: ManagedResource[] = [
    { name: 'prisma', start: () => prisma.$connect(), stop: () => prisma.$disconnect() },
  ];

  // The API queues manual runs through Redis even when this replica runs no workers.
  const redis = createRedisConnection({
    url: env.REDIS_URL,
    connectionName: `${SERVICE_NAME}:jobs`,
    logger,
    role: 'worker',
  });
  healthIndicators.push(createRedisHealthIndicator(redis));
  // Registered before the scheduler so it is closed after the workers (reverse stop order).
  resources.push({
    name: 'redis',
    stop: async () => {
      await redis.quit();
    },
  });
  const scheduler = new SyncScheduler({
    connection: redis,
    engine,
    repository,
    logger: logger.child({ component: 'sync-scheduler' }),
    sources: registry,
    attempts: env.SYNC_JOB_ATTEMPTS,
    timeoutMs: env.SYNC_JOB_TIMEOUT_MS,
    maintenanceCron: env.SYNC_MAINTENANCE_CRON,
    staleAfterMs: env.SYNC_STALE_RUN_AFTER_MS,
    epssRetentionDays: env.EPSS_RETENTION_DAYS,
    outboxRetentionDays: env.OUTBOX_RETENTION_DAYS,
  });
  const jobs: SyncJobQueue = scheduler.jobQueue;

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

  if (env.SYNC_WORKER_ENABLED) {
    resources.push({
      name: 'sync-scheduler',
      start: () => scheduler.start(),
      stop: () => scheduler.stop(),
    });
  } else {
    resources.push({ name: 'sync-queue', stop: () => scheduler.stop() });
  }

  return {
    logger,
    verifier: createTokenVerifier({
      issuer: publicUrls.issuer,
      audience: env.KEYCLOAK_AUDIENCE,
      keys: { jwksUrl: internal.jwks, timeoutMs: env.KEYCLOAK_TIMEOUT_MS },
    }),
    repository,
    registry,
    jobs,
    healthIndicators,
    resources,
  };
}
