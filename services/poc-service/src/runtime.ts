import { createTokenVerifier, keycloakRealmUrls } from '@cve/auth';
import { pingDatabase } from '@cve/database';
import { createRedisConnection, createRedisHealthIndicator } from '@cve/jobs';
import type { Logger } from '@cve/logger';
import {
  createRabbitMqHealthIndicator,
  EventConsumer,
  EventPublisher,
  OutboxRelay,
  RabbitMqConnection,
} from '@cve/messaging';
import { createTcpHealthIndicator, type HealthIndicator } from '@cve/shared';

import type { PocServiceDependencies } from './app.module.js';
import type { ManagedResource } from './common/lifecycle.js';
import type { Env } from './config/env.js';
import { createConnectorRegistry } from './connectors/registry.js';
import type { ScoringSettings } from './discovery/association-scorer.js';
import { DiscoveryEngine, type DiscoverySettings } from './discovery/discovery-engine.js';
import { DiscoveryScheduler } from './discovery/discovery-jobs.js';
import { CveTracker } from './events/cve-tracker.js';
import { ReferenceCollector } from './events/reference-collector.js';
import { pocSubscriptions } from './events/subscriptions.js';
import { PrismaOutboxStore } from './outbox/prisma-outbox.store.js';
import { createPrismaClient } from './persistence/prisma.js';
import { SERVICE_NAME } from './service.js';

export function scoringSettings(env: Env): ScoringSettings {
  return {
    minConfidence: env.POC_MIN_ASSOCIATION_CONFIDENCE,
    maxAssociations: env.POC_MAX_ASSOCIATIONS_PER_REPOSITORY,
  };
}

export function discoverySettings(env: Env): DiscoverySettings {
  return {
    ...scoringSettings(env),
    maxFilesPerArtifact: env.POC_MAX_FILES_PER_ARTIFACT,
    nearDuplicateThreshold: env.POC_NEAR_DUPLICATE_THRESHOLD,
    recentWindowMs: env.POC_GITHUB_RECENT_WINDOW_MINUTES * 60_000,
    recentInitialLookbackMs: env.POC_GITHUB_RECENT_INITIAL_LOOKBACK_HOURS * 3_600_000,
    recentMaxWindows: env.POC_GITHUB_RECENT_MAX_WINDOWS_PER_RUN,
  };
}

/**
 * Builds the production dependencies: PostgreSQL, Keycloak JWKS, Redis (BullMQ discovery
 * jobs), RabbitMQ (outbox relay and consumers) and the approved connectors.
 */
export function createRuntimeDependencies(env: Env, logger: Logger): PocServiceDependencies {
  const prisma = createPrismaClient(env.DATABASE_URL);
  const internal = keycloakRealmUrls(env.KEYCLOAK_URL, env.KEYCLOAK_REALM);
  const publicUrls = keycloakRealmUrls(env.KEYCLOAK_PUBLIC_URL, env.KEYCLOAK_REALM);
  const connectors = createConnectorRegistry(env, { logger });

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

  // The API and the consumers queue jobs through Redis even when this replica runs no workers.
  const redis = createRedisConnection({
    url: env.REDIS_URL,
    connectionName: `${SERVICE_NAME}:jobs`,
    logger,
    role: 'worker',
  });
  healthIndicators.push(createRedisHealthIndicator(redis));
  resources.push({
    name: 'redis',
    stop: async () => {
      await redis.quit();
    },
  });

  const settings = discoverySettings(env);
  // The scheduler owns the queues; the engine reaches inspections through it.
  const queues: { scheduler?: DiscoveryScheduler } = {};
  const engine = new DiscoveryEngine({
    prisma,
    github: connectors.github,
    inspections: {
      enqueueInspection: (input) => {
        if (queues.scheduler === undefined) throw new Error('discovery queues are not ready');
        return queues.scheduler.jobQueue.enqueueInspection(input);
      },
    },
    settings,
    logger: logger.child({ component: 'discovery-engine' }),
  });
  const scheduler = new DiscoveryScheduler({
    connection: redis,
    prisma,
    engine,
    logger: logger.child({ component: 'discovery-scheduler' }),
    githubEnabled: connectors.github !== null,
    attempts: env.POC_DISCOVERY_JOB_ATTEMPTS,
    timeoutMs: env.POC_DISCOVERY_JOB_TIMEOUT_MS,
    inspectionConcurrency: env.POC_INSPECTION_CONCURRENCY,
    sweepCron: env.POC_DISCOVERY_SWEEP_CRON,
    sweepBatchSize: env.POC_DISCOVERY_BATCH_SIZE,
    recentCron: env.POC_GITHUB_RECENT_CRON,
    maintenanceCron: env.POC_MAINTENANCE_CRON,
    retention: {
      processedEventDays: env.PROCESSED_EVENT_RETENTION_DAYS,
      outboxDays: env.OUTBOX_RETENTION_DAYS,
      runDays: env.DISCOVERY_RUN_RETENTION_DAYS,
    },
  });
  queues.scheduler = scheduler;
  const activeScheduler = scheduler;
  const jobs = connectors.github === null ? null : activeScheduler.jobQueue;

  if (env.OUTBOX_RELAY_ENABLED || env.EVENT_CONSUMERS_ENABLED) {
    const connection = new RabbitMqConnection({
      url: env.RABBITMQ_URL,
      connectionName: SERVICE_NAME,
      logger,
    });
    healthIndicators.push(createRabbitMqHealthIndicator(connection));
    resources.push({
      name: 'rabbitmq',
      start: () => connection.connect(),
      stop: () => connection.close(),
    });
    if (env.OUTBOX_RELAY_ENABLED) {
      const publisher = new EventPublisher({ connection, producer: SERVICE_NAME, logger });
      const relay = new OutboxRelay({ store: new PrismaOutboxStore(prisma), publisher, logger });
      resources.push(
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
    }
    if (env.EVENT_CONSUMERS_ENABLED) {
      // Duplicate suppression happens in the handlers' own transactions (inbox table).
      const consumer = new EventConsumer({ connection, service: SERVICE_NAME, logger });
      const [tracker, references] = pocSubscriptions({
        tracker: new CveTracker(prisma, logger.child({ component: 'cve-tracker' })),
        references: new ReferenceCollector(
          prisma,
          jobs,
          scoringSettings(env),
          logger.child({ component: 'reference-collector' }),
        ),
      });
      resources.push({
        name: 'event-consumer',
        start: async () => {
          await consumer.subscribe(tracker);
          if (connectors.referencesEnabled) await consumer.subscribe(references);
        },
        stop: () => consumer.close(),
      });
    }
  } else {
    healthIndicators.push(createTcpHealthIndicator('rabbitmq', env.RABBITMQ_URL));
  }

  resources.push(
    env.DISCOVERY_WORKER_ENABLED
      ? {
          name: 'discovery-scheduler',
          start: () => activeScheduler.start(),
          stop: () => activeScheduler.stop(),
        }
      : { name: 'discovery-queues', stop: () => activeScheduler.stop() },
  );

  return {
    logger,
    verifier: createTokenVerifier({
      issuer: publicUrls.issuer,
      audience: env.KEYCLOAK_AUDIENCE,
      keys: { jwksUrl: internal.jwks, timeoutMs: env.KEYCLOAK_TIMEOUT_MS },
    }),
    prisma,
    healthIndicators,
    jobs,
    connectors: connectors.info,
    scoring: scoringSettings(env),
    resources,
  };
}
