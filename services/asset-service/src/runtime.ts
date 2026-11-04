import { createTokenVerifier, keycloakRealmUrls } from '@cve/auth';
import { pingDatabase } from '@cve/database';
import type { Logger } from '@cve/logger';
import {
  createRabbitMqHealthIndicator,
  EventConsumer,
  EventPublisher,
  OutboxRelay,
  RabbitMqConnection,
} from '@cve/messaging';
import { createTcpHealthIndicator, type HealthIndicator } from '@cve/shared';

import type { AssetServiceDependencies } from './app.module.js';
import { ObservationApplier } from './associations/observation-applier.js';
import type { ManagedResource } from './common/lifecycle.js';
import type { Env } from './config/env.js';
import { CveFactsProjector } from './events/cve-facts.projector.js';
import { assetSubscriptions } from './events/subscriptions.js';
import { PrismaOutboxStore } from './outbox/prisma-outbox.store.js';
import { createPrismaClient, type PrismaClient } from './persistence/prisma.js';
import { SERVICE_NAME } from './service.js';

const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

/** Removes inbox entries older than the retention period (duplicates arrive within minutes). */
export async function removeExpiredProcessedEvents(
  prisma: PrismaClient,
  retentionDays: number,
  now = new Date(),
): Promise<number> {
  const cutoff = new Date(now.getTime() - retentionDays * 86_400_000);
  const { count } = await prisma.processedEvent.deleteMany({
    where: { processedAt: { lt: cutoff } },
  });
  return count;
}

/** Builds the production dependencies: PostgreSQL, Keycloak JWKS and RabbitMQ. */
export function createRuntimeDependencies(env: Env, logger: Logger): AssetServiceDependencies {
  const prisma = createPrismaClient(env.DATABASE_URL);
  const internal = keycloakRealmUrls(env.KEYCLOAK_URL, env.KEYCLOAK_REALM);
  const publicUrls = keycloakRealmUrls(env.KEYCLOAK_PUBLIC_URL, env.KEYCLOAK_REALM);

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
    // Redis is not used by this service yet; it is checked so the dependency stays visible.
    createTcpHealthIndicator('redis', env.REDIS_URL, { critical: false }),
  ];

  let cleanupTimer: NodeJS.Timeout | undefined;
  const cleanup = async () => {
    try {
      const removed = await removeExpiredProcessedEvents(
        prisma,
        env.PROCESSED_EVENT_RETENTION_DAYS,
      );
      if (removed > 0) logger.info({ removed }, 'expired processed-event entries removed');
    } catch (error) {
      logger.error({ err: error }, 'failed to remove expired processed-event entries');
    }
  };
  const resources: ManagedResource[] = [
    { name: 'prisma', start: () => prisma.$connect(), stop: () => prisma.$disconnect() },
    {
      name: 'processed-event-cleanup',
      start: () => {
        cleanupTimer = setInterval(() => void cleanup(), CLEANUP_INTERVAL_MS);
        cleanupTimer.unref();
        return Promise.resolve();
      },
      stop: () => {
        clearInterval(cleanupTimer);
        return Promise.resolve();
      },
    },
  ];

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
      const [observations, facts] = assetSubscriptions({
        observations: new ObservationApplier(prisma, logger),
        facts: new CveFactsProjector(prisma, logger),
      });
      resources.push({
        name: 'event-consumer',
        start: async () => {
          await consumer.subscribe(observations);
          await consumer.subscribe(facts);
        },
        stop: () => consumer.close(),
      });
    }
  } else {
    healthIndicators.push(createTcpHealthIndicator('rabbitmq', env.RABBITMQ_URL));
  }

  return {
    logger,
    verifier: createTokenVerifier({
      issuer: publicUrls.issuer,
      audience: env.KEYCLOAK_AUDIENCE,
      keys: { jwksUrl: internal.jwks, timeoutMs: env.KEYCLOAK_TIMEOUT_MS },
    }),
    prisma,
    healthIndicators,
    resources,
  };
}
