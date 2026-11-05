import { createTokenVerifier, keycloakRealmUrls } from '@cve/auth';
import { OBJECT_STORAGE_BUCKETS } from '@cve/contracts';
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

import type { DownloadServiceDependencies } from './app.module.js';
import type { ManagedResource } from './common/lifecycle.js';
import type { Env } from './config/env.js';
import { AddressPolicy } from './domain/ip-policy.js';
import type { SourcePolicy } from './domain/sources.js';
import { DownloadEngine } from './download/download-engine.js';
import { DownloadScheduler } from './download/download-jobs.js';
import { SafeFetcher, type Resolver } from './download/safe-fetcher.js';
import { buildSourcePolicies } from './download/source-catalog.js';
import { downloadSubscriptions, PocEventHandlers } from './events/poc-consumer.js';
import type { PrismaClient } from './generated/prisma/client.js';
import { PrismaOutboxStore } from './outbox/prisma-outbox.store.js';
import { createPrismaClient } from './persistence/prisma.js';
import { ClamdScanner, type FileScanner } from './scanning/clamav.js';
import { ScanEngine } from './scanning/scan-engine.js';
import { YaraCliScanner } from './scanning/yara.js';
import { SERVICE_NAME } from './service.js';
import { S3ArtifactObjectStore, type ArtifactObjectStore } from './storage/object-store.js';

/** Test seams: a local mock source needs its own DNS answers, address exception and CA. */
export interface NetworkOverrides {
  readonly resolver?: Resolver;
  readonly addressExceptions?: readonly string[];
  readonly ca?: string | Buffer;
}

export function createFetcher(env: Env, overrides: NetworkOverrides = {}): SafeFetcher {
  return new SafeFetcher({
    // Production passes no exceptions: every private, loopback and reserved range is blocked.
    addressPolicy: new AddressPolicy(overrides.addressExceptions ?? []),
    userAgent: env.DOWNLOAD_USER_AGENT,
    connectTimeoutMs: env.DOWNLOAD_RESPONSE_TIMEOUT_MS,
    idleTimeoutMs: env.DOWNLOAD_IDLE_TIMEOUT_MS,
    totalTimeoutMs: env.DOWNLOAD_TOTAL_TIMEOUT_MS,
    maxRedirects: env.DOWNLOAD_MAX_REDIRECTS,
    ...(overrides.resolver === undefined ? {} : { resolver: overrides.resolver }),
    ...(overrides.ca === undefined ? {} : { ca: overrides.ca }),
  });
}

export function createScanners(env: Env): FileScanner[] {
  const scanners: FileScanner[] = [];
  if (env.CLAMAV_ENABLED) {
    scanners.push(
      new ClamdScanner({
        host: env.CLAMAV_HOST,
        port: env.CLAMAV_PORT,
        timeoutMs: env.CLAMAV_TIMEOUT_MS,
      }),
    );
  }
  if (env.YARA_ENABLED) {
    scanners.push(
      new YaraCliScanner({
        binary: env.YARA_BINARY,
        rulesPath: env.YARA_RULES_PATH,
        timeoutMs: env.YARA_TIMEOUT_MS,
      }),
    );
  }
  return scanners;
}

export interface DownloadComponents {
  readonly sources: SourcePolicy[];
  readonly downloads: DownloadEngine;
  readonly scanner: ScanEngine;
  readonly scheduler: DownloadScheduler;
  readonly handlers: PocEventHandlers;
}

/** Builds the download pipeline (engines, queues, event handlers) on shared clients. */
export function createComponents(input: {
  readonly env: Env;
  readonly logger: Logger;
  readonly prisma: PrismaClient;
  readonly store: ArtifactObjectStore;
  readonly connection: ReturnType<typeof createRedisConnection>;
  readonly scanners: readonly FileScanner[];
  readonly network?: NetworkOverrides;
}): DownloadComponents {
  const { env, logger, prisma, store } = input;
  const sources = buildSourcePolicies(env);
  const scans: { scheduler?: DownloadScheduler } = {};
  const downloads = new DownloadEngine({
    prisma,
    fetcher: createFetcher(env, input.network),
    store,
    sources,
    scans: {
      enqueueScan: (artifactId, reason) => {
        if (scans.scheduler === undefined) throw new Error('scan queue is not ready');
        return scans.scheduler.enqueueScan(artifactId, reason);
      },
    },
    stagingDir: env.DOWNLOAD_STAGING_DIR,
    totalTimeoutMs: env.DOWNLOAD_TOTAL_TIMEOUT_MS,
    logger: logger.child({ component: 'download-engine' }),
  });
  const scanner = new ScanEngine({
    prisma,
    store,
    scanners: input.scanners,
    required: env.SCAN_REQUIRED_SCANNERS,
    stagingDir: env.DOWNLOAD_STAGING_DIR,
    logger: logger.child({ component: 'scan-engine' }),
  });
  const scheduler = new DownloadScheduler({
    connection: input.connection,
    prisma,
    store,
    downloads,
    scanner,
    logger: logger.child({ component: 'download-scheduler' }),
    attempts: env.DOWNLOAD_JOB_ATTEMPTS,
    backoffMs: env.DOWNLOAD_RETRY_BACKOFF_MS,
    downloadTimeoutMs: env.DOWNLOAD_TOTAL_TIMEOUT_MS,
    scanAttempts: env.SCAN_JOB_ATTEMPTS,
    scanTimeoutMs: Math.max(env.CLAMAV_TIMEOUT_MS, env.YARA_TIMEOUT_MS) * 2 + 5 * 60_000,
    concurrency: env.DOWNLOAD_CONCURRENCY,
    ratePerMinute: env.DOWNLOAD_RATE_LIMIT_PER_MINUTE,
    scanConcurrency: env.SCAN_CONCURRENCY,
    schedulerCron: env.DOWNLOAD_SCHEDULER_CRON,
    schedulerBatchSize: env.DOWNLOAD_SCHEDULER_BATCH_SIZE,
    maintenanceCron: env.DOWNLOAD_MAINTENANCE_CRON,
    retention: {
      processedEventDays: env.PROCESSED_EVENT_RETENTION_DAYS,
      outboxDays: env.OUTBOX_RETENTION_DAYS,
    },
  });
  scans.scheduler = scheduler;
  const handlers = new PocEventHandlers({
    prisma,
    jobs: scheduler,
    store,
    sources,
    maxAttempts: env.DOWNLOAD_JOB_ATTEMPTS,
    maxExpectedRatio: env.DOWNLOAD_MAX_EXPECTED_RATIO,
    logger: logger.child({ component: 'poc-events' }),
  });
  return { sources, downloads, scanner, scheduler, handlers };
}

/**
 * Builds the production dependencies: PostgreSQL, Keycloak JWKS, Redis (BullMQ), RabbitMQ
 * (outbox relay and PoC event consumers), MinIO and the scanners.
 */
export function createRuntimeDependencies(env: Env, logger: Logger): DownloadServiceDependencies {
  const prisma = createPrismaClient(env.DATABASE_URL);
  const internal = keycloakRealmUrls(env.KEYCLOAK_URL, env.KEYCLOAK_REALM);
  const publicUrls = keycloakRealmUrls(env.KEYCLOAK_PUBLIC_URL, env.KEYCLOAK_REALM);
  const store = new S3ArtifactObjectStore(env);
  const scanners = createScanners(env);

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
      name: 'minio',
      critical: true,
      check: async () => {
        const started = performance.now();
        try {
          await store.ping(OBJECT_STORAGE_BUCKETS.pocQuarantine);
          return {
            name: 'minio',
            status: 'ok',
            latencyMs: Math.round(performance.now() - started),
          };
        } catch (error) {
          return {
            name: 'minio',
            status: 'down',
            latencyMs: Math.round(performance.now() - started),
            message: error instanceof Error ? error.message : String(error),
          };
        }
      },
    },
    // Scanners are not critical for the API; without them artifacts stay `incomplete`.
    ...scanners.map((scanner): HealthIndicator => ({
      name: scanner.name,
      critical: false,
      check: async () => {
        const started = performance.now();
        try {
          await scanner.ping();
          return {
            name: scanner.name,
            status: 'ok',
            latencyMs: Math.round(performance.now() - started),
          };
        } catch (error) {
          return {
            name: scanner.name,
            status: 'down',
            latencyMs: Math.round(performance.now() - started),
            message: error instanceof Error ? error.message : String(error),
          };
        }
      },
    })),
  ];
  const resources: ManagedResource[] = [
    { name: 'prisma', start: () => prisma.$connect(), stop: () => prisma.$disconnect() },
    {
      name: 'object-store',
      stop: () => {
        store.close();
        return Promise.resolve();
      },
    },
  ];

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

  const components = createComponents({ env, logger, prisma, store, connection: redis, scanners });

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
      const subscriptions = downloadSubscriptions(components.handlers);
      resources.push({
        name: 'event-consumer',
        start: async () => {
          for (const subscription of subscriptions) {
            await consumer.subscribe(subscription as Parameters<typeof consumer.subscribe>[0]);
          }
        },
        stop: () => consumer.close(),
      });
    }
  } else {
    healthIndicators.push(createTcpHealthIndicator('rabbitmq', env.RABBITMQ_URL));
  }

  resources.push(
    env.DOWNLOAD_WORKER_ENABLED
      ? {
          name: 'download-scheduler',
          start: () => components.scheduler.start(),
          stop: () => components.scheduler.stop(),
        }
      : { name: 'download-queues', stop: () => components.scheduler.stop() },
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
    jobs: components.scheduler,
    store,
    sources: components.sources,
    settings: { maxAttempts: env.DOWNLOAD_JOB_ATTEMPTS },
    resources,
  };
}
