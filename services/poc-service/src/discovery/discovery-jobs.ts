import { createHash, randomUUID } from 'node:crypto';

import { z } from 'zod';

import {
  cveIdSchema,
  discoveryModeSchema,
  discoveryTriggerSchema,
  pocConnectorSchema,
} from '@cve/contracts';
import {
  defineJob,
  JobQueue,
  JobWorker,
  PermanentJobError,
  type createRedisConnection,
  type JobContext,
  type JobDefinition,
} from '@cve/jobs';
import type { Logger } from '@cve/logger';

import type { PrismaClient } from '../generated/prisma/client.js';
import { SERVICE_NAME } from '../service.js';
import type { DiscoveryEngine, InspectionQueue } from './discovery-engine.js';

type Redis = ReturnType<typeof createRedisConnection>;

const FULL_NAME_PATTERN = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;

export const discoveryPayloadSchema = z
  .object({
    connector: pocConnectorSchema,
    mode: discoveryModeSchema,
    trigger: discoveryTriggerSchema,
    cveId: cveIdSchema.optional(),
    repositoryId: z.uuid().optional(),
    fullName: z.string().regex(FULL_NAME_PATTERN).optional(),
    requestedBy: z.string().max(255).nullable().default(null),
    correlationId: z.string().max(128).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.mode === 'cve' && value.cveId === undefined) {
      ctx.addIssue({ code: 'custom', path: ['cveId'], message: 'required for mode cve' });
    }
    if (
      value.mode === 'repository' &&
      value.repositoryId === undefined &&
      value.fullName === undefined
    ) {
      ctx.addIssue({
        code: 'custom',
        path: ['repositoryId'],
        message: 'repositoryId or fullName is required',
      });
    }
  });
export type DiscoveryPayload = z.input<typeof discoveryPayloadSchema>;
type DiscoveryJobData = z.output<typeof discoveryPayloadSchema>;

export interface QueueNames {
  readonly discovery: string;
  readonly inspection: string;
  readonly scheduling: string;
  readonly maintenance: string;
}

export const DEFAULT_QUEUES: QueueNames = {
  discovery: 'poc-discovery',
  inspection: 'poc-inspection',
  scheduling: 'poc-scheduling',
  maintenance: 'poc-maintenance',
};

export function discoveryJob(options: {
  queue: string;
  name: string;
  attempts: number;
  timeoutMs: number;
  backoffDelayMs: number;
}) {
  return defineJob({
    queue: options.queue,
    name: options.name,
    payloadSchema: discoveryPayloadSchema,
    retry: { attempts: options.attempts, backoffDelayMs: options.backoffDelayMs },
    timeoutMs: options.timeoutMs,
  });
}

const emptyPayload = z.object({});
type EmptyPayload = z.output<typeof emptyPayload>;

/** Idempotency key: same input within BullMQ's retention means the same job. */
export function hashedJobId(prefix: string, key: string): string {
  return `${prefix}.${createHash('sha256').update(key).digest('hex').slice(0, 40)}`;
}

/** Maps a run outcome to BullMQ semantics: retryable failures throw, others fail permanently. */
export function discoveryHandler(engine: DiscoveryEngine) {
  return async (payload: DiscoveryJobData, context: JobContext): Promise<void> => {
    const outcome = await engine.run(
      {
        connector: payload.connector,
        mode: payload.mode,
        trigger: payload.trigger,
        cveId: payload.cveId,
        repositoryId: payload.repositoryId,
        fullName: payload.fullName,
        requestedBy: payload.requestedBy,
        correlationId: payload.correlationId,
        jobId: context.jobId,
        attempt: context.attempt,
        maxAttempts: context.maxAttempts,
      },
      context.signal,
    );
    if (outcome.status === 'failed') {
      if (!outcome.retryable) throw new PermanentJobError(outcome.error.message);
      throw outcome.error;
    }
  };
}

/** Producer for discovery and inspection jobs (API, consumers, scheduler). */
export interface DiscoveryJobQueue extends InspectionQueue {
  enqueueDiscovery(
    payload: DiscoveryPayload,
    jobId?: string,
  ): Promise<{ jobId: string; queued: boolean }>;
}

export class BullDiscoveryJobQueue implements DiscoveryJobQueue {
  constructor(
    private readonly discovery: JobQueue<DiscoveryJobData>,
    private readonly inspection: JobQueue<DiscoveryJobData>,
  ) {}

  private async add(
    queue: JobQueue<DiscoveryJobData>,
    payload: DiscoveryPayload,
    jobId: string,
  ): Promise<{ jobId: string; queued: boolean }> {
    const existing = await queue.queue.getJob(jobId);
    if (existing !== undefined) return { jobId, queued: false };
    const job = await queue.add(discoveryPayloadSchema.parse(payload), { jobId });
    return { jobId: job.id, queued: true };
  }

  enqueueDiscovery(payload: DiscoveryPayload, jobId?: string) {
    const queue = payload.mode === 'repository' ? this.inspection : this.discovery;
    return this.add(queue, payload, jobId ?? `${payload.trigger}.${payload.mode}.${randomUUID()}`);
  }

  async enqueueInspection(input: {
    repositoryId: string;
    dedupeKey: string;
    correlationId: string | undefined;
  }) {
    const result = await this.add(
      this.inspection,
      {
        connector: 'github',
        mode: 'repository',
        trigger: 'event',
        repositoryId: input.repositoryId,
        ...(input.correlationId === undefined ? {} : { correlationId: input.correlationId }),
      },
      hashedJobId('inspect', `${input.repositoryId}:${input.dedupeKey}`),
    );
    return result.queued;
  }
}

// ---------------------------------------------------------------------------- scheduling

/** Lease that keeps a picked CVE from being queued again while its job waits or runs. */
const SCAN_LEASE_MS = 2 * 60 * 60_000;

/**
 * Queues discovery for the tracked CVEs whose scan is due, most important first (KEV, EPSS,
 * recency). The picked rows are leased in the same statement, so replicas never pick the same
 * CVE twice.
 */
export async function runDiscoverySweep(options: {
  readonly prisma: PrismaClient;
  readonly queue: DiscoveryJobQueue;
  readonly batchSize: number;
  readonly logger: Logger;
  readonly now?: Date;
}): Promise<number> {
  const now = options.now ?? new Date();
  const lease = new Date(now.getTime() + SCAN_LEASE_MS);
  // UPDATE … RETURNING has no defined order: the outer query restores the priority order.
  const due = await options.prisma.$queryRaw<{ cveId: string }[]>`
    WITH "picked" AS (
      UPDATE "tracked_cves" SET "next_scan_at" = ${lease}
       WHERE "cve_id" IN (
             SELECT "cve_id" FROM "tracked_cves"
              WHERE "next_scan_at" <= ${now} AND "deleted_at" IS NULL AND "state" = 'published'
              ORDER BY "in_kev" DESC, "epss_score" DESC NULLS LAST, "published_at" DESC NULLS LAST
              LIMIT ${options.batchSize}
                FOR UPDATE SKIP LOCKED)
      RETURNING "cve_id", "in_kev", "epss_score", "published_at")
    SELECT "cve_id" AS "cveId" FROM "picked"
     ORDER BY "in_kev" DESC, "epss_score" DESC NULLS LAST, "published_at" DESC NULLS LAST`;
  const slot = now.toISOString().slice(0, 13).replace(/[-T:]/g, '');
  let queued = 0;
  for (const { cveId } of due) {
    const result = await options.queue.enqueueDiscovery(
      { connector: 'github', mode: 'cve', trigger: 'scheduled', cveId },
      `scheduled.cve.${cveId}.${slot}`,
    );
    if (result.queued) queued += 1;
  }
  if (due.length > 0)
    options.logger.info({ due: due.length, queued }, 'discovery sweep queued CVEs');
  return queued;
}

export interface MaintenanceOptions {
  readonly prisma: PrismaClient;
  readonly queue: DiscoveryJobQueue;
  readonly logger: Logger;
  readonly githubEnabled: boolean;
  /** A running run older than this is failed (its worker died). */
  readonly staleRunAfterMs: number;
  readonly processedEventRetentionDays: number;
  readonly outboxRetentionDays: number;
  readonly runRetentionDays: number;
  readonly now?: Date;
}

const DAY_MS = 86_400_000;
const RECOVERY_BATCH = 100;

/**
 * Hourly recovery and retention: fails runs whose worker died, re-queues inspections and
 * reference lookups that were never queued (the database is the source of truth, Redis may
 * have lost jobs), and purges old inbox, outbox and run rows.
 */
export async function runMaintenance(options: MaintenanceOptions) {
  const now = options.now ?? new Date();
  const { prisma } = options;
  const staleRuns = await prisma.discoveryRun.updateMany({
    where: {
      status: 'running',
      startedAt: { lt: new Date(now.getTime() - options.staleRunAfterMs) },
    },
    data: {
      status: 'failed',
      finishedAt: now,
      error: 'The worker stopped before the run finished',
    },
  });
  let inspections = 0;
  let references = 0;
  if (options.githubEnabled) {
    const due = await prisma.pocRepository.findMany({
      where: { status: 'active', inspectionDueAt: { lt: new Date(now.getTime() - 10 * 60_000) } },
      select: { id: true, inspectionDueAt: true },
      orderBy: { inspectionDueAt: 'asc' },
      take: RECOVERY_BATCH,
    });
    for (const repository of due) {
      const queued = await options.queue.enqueueInspection({
        repositoryId: repository.id,
        dedupeKey: `recovery:${String(repository.inspectionDueAt?.getTime() ?? 0)}`,
        correlationId: undefined,
      });
      if (queued) inspections += 1;
    }
    const unresolved = await prisma.pocReference.findMany({
      where: {
        kind: 'github_repository',
        repositoryId: null,
        removedAt: null,
        repositoryKey: { not: null },
        OR: [
          { resolveQueuedAt: null },
          { resolveQueuedAt: { lt: new Date(now.getTime() - 7 * DAY_MS) } },
        ],
      },
      select: { repositoryKey: true },
      distinct: ['repositoryKey'],
      take: RECOVERY_BATCH,
    });
    for (const { repositoryKey } of unresolved) {
      if (repositoryKey === null || !FULL_NAME_PATTERN.test(repositoryKey)) continue;
      await options.queue.enqueueDiscovery(
        { connector: 'github', mode: 'repository', trigger: 'event', fullName: repositoryKey },
        hashedJobId('reference', `${repositoryKey}:${now.toISOString().slice(0, 10)}`),
      );
      await prisma.pocReference.updateMany({
        where: { repositoryKey, repositoryId: null },
        data: { resolveQueuedAt: now },
      });
      references += 1;
    }
  }
  const purged = {
    processedEvents: (
      await prisma.processedEvent.deleteMany({
        where: {
          processedAt: {
            lt: new Date(now.getTime() - options.processedEventRetentionDays * DAY_MS),
          },
        },
      })
    ).count,
    outboxEvents: (
      await prisma.outboxEvent.deleteMany({
        where: {
          publishedAt: { lt: new Date(now.getTime() - options.outboxRetentionDays * DAY_MS) },
        },
      })
    ).count,
    runs: (
      await prisma.discoveryRun.deleteMany({
        where: {
          status: { not: 'running' },
          startedAt: { lt: new Date(now.getTime() - options.runRetentionDays * DAY_MS) },
        },
      })
    ).count,
  };
  const result = { staleRuns: staleRuns.count, inspections, references, purged };
  options.logger.info(result, 'maintenance finished');
  return result;
}

// ---------------------------------------------------------------------------- wiring

export interface DiscoverySchedulerOptions {
  readonly connection: Redis;
  readonly prisma: PrismaClient;
  readonly engine: DiscoveryEngine;
  readonly logger: Logger;
  readonly githubEnabled: boolean;
  readonly attempts: number;
  readonly timeoutMs: number;
  readonly inspectionConcurrency: number;
  readonly sweepCron: string;
  readonly sweepBatchSize: number;
  readonly recentCron: string;
  readonly maintenanceCron: string;
  readonly retention: {
    readonly processedEventDays: number;
    readonly outboxDays: number;
    readonly runDays: number;
  };
  readonly retryBackoffMs?: number;
  readonly queues?: QueueNames;
}

/**
 * BullMQ wiring of the PoC Service:
 * - `poc-discovery`: CVE searches and the recent sweep (concurrency 1: the search quota is
 *   small and shared);
 * - `poc-inspection`: repository inspections (metadata, head commit, file listing);
 * - `poc-scheduling`: queues due tracked CVEs;
 * - `poc-maintenance`: recovery and retention.
 */
export class DiscoveryScheduler {
  readonly jobQueue: BullDiscoveryJobQueue;
  private readonly discoveryDefinition: JobDefinition<DiscoveryJobData>;
  private readonly inspectionDefinition: JobDefinition<DiscoveryJobData>;
  private readonly sweepDefinition: JobDefinition<EmptyPayload>;
  private readonly maintenanceDefinition: JobDefinition<EmptyPayload>;
  private readonly discoveryQueue: JobQueue<DiscoveryJobData>;
  private readonly inspectionQueue: JobQueue<DiscoveryJobData>;
  private readonly sweepQueue: JobQueue<EmptyPayload>;
  private readonly maintenanceQueue: JobQueue<EmptyPayload>;
  private readonly workers: { start(): Promise<void>; close(): Promise<void> }[] = [];

  constructor(private readonly options: DiscoverySchedulerOptions) {
    const queues = options.queues ?? DEFAULT_QUEUES;
    const backoffDelayMs = options.retryBackoffMs ?? 60_000;
    this.discoveryDefinition = discoveryJob({
      queue: queues.discovery,
      name: 'discover',
      attempts: options.attempts,
      timeoutMs: options.timeoutMs,
      backoffDelayMs,
    });
    this.inspectionDefinition = discoveryJob({
      queue: queues.inspection,
      name: 'inspect',
      attempts: options.attempts,
      timeoutMs: Math.min(options.timeoutMs, 10 * 60_000),
      backoffDelayMs,
    });
    this.sweepDefinition = defineJob({
      queue: queues.scheduling,
      name: 'sweep',
      payloadSchema: emptyPayload,
      retry: { attempts: 3, backoffDelayMs: 10_000 },
      timeoutMs: 5 * 60_000,
    });
    this.maintenanceDefinition = defineJob({
      queue: queues.maintenance,
      name: 'maintain',
      payloadSchema: emptyPayload,
      retry: { attempts: 3, backoffDelayMs: 10_000 },
      timeoutMs: 10 * 60_000,
    });
    const queueOptions = {
      connection: options.connection,
      service: SERVICE_NAME,
      logger: options.logger,
    } as const;
    this.discoveryQueue = new JobQueue(this.discoveryDefinition, queueOptions);
    this.inspectionQueue = new JobQueue(this.inspectionDefinition, queueOptions);
    this.sweepQueue = new JobQueue(this.sweepDefinition, queueOptions);
    this.maintenanceQueue = new JobQueue(this.maintenanceDefinition, queueOptions);
    this.jobQueue = new BullDiscoveryJobQueue(this.discoveryQueue, this.inspectionQueue);
  }

  async start(): Promise<void> {
    const { options } = this;
    const workerOptions = {
      connection: options.connection,
      service: SERVICE_NAME,
      logger: options.logger,
    } as const;
    const handler = discoveryHandler(options.engine);
    const workers = [
      new JobWorker(this.discoveryDefinition, handler, { ...workerOptions, concurrency: 1 }),
      new JobWorker(this.inspectionDefinition, handler, {
        ...workerOptions,
        concurrency: options.inspectionConcurrency,
      }),
      new JobWorker(
        this.sweepDefinition,
        async () => {
          if (!options.githubEnabled) return;
          await runDiscoverySweep({
            prisma: options.prisma,
            queue: this.jobQueue,
            batchSize: options.sweepBatchSize,
            logger: options.logger,
          });
        },
        workerOptions,
      ),
      new JobWorker(
        this.maintenanceDefinition,
        async () => {
          await runMaintenance({
            prisma: options.prisma,
            queue: this.jobQueue,
            logger: options.logger,
            githubEnabled: options.githubEnabled,
            staleRunAfterMs: options.timeoutMs + 10 * 60_000,
            processedEventRetentionDays: options.retention.processedEventDays,
            outboxRetentionDays: options.retention.outboxDays,
            runRetentionDays: options.retention.runDays,
          });
        },
        workerOptions,
      ),
    ];
    for (const worker of workers) {
      this.workers.push(worker);
      await worker.start();
    }
    await this.sweepQueue.schedule('sweep', { cron: options.sweepCron, timezone: 'UTC' }, {});
    await this.maintenanceQueue.schedule(
      'maintenance',
      { cron: options.maintenanceCron, timezone: 'UTC' },
      {},
    );
    if (options.githubEnabled) {
      await this.discoveryQueue.schedule(
        'scheduled.recent',
        { cron: options.recentCron, timezone: 'UTC' },
        { connector: 'github', mode: 'recent', trigger: 'scheduled', requestedBy: null },
      );
    } else if (await this.discoveryQueue.removeSchedule('scheduled.recent')) {
      options.logger.info('recent sweep schedule removed: the github connector is disabled');
    }
  }

  async stop(): Promise<void> {
    for (const worker of this.workers) await worker.close();
    for (const queue of [
      this.discoveryQueue,
      this.inspectionQueue,
      this.sweepQueue,
      this.maintenanceQueue,
    ]) {
      await queue.close();
    }
  }
}
