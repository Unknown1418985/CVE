import { randomUUID } from 'node:crypto';

import { z } from 'zod';

import {
  intelligenceSourceSchema,
  syncTriggerSchema,
  type IntelligenceSource,
} from '@cve/contracts';
import {
  defineJob,
  JobQueue,
  JobWorker,
  PermanentJobError,
  type createRedisConnection,
  type JobDefinition,
} from '@cve/jobs';
import type { Logger } from '@cve/logger';

type Redis = ReturnType<typeof createRedisConnection>;

import type { IntelligenceRepository } from '../persistence/ports.js';
import { SERVICE_NAME } from '../service.js';
import type { SyncEngine } from './sync-engine.js';

export const sourceSyncPayloadSchema = z.object({
  source: intelligenceSourceSchema,
  trigger: syncTriggerSchema,
  requestedBy: z.string().max(200).nullable().default(null),
  fresh: z.boolean().default(false),
  correlationId: z.string().max(128).optional(),
});
export type SourceSyncPayload = z.input<typeof sourceSyncPayloadSchema>;

export function sourceSyncJob(options: {
  attempts: number;
  timeoutMs: number;
  backoffDelayMs?: number;
  queue?: string;
}) {
  return defineJob({
    queue: options.queue ?? 'source-sync',
    name: 'run',
    payloadSchema: sourceSyncPayloadSchema,
    // Each retry is a new run that resumes from the failed run's checkpoint.
    retry: { attempts: options.attempts, backoffDelayMs: options.backoffDelayMs ?? 60_000 },
    timeoutMs: options.timeoutMs,
  });
}

export function maintenanceJob(queue = 'sync-maintenance') {
  return defineJob({
    queue,
    name: 'recover',
    payloadSchema: z.object({}),
    retry: { attempts: 3, backoffDelayMs: 10_000 },
    timeoutMs: 5 * 60_000,
  });
}
type MaintenancePayload = z.output<ReturnType<typeof maintenanceJob>['payloadSchema']>;

export class SourceBusyError extends Error {
  constructor(source: IntelligenceSource) {
    super(`A ${source} synchronisation is already running`);
    this.name = 'SourceBusyError';
  }
}

/** Handles one `source-sync` job: runs the engine and maps the outcome to BullMQ semantics. */
export function sourceSyncHandler(engine: SyncEngine) {
  return async (
    payload: z.output<typeof sourceSyncPayloadSchema>,
    context: {
      jobId: string;
      attempt: number;
      maxAttempts: number;
      signal: AbortSignal;
      logger: Logger;
    },
  ): Promise<void> => {
    const outcome = await engine.run(
      {
        source: payload.source,
        trigger: payload.trigger,
        jobId: context.jobId,
        attempt: context.attempt,
        maxAttempts: context.maxAttempts,
        requestedBy: payload.requestedBy,
        fresh: payload.fresh,
        correlationId: payload.correlationId,
      },
      context.signal,
    );
    switch (outcome.status) {
      case 'succeeded':
        return;
      case 'skipped':
        if (outcome.reason === 'disabled')
          throw new PermanentJobError(`${payload.source} is disabled`);
        // A scheduled run that overlaps a running one is redundant: the next schedule continues.
        if (payload.trigger === 'scheduled') {
          context.logger.info(
            { source: payload.source },
            'skipped: the source is already synchronising',
          );
          return;
        }
        throw new SourceBusyError(payload.source);
      case 'failed':
        if (!outcome.retryable) throw new PermanentJobError(outcome.error.message);
        throw outcome.error;
    }
  };
}

export interface MaintenanceOptions {
  readonly repository: IntelligenceRepository;
  readonly engine: SyncEngine;
  readonly enqueue: (payload: SourceSyncPayload, jobId: string) => Promise<unknown>;
  readonly staleAfterMs: number;
  readonly epssRetentionDays: number;
  readonly outboxRetentionDays: number;
  readonly logger: Logger;
  readonly now?: () => Date;
}

/**
 * Periodic recovery: runs whose worker died (no heartbeat) are marked abandoned and a recovery
 * job resumes them from their checkpoint; expired EPSS scores and published outbox rows are
 * purged.
 */
export async function runMaintenance(options: MaintenanceOptions): Promise<{ recovered: number }> {
  const now = options.now?.() ?? new Date();
  const stale = await options.repository.findStaleRuns(
    new Date(now.getTime() - options.staleAfterMs),
  );
  let recovered = 0;
  for (const run of stale) {
    const abandoned = await options.repository.failRun(run.id, {
      status: 'abandoned',
      finishedAt: now,
      stats: null,
      error: 'The worker stopped sending heartbeats',
      events: [options.engine.abandonedRunEvent(run, now)],
    });
    if (!abandoned || !options.engine.isEnabled(run.source)) continue;
    await options.enqueue(
      { source: run.source, trigger: 'recovery' },
      `recovery.${run.source}.${run.id}`,
    );
    recovered += 1;
    options.logger.warn({ runId: run.id, source: run.source }, 'abandoned run recovered');
  }
  const epssCutoff = new Date(now.getTime() - options.epssRetentionDays * 86_400_000)
    .toISOString()
    .slice(0, 10);
  const purgedScores = await options.repository.purgeEpssScoresBefore(epssCutoff);
  const purgedEvents = await options.repository.purgePublishedOutboxBefore(
    new Date(now.getTime() - options.outboxRetentionDays * 86_400_000),
  );
  if (purgedScores > 0 || purgedEvents > 0) {
    options.logger.info({ purgedScores, purgedEvents }, 'expired data purged');
  }
  return { recovered };
}

/** Port used by the API to queue runs (BullMQ in production, a fake in tests). */
export interface SyncJobQueue {
  /** Queues a run; with an existing `jobId` nothing is queued and `queued` is false. */
  enqueue(payload: SourceSyncPayload, jobId?: string): Promise<{ jobId: string; queued: boolean }>;
}

export class BullSyncJobQueue implements SyncJobQueue {
  constructor(private readonly queue: JobQueue<z.output<typeof sourceSyncPayloadSchema>>) {}

  async enqueue(
    payload: SourceSyncPayload,
    jobId?: string,
  ): Promise<{ jobId: string; queued: boolean }> {
    const id = jobId ?? `${payload.trigger}.${payload.source}.${randomUUID()}`;
    const existing = await this.queue.queue.getJob(id);
    if (existing !== undefined) return { jobId: id, queued: false };
    const job = await this.queue.add(sourceSyncPayloadSchema.parse(payload), { jobId: id });
    return { jobId: job.id, queued: true };
  }
}

export interface SyncSchedulerOptions {
  readonly connection: Redis;
  readonly engine: SyncEngine;
  readonly repository: IntelligenceRepository;
  readonly logger: Logger;
  readonly sources: ReadonlyMap<IntelligenceSource, { enabled: boolean; schedule: string }>;
  readonly attempts: number;
  readonly timeoutMs: number;
  readonly maintenanceCron: string;
  readonly staleAfterMs: number;
  readonly epssRetentionDays: number;
  readonly outboxRetentionDays: number;
  /** BullMQ backoff base between attempts of a failed run (default 60 s). */
  readonly retryBackoffMs?: number;
  /** Queue names (tests isolate themselves with unique names). */
  readonly queues?: { readonly sync: string; readonly maintenance: string };
}

/**
 * BullMQ wiring: one recurring job per enabled source (job schedulers are idempotent upserts),
 * a worker per queue, and the maintenance schedule. Disabled sources lose their schedule.
 */
export class SyncScheduler {
  readonly definition: JobDefinition<z.output<typeof sourceSyncPayloadSchema>>;
  readonly queue: JobQueue<z.output<typeof sourceSyncPayloadSchema>>;
  readonly jobQueue: BullSyncJobQueue;
  private readonly maintenanceDefinition: JobDefinition<MaintenancePayload>;
  private readonly maintenanceQueue: JobQueue<MaintenancePayload>;
  private readonly workers: { close(): Promise<void> }[] = [];

  constructor(private readonly options: SyncSchedulerOptions) {
    this.definition = sourceSyncJob({
      attempts: options.attempts,
      timeoutMs: options.timeoutMs,
      ...(options.retryBackoffMs === undefined ? {} : { backoffDelayMs: options.retryBackoffMs }),
      ...(options.queues === undefined ? {} : { queue: options.queues.sync }),
    });
    this.maintenanceDefinition = maintenanceJob(options.queues?.maintenance);
    const queueOptions = {
      connection: options.connection,
      service: SERVICE_NAME,
      logger: options.logger,
    } as const;
    this.queue = new JobQueue(this.definition, queueOptions);
    this.jobQueue = new BullSyncJobQueue(this.queue);
    this.maintenanceQueue = new JobQueue(this.maintenanceDefinition, queueOptions);
  }

  async start(): Promise<void> {
    const { options } = this;
    const sourceWorker = new JobWorker(this.definition, sourceSyncHandler(options.engine), {
      connection: options.connection,
      service: SERVICE_NAME,
      logger: options.logger,
      // Different sources run in parallel; the lease serialises runs of the same source.
      concurrency: Math.max(1, [...options.sources.values()].filter((s) => s.enabled).length),
    });
    const maintenanceWorker = new JobWorker(
      this.maintenanceDefinition,
      async () => {
        await runMaintenance({
          repository: options.repository,
          engine: options.engine,
          enqueue: (payload, jobId) => this.jobQueue.enqueue(payload, jobId),
          staleAfterMs: options.staleAfterMs,
          epssRetentionDays: options.epssRetentionDays,
          outboxRetentionDays: options.outboxRetentionDays,
          logger: options.logger,
        });
      },
      { connection: options.connection, service: SERVICE_NAME, logger: options.logger },
    );
    this.workers.push(sourceWorker, maintenanceWorker);
    await sourceWorker.start();
    await maintenanceWorker.start();

    for (const [source, entry] of options.sources) {
      const schedulerId = `scheduled.${source}`;
      if (entry.enabled) {
        await this.queue.schedule(
          schedulerId,
          { cron: entry.schedule, timezone: 'UTC' },
          {
            source,
            trigger: 'scheduled',
            requestedBy: null,
            fresh: false,
          },
        );
      } else if (await this.queue.removeSchedule(schedulerId)) {
        options.logger.info({ source }, 'schedule of the disabled source removed');
      }
    }
    await this.maintenanceQueue.schedule(
      'maintenance',
      { cron: options.maintenanceCron, timezone: 'UTC' },
      {},
    );
  }

  async stop(): Promise<void> {
    for (const worker of this.workers) await worker.close();
    await this.queue.close();
    await this.maintenanceQueue.close();
  }
}
