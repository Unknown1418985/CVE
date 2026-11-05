import { z } from 'zod';

import {
  defineJob,
  JobQueue,
  JobWorker,
  PermanentJobError,
  type createRedisConnection,
  type JobDefinition,
} from '@cve/jobs';
import type { Logger } from '@cve/logger';

import { OBJECT_STORAGE_BUCKETS } from '@cve/contracts';

import type { PrismaClient } from '../generated/prisma/client.js';
import type { ScanEngine } from '../scanning/scan-engine.js';
import type { ArtifactObjectStore } from '../storage/object-store.js';
import { SERVICE_NAME } from '../service.js';
import type { DownloadEngine, ScanQueue } from './download-engine.js';

type Redis = ReturnType<typeof createRedisConnection>;

const downloadPayload = z.object({ requestId: z.uuid() });
const scanPayload = z.object({ artifactId: z.uuid(), reason: z.string().max(200) });
const emptyPayload = z.object({});
type DownloadPayload = z.output<typeof downloadPayload>;
type ScanPayload = z.output<typeof scanPayload>;
type EmptyPayload = z.output<typeof emptyPayload>;

export interface QueueNames {
  readonly download: string;
  readonly scan: string;
  readonly scheduling: string;
  readonly maintenance: string;
}

export const DEFAULT_QUEUES: QueueNames = {
  download: 'artifact-download',
  scan: 'artifact-scan',
  scheduling: 'download-scheduling',
  maintenance: 'download-maintenance',
};

/** Producer used by the API, the event consumer and the scheduler. */
export interface DownloadJobQueue extends ScanQueue {
  /** Queues a due request now (no-op when it is not due, not pending or already queued). */
  queueRequest(requestId: string): Promise<boolean>;
}

/** `1` (highest) … `10` (lowest) maps onto BullMQ priorities. */
const bullPriority = (priority: number) => Math.min(10, Math.max(1, priority));

/**
 * Hands due pending requests to BullMQ. The row is marked queued in the same statement that
 * selects it, so replicas never queue the same request twice; the job ID is recorded so that
 * maintenance can tell a lost job from a waiting one.
 */
export async function queueDueRequests(options: {
  readonly prisma: PrismaClient;
  readonly queue: JobQueue<DownloadPayload>;
  readonly batchSize: number;
  readonly requestId?: string;
  readonly logger: Logger;
}): Promise<number> {
  const now = new Date();
  const jobSuffix = String(now.getTime());
  const picked =
    options.requestId === undefined
      ? await options.prisma.$queryRaw<{ id: string; priority: number }[]>`
        UPDATE "download_requests" AS r
           SET "queued_at" = ${now}, "job_id" = 'download.' || r."id" || '.' || ${jobSuffix}
         WHERE r."id" IN (
               SELECT "id" FROM "download_requests"
                WHERE "status" = 'pending' AND "queued_at" IS NULL AND "scheduled_for" <= ${now}
                ORDER BY "priority", "scheduled_for"
                LIMIT ${options.batchSize}
                  FOR UPDATE SKIP LOCKED)
     RETURNING r."id", r."priority"`
      : await options.prisma.$queryRaw<{ id: string; priority: number }[]>`
        UPDATE "download_requests" AS r
           SET "queued_at" = ${now}, "job_id" = 'download.' || r."id" || '.' || ${jobSuffix}
         WHERE r."id" = ${options.requestId}::uuid AND r."status" = 'pending'
           AND r."queued_at" IS NULL AND r."scheduled_for" <= ${now}
     RETURNING r."id", r."priority"`;
  let queued = 0;
  for (const row of picked) {
    try {
      await options.queue.add(
        { requestId: row.id },
        { jobId: `download.${row.id}.${jobSuffix}`, priority: bullPriority(row.priority) },
      );
      queued += 1;
    } catch (error) {
      // Leave it for the next sweep.
      await options.prisma.downloadRequest.updateMany({
        where: { id: row.id, status: 'pending' },
        data: { queuedAt: null, jobId: null },
      });
      options.logger.warn({ err: error, requestId: row.id }, 'failed to queue a download');
    }
  }
  if (picked.length > 0) options.logger.info({ queued }, 'queued due downloads');
  return queued;
}

export interface MaintenanceOptions {
  readonly prisma: PrismaClient;
  readonly store: ArtifactObjectStore;
  readonly downloads: JobQueue<DownloadPayload>;
  readonly scans: ScanQueue;
  readonly logger: Logger;
  readonly processedEventRetentionDays: number;
  readonly outboxRetentionDays: number;
  readonly now?: Date;
}

const DAY_MS = 86_400_000;
const RECOVERY_BATCH = 200;

/**
 * Recovery and retention (the database is the source of truth; Redis may lose jobs):
 * - requests whose worker died (expired lease) go back to pending;
 * - pending requests whose BullMQ job no longer exists are queued again;
 * - artifacts that were never scanned, or whose scan stalled, are queued for scanning;
 * - released copies of artifacts that are no longer released are deleted;
 * - old inbox and published outbox rows are purged.
 */
export async function runMaintenance(options: MaintenanceOptions) {
  const now = options.now ?? new Date();
  const { prisma } = options;
  const expired = await prisma.downloadRequest.findMany({
    where: { status: 'downloading', leaseUntil: { lt: now } },
    select: { id: true },
    take: RECOVERY_BATCH,
  });
  for (const { id } of expired) {
    await prisma.$transaction([
      prisma.downloadAttempt.updateMany({
        where: { requestId: id, finishedAt: null },
        data: {
          outcome: 'failed',
          errorCode: 'internal-error',
          error: 'The worker stopped before the attempt finished',
          retryable: true,
          finishedAt: now,
        },
      }),
      prisma.downloadRequest.updateMany({
        where: { id, status: 'downloading', leaseUntil: { lt: now } },
        data: { status: 'pending', queuedAt: null, jobId: null, leaseUntil: null },
      }),
    ]);
  }

  let requeued = 0;
  const waiting = await prisma.downloadRequest.findMany({
    where: { status: 'pending', queuedAt: { lt: new Date(now.getTime() - 15 * 60_000) } },
    select: { id: true, jobId: true },
    take: RECOVERY_BATCH,
  });
  for (const request of waiting) {
    const job =
      request.jobId === null ? undefined : await options.downloads.queue.getJob(request.jobId);
    const state = job === undefined ? 'missing' : await job.getState();
    if (state === 'missing' || state === 'completed' || state === 'failed' || state === 'unknown') {
      await prisma.downloadRequest.updateMany({
        where: { id: request.id, status: 'pending', jobId: request.jobId },
        data: { queuedAt: null, jobId: null },
      });
      requeued += 1;
    }
  }

  let scans = 0;
  const unscanned = await prisma.storedArtifact.findMany({
    where: {
      OR: [
        { scanStatus: 'pending', scanQueuedAt: null },
        {
          scanStatus: { in: ['pending', 'scanning'] },
          scanQueuedAt: { lt: new Date(now.getTime() - 60 * 60_000) },
        },
      ],
    },
    select: { id: true },
    take: RECOVERY_BATCH,
  });
  for (const { id } of unscanned) {
    if (await options.scans.enqueueScan(id, 'recovery')) scans += 1;
  }

  let releasedCopies = 0;
  const stale = await prisma.storedArtifact.findMany({
    where: {
      lifecycleStatus: { not: 'released' },
      releasedKey: { not: null },
      updatedAt: { lt: new Date(now.getTime() - 10 * 60_000) },
    },
    select: { id: true, releasedKey: true },
    take: RECOVERY_BATCH,
  });
  for (const artifact of stale) {
    if (artifact.releasedKey === null) continue;
    try {
      await options.store.delete(OBJECT_STORAGE_BUCKETS.pocArtifacts, artifact.releasedKey);
      await prisma.storedArtifact.updateMany({
        where: {
          id: artifact.id,
          lifecycleStatus: { not: 'released' },
          releasedKey: artifact.releasedKey,
        },
        data: { releasedKey: null },
      });
      releasedCopies += 1;
    } catch (error) {
      options.logger.warn(
        { err: error, artifactId: artifact.id },
        'failed to delete a released copy',
      );
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
  };
  const result = { expiredLeases: expired.length, requeued, scans, releasedCopies, purged };
  options.logger.info(result, 'download maintenance finished');
  return result;
}

export interface DownloadSchedulerOptions {
  readonly connection: Redis;
  readonly prisma: PrismaClient;
  readonly store: ArtifactObjectStore;
  readonly downloads: DownloadEngine;
  readonly scanner: ScanEngine;
  readonly logger: Logger;
  readonly attempts: number;
  readonly backoffMs: number;
  readonly downloadTimeoutMs: number;
  readonly scanAttempts: number;
  readonly scanTimeoutMs: number;
  readonly concurrency: number;
  readonly ratePerMinute: number;
  readonly scanConcurrency: number;
  readonly schedulerCron: string;
  readonly schedulerBatchSize: number;
  readonly maintenanceCron: string;
  readonly retention: { readonly processedEventDays: number; readonly outboxDays: number };
  readonly queues?: QueueNames;
}

/**
 * BullMQ wiring of the Download Service:
 * - `artifact-download`: one request per job, exponential backoff, global rate limit;
 * - `artifact-scan`: ClamAV and YARA inspection of quarantined objects;
 * - `download-scheduling`: queues due requests (download scheduling) every minute;
 * - `download-maintenance`: recovery and retention.
 */
export class DownloadScheduler implements DownloadJobQueue {
  private readonly downloadDefinition: JobDefinition<DownloadPayload>;
  private readonly scanDefinition: JobDefinition<ScanPayload>;
  private readonly schedulingDefinition: JobDefinition<EmptyPayload>;
  private readonly maintenanceDefinition: JobDefinition<EmptyPayload>;
  readonly downloadQueue: JobQueue<DownloadPayload>;
  readonly scanQueue: JobQueue<ScanPayload>;
  private readonly schedulingQueue: JobQueue<EmptyPayload>;
  private readonly maintenanceQueue: JobQueue<EmptyPayload>;
  private readonly workers: JobWorker<unknown>[] = [];

  constructor(private readonly options: DownloadSchedulerOptions) {
    const queues = options.queues ?? DEFAULT_QUEUES;
    this.downloadDefinition = defineJob({
      queue: queues.download,
      name: 'download',
      payloadSchema: downloadPayload,
      retry: { attempts: options.attempts, backoffDelayMs: options.backoffMs },
      // The fetcher enforces its own deadline; this is the outer safety net.
      timeoutMs: options.downloadTimeoutMs + 5 * 60_000,
    });
    this.scanDefinition = defineJob({
      queue: queues.scan,
      name: 'scan',
      payloadSchema: scanPayload,
      retry: { attempts: options.scanAttempts, backoffDelayMs: options.backoffMs },
      timeoutMs: options.scanTimeoutMs,
    });
    this.schedulingDefinition = defineJob({
      queue: queues.scheduling,
      name: 'schedule',
      payloadSchema: emptyPayload,
      retry: { attempts: 2, backoffDelayMs: 5_000 },
      timeoutMs: 60_000,
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
    this.downloadQueue = new JobQueue(this.downloadDefinition, queueOptions);
    this.scanQueue = new JobQueue(this.scanDefinition, queueOptions);
    this.schedulingQueue = new JobQueue(this.schedulingDefinition, queueOptions);
    this.maintenanceQueue = new JobQueue(this.maintenanceDefinition, queueOptions);
  }

  async queueRequest(requestId: string): Promise<boolean> {
    const queued = await queueDueRequests({
      prisma: this.options.prisma,
      queue: this.downloadQueue,
      batchSize: 1,
      requestId,
      logger: this.options.logger,
    });
    return queued > 0;
  }

  async enqueueScan(artifactId: string, reason: string): Promise<boolean> {
    const now = new Date();
    // Marking the artifact first lets maintenance find scans Redis lost.
    const marked = await this.options.prisma.storedArtifact.updateMany({
      where: { id: artifactId },
      data: { scanQueuedAt: now },
    });
    if (marked.count === 0) return false;
    await this.scanQueue.add(
      { artifactId, reason },
      { jobId: `scan.${artifactId}.${String(now.getTime())}` },
    );
    return true;
  }

  async start(): Promise<void> {
    const { options } = this;
    const workerOptions = {
      connection: options.connection,
      service: SERVICE_NAME,
      logger: options.logger,
    } as const;
    const download = new JobWorker(
      this.downloadDefinition,
      async (payload, context) => {
        const outcome = await options.downloads.run(
          payload.requestId,
          { jobId: context.jobId, attempt: context.attempt, maxAttempts: context.maxAttempts },
          context.signal,
        );
        // Retryable failures throw so BullMQ applies the backoff; final outcomes are recorded.
        if (outcome.status === 'retry') throw outcome.error;
      },
      {
        ...workerOptions,
        concurrency: options.concurrency,
        rateLimit: { max: options.ratePerMinute, durationMs: 60_000 },
      },
    );
    const scan = new JobWorker(
      this.scanDefinition,
      async (payload, context) => {
        const outcome = await options.scanner.run(
          payload.artifactId,
          payload.reason,
          context.signal,
        );
        if (outcome.status === 'scanned' && outcome.scannerErrors) {
          if (context.attempt < context.maxAttempts) {
            throw new Error('a scanner failed; the scan will be retried');
          }
          throw new PermanentJobError('a scanner kept failing; the artifact stays incomplete');
        }
      },
      { ...workerOptions, concurrency: options.scanConcurrency },
    );
    const scheduling = new JobWorker(
      this.schedulingDefinition,
      async () => {
        await queueDueRequests({
          prisma: options.prisma,
          queue: this.downloadQueue,
          batchSize: options.schedulerBatchSize,
          logger: options.logger,
        });
      },
      workerOptions,
    );
    const maintenance = new JobWorker(
      this.maintenanceDefinition,
      async () => {
        await runMaintenance({
          prisma: options.prisma,
          store: options.store,
          downloads: this.downloadQueue,
          scans: this,
          logger: options.logger,
          processedEventRetentionDays: options.retention.processedEventDays,
          outboxRetentionDays: options.retention.outboxDays,
        });
      },
      workerOptions,
    );
    for (const worker of [download, scan, scheduling, maintenance] as JobWorker<unknown>[]) {
      this.workers.push(worker);
      await worker.start();
    }
    await this.schedulingQueue.schedule(
      'schedule',
      { cron: options.schedulerCron, timezone: 'UTC' },
      {},
    );
    await this.maintenanceQueue.schedule(
      'maintenance',
      { cron: options.maintenanceCron, timezone: 'UTC' },
      {},
    );
  }

  async stop(): Promise<void> {
    for (const worker of this.workers) await worker.close();
    for (const queue of [
      this.downloadQueue,
      this.scanQueue,
      this.schedulingQueue,
      this.maintenanceQueue,
    ]) {
      await queue.close();
    }
  }
}
