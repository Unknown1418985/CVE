import type { ServiceName } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { Queue, type JobsOptions } from 'bullmq';
import type { Redis } from 'ioredis';

import type { JobDefinition } from './job-definition.js';
import { bullPrefix } from './keys.js';

export interface JobQueueOptions {
  readonly connection: Redis;
  readonly service: ServiceName;
  readonly logger: Logger;
}

export interface EnqueueOptions {
  /**
   * Idempotency key. Adding a job whose ID already exists is a no-op, which makes
   * enqueueing safe to repeat (for example `nvd-sync:2026-11-04`).
   */
  readonly jobId?: string;
  readonly delayMs?: number;
  /** 1 (highest) … 2 097 152 (lowest). */
  readonly priority?: number;
}

export type ScheduleOptions =
  | { readonly everyMs: number; readonly cron?: never; readonly timezone?: never }
  | { readonly cron: string; readonly timezone?: string; readonly everyMs?: never };

export interface EnqueuedJob {
  readonly id: string;
  readonly queue: string;
  readonly name: string;
}

const JOB_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function assertJobId(jobId: string): void {
  // BullMQ uses ':' as a key separator and treats numeric IDs as auto-generated.
  if (!JOB_ID_PATTERN.test(jobId) || /^\d+$/.test(jobId)) {
    throw new Error(`Invalid job ID "${jobId}": use 1-128 of [A-Za-z0-9._-], not purely numeric`);
  }
}

/** Default BullMQ options derived from a job definition. */
export function defaultJobOptions(definition: JobDefinition<unknown>): JobsOptions {
  return {
    attempts: definition.retry.attempts,
    backoff: { type: 'exponential', delay: definition.retry.backoffDelayMs },
    removeOnComplete: {
      age: definition.retention.completedAgeSeconds,
      count: definition.retention.completedCount,
    },
    removeOnFail: {
      age: definition.retention.failedAgeSeconds,
      count: definition.retention.failedCount,
    },
  };
}

/** Typed producer for one job definition. Payloads are validated before they reach Redis. */
export class JobQueue<TPayload> {
  readonly queue: Queue;

  constructor(
    private readonly definition: JobDefinition<TPayload>,
    private readonly options: JobQueueOptions,
  ) {
    this.queue = new Queue(definition.queue, {
      connection: options.connection,
      prefix: bullPrefix(options.service),
      defaultJobOptions: defaultJobOptions(definition),
    });
    this.queue.on('error', (error: Error) => {
      options.logger.error({ err: error, queue: definition.queue }, 'job queue error');
    });
  }

  private validate(payload: TPayload): TPayload {
    return this.definition.payloadSchema.parse(payload);
  }

  async add(payload: TPayload, options: EnqueueOptions = {}): Promise<EnqueuedJob> {
    const data = this.validate(payload);
    if (options.jobId !== undefined) assertJobId(options.jobId);
    const job = await this.queue.add(this.definition.name, data, {
      ...(options.jobId === undefined ? {} : { jobId: options.jobId }),
      ...(options.delayMs === undefined ? {} : { delay: options.delayMs }),
      ...(options.priority === undefined ? {} : { priority: options.priority }),
    });
    if (job.id === undefined) throw new Error('BullMQ did not assign a job ID');
    this.options.logger.debug(
      { queue: this.definition.queue, job: this.definition.name, jobId: job.id },
      'job enqueued',
    );
    return { id: job.id, queue: this.definition.queue, name: this.definition.name };
  }

  /**
   * Creates or updates a recurring job (idempotent by `schedulerId`), e.g. an hourly
   * synchronisation. Only one scheduler with a given ID exists per queue.
   */
  async schedule(schedulerId: string, schedule: ScheduleOptions, payload: TPayload): Promise<void> {
    assertJobId(schedulerId);
    const data = this.validate(payload);
    const repeat =
      schedule.cron === undefined
        ? { every: schedule.everyMs }
        : {
            pattern: schedule.cron,
            ...(schedule.timezone === undefined ? {} : { tz: schedule.timezone }),
          };
    if (repeat.every !== undefined && (!Number.isInteger(repeat.every) || repeat.every < 1_000)) {
      throw new Error('everyMs must be an integer of at least 1000');
    }
    await this.queue.upsertJobScheduler(schedulerId, repeat, {
      name: this.definition.name,
      data,
    });
    this.options.logger.info(
      { queue: this.definition.queue, schedulerId, schedule },
      'job schedule upserted',
    );
  }

  async removeSchedule(schedulerId: string): Promise<boolean> {
    return this.queue.removeJobScheduler(schedulerId);
  }

  async counts(): Promise<Record<string, number>> {
    return this.queue.getJobCounts(
      'waiting',
      'active',
      'delayed',
      'completed',
      'failed',
      'prioritized',
    );
  }

  async close(): Promise<void> {
    await this.queue.close();
  }
}
