import type { ServiceName } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { UnrecoverableError, Worker, type Job } from 'bullmq';
import type { Redis } from 'ioredis';

import type { JobDefinition } from './job-definition.js';
import { bullPrefix } from './keys.js';

export interface JobContext {
  readonly jobId: string;
  /** 1 for the first attempt. */
  readonly attempt: number;
  readonly maxAttempts: number;
  /** Aborted when the job exceeds its timeout or the worker shuts down. */
  readonly signal: AbortSignal;
  readonly logger: Logger;
  updateProgress(progress: number): Promise<void>;
}

export type JobHandler<TPayload> = (payload: TPayload, context: JobContext) => Promise<void>;

export interface JobWorkerOptions {
  readonly connection: Redis;
  readonly service: ServiceName;
  readonly logger: Logger;
  /** Jobs processed in parallel by this worker. Default 1. */
  readonly concurrency?: number;
  /** Optional global rate limit for this queue, e.g. to respect an upstream API quota. */
  readonly rateLimit?: { readonly max: number; readonly durationMs: number };
}

/** Thrown from a handler to fail a job permanently without further retries. */
export class PermanentJobError extends UnrecoverableError {
  constructor(message: string) {
    super(message);
    this.name = 'PermanentJobError';
  }
}

export class JobTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Job exceeded its timeout of ${timeoutMs}ms`);
    this.name = 'JobTimeoutError';
  }
}

async function runWithTimeout(
  run: (signal: AbortSignal) => Promise<void>,
  timeoutMs: number | undefined,
  parent: AbortSignal,
): Promise<void> {
  const controller = new AbortController();
  const onParentAbort = () => {
    controller.abort(parent.reason);
  };
  parent.addEventListener('abort', onParentAbort, { once: true });
  let timer: NodeJS.Timeout | undefined;
  try {
    const work = run(controller.signal);
    if (timeoutMs === undefined) {
      await work;
      return;
    }
    await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          const error = new JobTimeoutError(timeoutMs);
          controller.abort(error);
          reject(error);
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    parent.removeEventListener('abort', onParentAbort);
  }
}

/**
 * Processes one job definition. Payloads are re-validated (Redis content is not trusted);
 * invalid payloads fail permanently. Retries follow the definition's exponential backoff.
 */
export class JobWorker<TPayload> {
  readonly worker: Worker;
  private readonly shutdown = new AbortController();

  constructor(
    private readonly definition: JobDefinition<TPayload>,
    handler: JobHandler<TPayload>,
    private readonly options: JobWorkerOptions,
  ) {
    const baseLogger = options.logger.child({ queue: definition.queue, job: definition.name });
    this.worker = new Worker(
      definition.queue,
      async (job: Job) => {
        const jobId = job.id ?? 'unknown';
        const attempt = job.attemptsMade + 1;
        const logger = baseLogger.child({ jobId, attempt });
        if (job.name !== definition.name) {
          throw new PermanentJobError(
            `Unexpected job name "${job.name}" on queue "${definition.queue}"`,
          );
        }
        const parsed = definition.payloadSchema.safeParse(job.data);
        if (!parsed.success) {
          throw new PermanentJobError(`Invalid job payload: ${parsed.error.message}`);
        }
        const started = performance.now();
        await runWithTimeout(
          (signal) =>
            handler(parsed.data, {
              jobId,
              attempt,
              maxAttempts: job.opts.attempts ?? 1,
              signal,
              logger,
              updateProgress: (progress) => job.updateProgress(progress),
            }),
          definition.timeoutMs,
          this.shutdown.signal,
        );
        logger.info({ durationMs: Math.round(performance.now() - started) }, 'job completed');
      },
      {
        connection: options.connection,
        prefix: bullPrefix(options.service),
        concurrency: options.concurrency ?? 1,
        autorun: false,
        ...(options.rateLimit === undefined
          ? {}
          : { limiter: { max: options.rateLimit.max, duration: options.rateLimit.durationMs } }),
      },
    );

    this.worker.on('failed', (job: Job | undefined, error: Error) => {
      const attempts = job?.opts.attempts ?? 1;
      const final =
        error instanceof UnrecoverableError || job === undefined || job.attemptsMade >= attempts;
      const fields = {
        err: error,
        jobId: job?.id,
        attemptsMade: job?.attemptsMade,
        maxAttempts: attempts,
      };
      if (final) baseLogger.error(fields, 'job failed permanently');
      else baseLogger.warn(fields, 'job attempt failed, will retry');
    });
    this.worker.on('stalled', (jobId: string) => {
      baseLogger.warn({ jobId }, 'job stalled and will be reprocessed');
    });
    this.worker.on('error', (error: Error) => {
      baseLogger.error({ err: error }, 'job worker error');
    });
  }

  /** Starts processing; resolves once the worker is connected and running. */
  async start(): Promise<void> {
    void this.worker.run().catch((error: unknown) => {
      this.options.logger.error(
        { err: error, queue: this.definition.queue },
        'job worker stopped unexpectedly',
      );
    });
    await this.worker.waitUntilReady();
  }

  /** Signals running handlers to abort, waits for them, then disconnects. */
  async close(): Promise<void> {
    this.shutdown.abort(new Error('worker shutting down'));
    await this.worker.close();
  }
}
