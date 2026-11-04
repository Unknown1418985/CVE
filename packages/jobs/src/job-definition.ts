import type { z } from 'zod';

import { assertQueueName } from './keys.js';

export interface JobRetryPolicy {
  /** Total attempts including the first. Default 5. */
  readonly attempts: number;
  /** Base delay for exponential backoff (delay · 2^(attempt-1)). Default 2 s. */
  readonly backoffDelayMs: number;
}

export interface JobRetention {
  /** Completed jobs are kept for this long (seconds) and at most `completedCount`. */
  readonly completedAgeSeconds: number;
  readonly completedCount: number;
  /** Failed jobs are kept longer so they can be inspected and retried. */
  readonly failedAgeSeconds: number;
  readonly failedCount: number;
}

export interface JobDefinition<TPayload> {
  /** Kebab-case queue name, unique within the service. */
  readonly queue: string;
  /** Job name within the queue, used in logs and metrics. */
  readonly name: string;
  readonly payloadSchema: z.ZodType<TPayload>;
  readonly retry: JobRetryPolicy;
  readonly retention: JobRetention;
  /** Maximum processing time before the job is failed. */
  readonly timeoutMs?: number;
}

export const DEFAULT_RETRY_POLICY: JobRetryPolicy = { attempts: 5, backoffDelayMs: 2_000 };

export const DEFAULT_RETENTION: JobRetention = {
  completedAgeSeconds: 24 * 60 * 60,
  completedCount: 1_000,
  failedAgeSeconds: 14 * 24 * 60 * 60,
  failedCount: 10_000,
};

export interface DefineJobInput<TPayload> {
  readonly queue: string;
  readonly name: string;
  readonly payloadSchema: z.ZodType<TPayload>;
  readonly retry?: Partial<JobRetryPolicy>;
  readonly retention?: Partial<JobRetention>;
  readonly timeoutMs?: number;
}

/** Declares a typed job. Definitions are shared by the producer and the worker. */
export function defineJob<TPayload>(input: DefineJobInput<TPayload>): JobDefinition<TPayload> {
  assertQueueName(input.queue);
  assertQueueName(input.name);
  const retry = { ...DEFAULT_RETRY_POLICY, ...input.retry };
  if (!Number.isInteger(retry.attempts) || retry.attempts < 1 || retry.attempts > 50) {
    throw new Error('retry.attempts must be an integer between 1 and 50');
  }
  if (!Number.isInteger(retry.backoffDelayMs) || retry.backoffDelayMs < 0) {
    throw new Error('retry.backoffDelayMs must be a non-negative integer');
  }
  if (
    input.timeoutMs !== undefined &&
    (!Number.isInteger(input.timeoutMs) || input.timeoutMs < 1)
  ) {
    throw new Error('timeoutMs must be a positive integer');
  }
  return {
    queue: input.queue,
    name: input.name,
    payloadSchema: input.payloadSchema,
    retry,
    retention: { ...DEFAULT_RETENTION, ...input.retention },
    ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }),
  };
}
