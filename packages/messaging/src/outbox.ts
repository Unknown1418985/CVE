import type { DomainEventEnvelope } from '@cve/contracts';
import type { Logger } from '@cve/logger';

import { errorMessage } from './errors.js';

/** An event written in the same database transaction as the state change that caused it. */
export interface OutboxRecord {
  readonly id: string;
  readonly event: DomainEventEnvelope;
  /** Publication attempts made so far. */
  readonly attempts: number;
}

/**
 * Persistence port implemented by each service on top of its own database (Prisma), so the
 * outbox table lives next to the data it describes (CLAUDE.md §4, transactional outbox).
 */
export interface OutboxStore {
  /**
   * Returns up to `limit` unpublished records whose next attempt is due, and locks them
   * against concurrent relays (e.g. `SELECT … FOR UPDATE SKIP LOCKED` with a lease).
   */
  claimDue(limit: number, now: Date): Promise<readonly OutboxRecord[]>;
  markPublished(id: string, publishedAt: Date): Promise<void>;
  markFailed(id: string, error: string, nextAttemptAt: Date): Promise<void>;
}

export interface OutboxPublisher {
  publish(event: DomainEventEnvelope): Promise<void>;
}

export interface OutboxRelayOptions {
  readonly store: OutboxStore;
  readonly publisher: OutboxPublisher;
  readonly logger: Logger;
  readonly batchSize?: number;
  readonly pollIntervalMs?: number;
  readonly baseRetryDelayMs?: number;
  readonly maxRetryDelayMs?: number;
  readonly now?: () => Date;
}

export interface OutboxRunResult {
  readonly published: number;
  readonly failed: number;
}

/** Exponential backoff for failed publications: base · 2^(attempts), capped. */
export function outboxRetryDelayMs(attempts: number, baseMs: number, maxMs: number): number {
  return Math.min(maxMs, baseMs * 2 ** Math.max(0, attempts));
}

/**
 * Polls the outbox and publishes due events in order. Records are only marked published after
 * the broker confirmed them, giving at-least-once delivery; consumers deduplicate by event ID.
 */
export class OutboxRelay {
  private timer: NodeJS.Timeout | undefined;
  private running: Promise<OutboxRunResult> | undefined;
  private stopped = true;

  constructor(private readonly options: OutboxRelayOptions) {}

  private now(): Date {
    return this.options.now?.() ?? new Date();
  }

  async runOnce(): Promise<OutboxRunResult> {
    const { store, publisher, logger } = this.options;
    const baseMs = this.options.baseRetryDelayMs ?? 1_000;
    const maxMs = this.options.maxRetryDelayMs ?? 5 * 60_000;
    const records = await store.claimDue(this.options.batchSize ?? 100, this.now());
    let published = 0;
    let failed = 0;
    for (const record of records) {
      try {
        await publisher.publish(record.event);
        await store.markPublished(record.id, this.now());
        published += 1;
      } catch (error) {
        failed += 1;
        const delay = outboxRetryDelayMs(record.attempts, baseMs, maxMs);
        logger.error(
          {
            err: error,
            outboxId: record.id,
            eventId: record.event.eventId,
            attempts: record.attempts + 1,
            retryInMs: delay,
          },
          'outbox publication failed',
        );
        await store.markFailed(
          record.id,
          errorMessage(error),
          new Date(this.now().getTime() + delay),
        );
      }
    }
    return { published, failed };
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.schedule(0);
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.running = this.runOnce();
      this.running
        .then((result) => {
          // Drain quickly while there is a backlog, otherwise wait for the poll interval.
          const full = result.published + result.failed >= (this.options.batchSize ?? 100);
          this.schedule(full ? 0 : (this.options.pollIntervalMs ?? 1_000));
        })
        .catch((error: unknown) => {
          this.options.logger.error({ err: error }, 'outbox relay iteration failed');
          this.schedule(this.options.pollIntervalMs ?? 1_000);
        });
    }, delayMs);
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.running?.catch(() => undefined);
  }
}
