import { sleep } from './abortable.js';

export interface RateLimit {
  /** Requests allowed per window. */
  readonly maxRequests: number;
  readonly windowMs: number;
  /** Minimum spacing between two requests (NVD recommends a pause between requests). */
  readonly minIntervalMs?: number;
}

/**
 * Sliding-window limiter for the requests of one source. Runs of a source never overlap (the
 * source lease guarantees it across replicas), so an in-process limiter enforces the quota.
 * The upstream can also pause it (`pauseUntil`) when it reports an exhausted quota.
 */
export class SlidingWindowRateLimiter {
  private readonly sent: number[] = [];
  private pausedUntil = 0;
  private queue: Promise<void> = Promise.resolve();

  constructor(
    readonly limit: RateLimit,
    private readonly now: () => number = Date.now,
  ) {
    if (!Number.isInteger(limit.maxRequests) || limit.maxRequests < 1) {
      throw new Error('maxRequests must be a positive integer');
    }
    if (!Number.isInteger(limit.windowMs) || limit.windowMs < 1) {
      throw new Error('windowMs must be a positive integer');
    }
  }

  /** Waits until a request may be sent and records it. Callers are served in order. */
  acquire(signal?: AbortSignal): Promise<void> {
    const turn = this.queue.then(() => this.waitForSlot(signal));
    // A rejected (aborted) turn must not block later callers.
    this.queue = turn.catch(() => undefined);
    return turn;
  }

  /** Blocks every request until `until` (epoch ms), e.g. from a rate-limit reset header. */
  pauseUntil(until: number): void {
    this.pausedUntil = Math.max(this.pausedUntil, until);
  }

  /** Time the next request would have to wait now (for tests and diagnostics). */
  delayMs(): number {
    const now = this.now();
    this.prune(now);
    let delay = Math.max(0, this.pausedUntil - now);
    if (this.sent.length >= this.limit.maxRequests) {
      const oldest = this.sent[this.sent.length - this.limit.maxRequests] ?? now;
      delay = Math.max(delay, oldest + this.limit.windowMs - now);
    }
    const last = this.sent.at(-1);
    if (last !== undefined && this.limit.minIntervalMs !== undefined) {
      delay = Math.max(delay, last + this.limit.minIntervalMs - now);
    }
    return delay;
  }

  private prune(now: number): void {
    while (this.sent.length > 0 && (this.sent[0] ?? 0) <= now - this.limit.windowMs) {
      this.sent.shift();
    }
  }

  private async waitForSlot(signal?: AbortSignal): Promise<void> {
    for (;;) {
      const delay = this.delayMs();
      if (delay <= 0) break;
      await sleep(delay, signal);
    }
    this.sent.push(this.now());
  }
}
