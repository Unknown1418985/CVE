/**
 * Idempotency store for consumers. RabbitMQ delivers at least once, so a consumer records
 * the IDs of events it has fully processed and skips duplicates.
 */
export interface ProcessedEventStore {
  isProcessed(consumer: string, eventId: string): Promise<boolean>;
  markProcessed(consumer: string, eventId: string): Promise<void>;
}

/** Minimal subset of an ioredis client used by {@link RedisProcessedEventStore}. */
export interface RedisLike {
  exists(key: string): Promise<number>;
  set(key: string, value: string, mode: 'PX', ttlMs: number): Promise<unknown>;
}

export interface RedisProcessedEventStoreOptions {
  readonly redis: RedisLike;
  /**
   * Key prefix; must fall inside the service's Redis ACL key pattern,
   * e.g. `cve:cve-service:` (see `redisKeyPrefix`).
   */
  readonly keyPrefix: string;
  /** How long processed IDs are remembered. Default 7 days. */
  readonly ttlMs?: number;
}

/** Redis-backed store; entries expire so the keyspace stays bounded. */
export class RedisProcessedEventStore implements ProcessedEventStore {
  private readonly ttlMs: number;

  constructor(private readonly options: RedisProcessedEventStoreOptions) {
    this.ttlMs = options.ttlMs ?? 7 * 24 * 60 * 60 * 1000;
  }

  private key(consumer: string, eventId: string): string {
    return `${this.options.keyPrefix}inbox:${consumer}:${eventId}`;
  }

  async isProcessed(consumer: string, eventId: string): Promise<boolean> {
    return (await this.options.redis.exists(this.key(consumer, eventId))) === 1;
  }

  async markProcessed(consumer: string, eventId: string): Promise<void> {
    await this.options.redis.set(this.key(consumer, eventId), '1', 'PX', this.ttlMs);
  }
}
