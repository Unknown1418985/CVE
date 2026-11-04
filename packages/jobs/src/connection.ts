import type { Logger } from '@cve/logger';
import { Redis } from 'ioredis';

export interface RedisConnectionOptions {
  /** `redis://<user>:<password>@redis:6379` */
  readonly url: string;
  /** Shown in `CLIENT LIST`, e.g. `cve-service:jobs`. */
  readonly connectionName: string;
  readonly logger: Logger;
  /**
   * BullMQ workers use blocking commands and require `maxRetriesPerRequest: null`.
   * Producers fail fast instead so callers see Redis outages.
   */
  readonly role: 'worker' | 'producer' | 'client';
}

/** Removes credentials from a Redis URL before it is logged. */
export function redactRedisUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.password !== '') parsed.password = '****';
    return parsed.toString();
  } catch {
    return '[invalid url]';
  }
}

/** Exponential reconnect delay with a 20 s cap. */
export function redisRetryDelayMs(times: number): number {
  return Math.min(20_000, 200 * 2 ** Math.min(times, 10));
}

export function createRedisConnection(options: RedisConnectionOptions): Redis {
  const redis = new Redis(options.url, {
    connectionName: options.connectionName,
    maxRetriesPerRequest: options.role === 'worker' ? null : 3,
    enableOfflineQueue: options.role !== 'producer',
    connectTimeout: 10_000,
    retryStrategy: redisRetryDelayMs,
  });
  const target = redactRedisUrl(options.url);
  redis.on('ready', () => {
    options.logger.info({ redis: target, connection: options.connectionName }, 'redis connected');
  });
  redis.on('error', (error: Error) => {
    options.logger.error(
      { err: error, connection: options.connectionName },
      'redis connection error',
    );
  });
  redis.on('reconnecting', (delayMs: number) => {
    options.logger.warn({ delayMs, connection: options.connectionName }, 'redis reconnecting');
  });
  return redis;
}
