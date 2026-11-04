import type { DependencyCheck } from '@cve/contracts';

/** Structurally compatible with `HealthIndicator` from `@cve/shared`. */
export interface RedisHealthIndicator {
  readonly name: string;
  readonly critical: boolean;
  check(timeoutMs: number): Promise<DependencyCheck>;
}

/** Sends `PING` and reports latency; never throws. */
export function createRedisHealthIndicator(
  redis: { ping(): Promise<string> },
  options: { name?: string; critical?: boolean } = {},
): RedisHealthIndicator {
  const name = options.name ?? 'redis';
  return {
    name,
    critical: options.critical ?? true,
    check: async (timeoutMs) => {
      const started = performance.now();
      let timer: NodeJS.Timeout | undefined;
      try {
        const reply = await Promise.race([
          redis.ping(),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
              reject(new Error(`PING timed out after ${timeoutMs}ms`));
            }, timeoutMs);
          }),
        ]);
        const latencyMs = Math.round(performance.now() - started);
        return reply === 'PONG'
          ? { name, status: 'ok', latencyMs, message: 'PONG' }
          : { name, status: 'down', latencyMs, message: 'unexpected PING reply' };
      } catch (error) {
        return {
          name,
          status: 'down',
          latencyMs: Math.round(performance.now() - started),
          message: error instanceof Error ? error.message : 'redis check failed',
        };
      } finally {
        if (timer) clearTimeout(timer);
      }
    },
  };
}
