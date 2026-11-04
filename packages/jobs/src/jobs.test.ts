import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { redactRedisUrl, redisRetryDelayMs } from './connection.js';
import { createRedisHealthIndicator } from './health.js';
import { DEFAULT_RETRY_POLICY, defineJob } from './job-definition.js';
import { bullPrefix, redisKeyPrefix } from './keys.js';
import { assertJobId, defaultJobOptions } from './queue.js';

const payloadSchema = z.object({ cveId: z.string() });

describe('key prefixes', () => {
  it('scopes keys to the service', () => {
    expect(redisKeyPrefix('download-service')).toBe('cve:download-service:');
    expect(bullPrefix('download-service')).toBe('cve:download-service:bull');
    expect(() => redisKeyPrefix('evil' as 'cve-service')).toThrow(/Unknown service/);
  });
});

describe('defineJob', () => {
  it('applies defaults', () => {
    const job = defineJob({ queue: 'nvd-sync', name: 'sync-window', payloadSchema });
    expect(job.retry).toEqual(DEFAULT_RETRY_POLICY);
    expect(defaultJobOptions(job as never)).toMatchObject({
      attempts: 5,
      backoff: { type: 'exponential', delay: 2_000 },
      removeOnComplete: { age: 86_400, count: 1_000 },
    });
  });

  it('validates names and policies', () => {
    expect(() => defineJob({ queue: 'NVD', name: 'x', payloadSchema })).toThrow(/queue name/);
    expect(() => defineJob({ queue: 'a:b', name: 'x', payloadSchema })).toThrow(/queue name/);
    expect(() =>
      defineJob({ queue: 'ok', name: 'x', payloadSchema, retry: { attempts: 0 } }),
    ).toThrow(/attempts/);
    expect(() => defineJob({ queue: 'ok', name: 'x', payloadSchema, timeoutMs: 0 })).toThrow(
      /timeoutMs/,
    );
  });
});

describe('assertJobId', () => {
  it('accepts idempotency keys and rejects unsafe ones', () => {
    expect(() => {
      assertJobId('nvd-sync.2026-11-04');
    }).not.toThrow();
    expect(() => {
      assertJobId('CVE-2026-1234');
    }).not.toThrow();
    for (const bad of ['', '123', 'a:b', '../x', 'x'.repeat(200)]) {
      expect(() => {
        assertJobId(bad);
      }).toThrow();
    }
  });
});

describe('connection helpers', () => {
  it('redacts credentials', () => {
    expect(redactRedisUrl('redis://svc:s3cret@redis:6379')).not.toContain('s3cret');
  });

  it('backs off exponentially with a cap', () => {
    expect(redisRetryDelayMs(1)).toBe(400);
    expect(redisRetryDelayMs(50)).toBe(20_000);
  });
});

describe('createRedisHealthIndicator', () => {
  it('reports ok on PONG', async () => {
    const indicator = createRedisHealthIndicator({ ping: () => Promise.resolve('PONG') });
    await expect(indicator.check(100)).resolves.toMatchObject({ name: 'redis', status: 'ok' });
  });

  it('reports down on errors and timeouts without throwing', async () => {
    const failing = createRedisHealthIndicator({
      ping: () => Promise.reject<string>(new Error('NOAUTH')),
    });
    await expect(failing.check(100)).resolves.toMatchObject({ status: 'down', message: 'NOAUTH' });
    const hanging = createRedisHealthIndicator({
      ping: () => new Promise<'PONG'>(() => undefined),
    });
    await expect(hanging.check(20)).resolves.toMatchObject({ status: 'down' });
  });
});
