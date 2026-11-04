import { randomUUID } from 'node:crypto';

import { createLogger } from '@cve/logger';
import { RedisProcessedEventStore } from '@cve/messaging';
import { integrationHost, serviceRedisUrl } from '@cve/testing/integration';
import { QueueEvents } from 'bullmq';
import { Redis } from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  JobQueue,
  JobWorker,
  PermanentJobError,
  bullPrefix,
  createRedisConnection,
  createRedisHealthIndicator,
  defineJob,
  redisKeyPrefix,
  type JobDefinition,
} from '../../src/index.js';

const logger = createLogger({ service: 'jobs-integration', level: 'silent' });
const run = randomUUID().slice(0, 8);
const payloadSchema = z.object({ cveId: z.string() });
type Payload = z.infer<typeof payloadSchema>;

describe('BullMQ jobs (live Redis, service ACL user)', () => {
  const connection = createRedisConnection({
    url: serviceRedisUrl('cve-service'),
    connectionName: `cve-service:itest-${run}`,
    logger,
    role: 'worker',
  });
  const closers: (() => Promise<void>)[] = [];

  function setup(
    name: string,
    handler: (payload: Payload, attempt: number) => Promise<void>,
    options: Partial<Parameters<typeof defineJob<Payload>>[0]> = {},
  ) {
    const definition: JobDefinition<Payload> = defineJob({
      queue: `itest-${run}-${name}`,
      name: 'process',
      payloadSchema,
      retry: { attempts: 3, backoffDelayMs: 50 },
      ...options,
    });
    const queue = new JobQueue(definition, { connection, service: 'cve-service', logger });
    const worker = new JobWorker(
      definition,
      (payload, context) => handler(payload, context.attempt),
      {
        connection,
        service: 'cve-service',
        logger,
        concurrency: 2,
      },
    );
    const events = new QueueEvents(definition.queue, {
      connection: connection.duplicate(),
      prefix: bullPrefix('cve-service'),
    });
    closers.push(async () => {
      await worker.close();
      await queue.queue.obliterate({ force: true });
      await queue.close();
      await events.close();
    });
    return { queue, worker, events };
  }

  beforeAll(async () => {
    await connection.ping();
  });

  afterAll(async () => {
    for (const close of closers) await close();
    connection.disconnect();
  });

  it('reports healthy via PING', async () => {
    await expect(createRedisHealthIndicator(connection).check(1_000)).resolves.toMatchObject({
      status: 'ok',
    });
  });

  it('processes validated jobs and stores keys only under the service prefix', async () => {
    const processed: string[] = [];
    const { queue, worker, events } = setup('basic', (payload) => {
      processed.push(payload.cveId);
      return Promise.resolve();
    });
    await worker.start();
    await events.waitUntilReady();
    const job = await queue.add({ cveId: 'CVE-2026-1000' });
    const bullJob = await queue.queue.getJob(job.id);
    await bullJob?.waitUntilFinished(events, 10_000);
    expect(processed).toEqual(['CVE-2026-1000']);
    const keys = await connection.scan(
      '0',
      'MATCH',
      `${bullPrefix('cve-service')}:itest-${run}-basic:*`,
      'COUNT',
      1000,
    );
    expect(keys[1].length).toBeGreaterThan(0);
    await expect(queue.add({ cveId: 42 } as unknown as Payload)).rejects.toThrow();
  });

  it('retries with backoff and then succeeds', async () => {
    const attempts: number[] = [];
    const { queue, worker, events } = setup('retry', (_payload, attempt) => {
      attempts.push(attempt);
      return attempt < 3 ? Promise.reject(new Error('transient')) : Promise.resolve();
    });
    await worker.start();
    await events.waitUntilReady();
    const job = await queue.add({ cveId: 'CVE-2026-1001' });
    await (await queue.queue.getJob(job.id))?.waitUntilFinished(events, 10_000);
    expect(attempts).toEqual([1, 2, 3]);
  });

  it('fails permanently on invalid stored payloads, permanent errors and timeouts', async () => {
    let calls = 0;
    const { queue, worker, events } = setup(
      'failures',
      async (payload) => {
        calls += 1;
        if (payload.cveId === 'permanent') throw new PermanentJobError('cannot succeed');
        if (payload.cveId === 'slow') await new Promise((resolve) => setTimeout(resolve, 2_000));
      },
      { timeoutMs: 200, retry: { attempts: 1, backoffDelayMs: 0 } },
    );
    await worker.start();
    await events.waitUntilReady();

    // A payload written by something other than JobQueue.add (Redis content is not trusted).
    const raw = await queue.queue.add('process', { cveId: 123 });
    await expect(
      (await queue.queue.getJob(raw.id ?? ''))?.waitUntilFinished(events, 10_000),
    ).rejects.toThrow(/Invalid job payload/);

    const permanent = await queue.add({ cveId: 'permanent' });
    await expect(
      (await queue.queue.getJob(permanent.id))?.waitUntilFinished(events, 10_000),
    ).rejects.toThrow(/cannot succeed/);

    const slow = await queue.add({ cveId: 'slow' });
    await expect(
      (await queue.queue.getJob(slow.id))?.waitUntilFinished(events, 10_000),
    ).rejects.toThrow(/timeout of 200ms/);

    expect(calls).toBe(2);
    expect((await queue.counts())['failed']).toBe(3);
  });

  it('deduplicates jobs by idempotency key and runs schedules', async () => {
    const processed: string[] = [];
    const { queue, worker } = setup('schedule', (payload) => {
      processed.push(payload.cveId);
      return Promise.resolve();
    });
    const first = await queue.add(
      { cveId: 'CVE-2026-1002' },
      { jobId: `sync.${run}`, delayMs: 60_000 },
    );
    const second = await queue.add(
      { cveId: 'CVE-2026-1002' },
      { jobId: `sync.${run}`, delayMs: 60_000 },
    );
    expect(second.id).toBe(first.id);
    expect((await queue.counts())['delayed']).toBe(1);

    await queue.schedule(`every-second.${run}`, { everyMs: 1_000 }, { cveId: 'CVE-2026-1003' });
    await worker.start();
    await expect
      .poll(() => processed.filter((id) => id === 'CVE-2026-1003').length, { timeout: 10_000 })
      .toBeGreaterThanOrEqual(2);
    expect(await queue.removeSchedule(`every-second.${run}`)).toBe(true);
  });

  it('stores processed event IDs for consumer idempotency', async () => {
    const store = new RedisProcessedEventStore({
      redis: connection,
      keyPrefix: redisKeyPrefix('cve-service'),
      ttlMs: 60_000,
    });
    const eventId = randomUUID();
    await expect(store.isProcessed(`itest-${run}`, eventId)).resolves.toBe(false);
    await store.markProcessed(`itest-${run}`, eventId);
    await expect(store.isProcessed(`itest-${run}`, eventId)).resolves.toBe(true);
    await connection.del(`${redisKeyPrefix('cve-service')}inbox:itest-${run}:${eventId}`);
  });
});

describe('Redis ACL isolation', () => {
  let poc: Redis;

  beforeAll(() => {
    poc = new Redis(serviceRedisUrl('poc-service'), { maxRetriesPerRequest: 1, lazyConnect: true });
  });

  afterAll(() => {
    poc.disconnect();
  });

  it('confines a service to its own key prefix and channels', async () => {
    await poc.connect();
    await expect(
      poc.set(`${redisKeyPrefix('poc-service')}itest-${run}`, '1', 'EX', 30),
    ).resolves.toBe('OK');
    await expect(poc.get(`${redisKeyPrefix('cve-service')}anything`)).rejects.toThrow(/NOPERM/);
    await expect(poc.set('unscoped-key', '1')).rejects.toThrow(/NOPERM/);
    await expect(poc.publish('cve:cve-service:events', 'x')).rejects.toThrow(/NOPERM/);
    // Lua scripts are checked against the same key permissions.
    await expect(
      poc.eval("return redis.call('GET', KEYS[1])", 1, 'cve:cve-service:x'),
    ).rejects.toThrow(/NOPERM|permissions/);
  });

  it('denies dangerous and administrative commands', async () => {
    for (const command of [
      ['FLUSHALL'],
      ['KEYS', '*'],
      ['CONFIG', 'GET', '*'],
      ['ACL', 'LIST'],
      ['DEBUG', 'SLEEP', '0'],
      ['SHUTDOWN'],
    ]) {
      // DEBUG is additionally disabled server-wide (enable-debug-command defaults to no).
      await expect(poc.call(command[0] ?? '', ...command.slice(1))).rejects.toThrow(
        /NOPERM|not allowed/,
      );
    }
  });

  async function connectionErrors(options: {
    username?: string;
    password?: string;
  }): Promise<string[]> {
    const errors: string[] = [];
    const client = new Redis({
      host: integrationHost(),
      port: 6379,
      lazyConnect: true,
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
      ...options,
    });
    client.on('error', (error: Error) => errors.push(error.message));
    await client.connect().catch((error: unknown) => errors.push(String(error)));
    await client.ping().catch((error: unknown) => errors.push(String(error)));
    client.disconnect();
    return errors;
  }

  it('rejects the default user and wrong passwords', async () => {
    expect((await connectionErrors({})).join(' ')).toMatch(/NOAUTH/);
    expect(
      (await connectionErrors({ username: 'default', password: 'anything-at-all-123' })).join(' '),
    ).toMatch(/WRONGPASS/);
    expect(
      (await connectionErrors({ username: 'poc-service', password: 'wrong-password-123' })).join(
        ' ',
      ),
    ).toMatch(/WRONGPASS/);
  });
});
