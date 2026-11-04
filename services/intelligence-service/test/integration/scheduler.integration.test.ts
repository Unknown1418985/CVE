import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createRedisConnection } from '@cve/jobs';

import { createPrismaClient, type PrismaClient } from '../../src/persistence/prisma.js';
import { PrismaIntelligenceRepository } from '../../src/persistence/prisma-intelligence.repository.js';
import { enabledAdapters } from '../../src/sources/registry.js';
import { SyncEngine } from '../../src/sync/sync-engine.js';
import { SyncScheduler } from '../../src/sync/sync-jobs.js';
import { kevCatalog, kevEntry, nvdCve, nvdPage } from '../fixtures/index.js';
import { MockSource } from '../mock-source.js';
import { intelligenceTestEnv, silentLogger, testRegistry } from '../support.js';
import {
  intelligenceDatabaseUrl,
  intelligenceRedisUrl,
  migrate,
  resetDatabase,
  TEST_REQUESTER,
} from './support.js';

const NVD = '/rest/json/cves/2.0';
const KEV = '/feeds/known_exploited_vulnerabilities.json';
const suffix = randomUUID().slice(0, 8);

let prisma: PrismaClient;
let repository: PrismaIntelligenceRepository;
let mock: MockSource;
let scheduler: SyncScheduler;
const redis = createRedisConnection({
  url: intelligenceRedisUrl(),
  connectionName: `intelligence-service:itest-${suffix}`,
  logger: silentLogger,
  role: 'worker',
});

let nvdFailures = 0;

beforeAll(async () => {
  const url = intelligenceDatabaseUrl();
  migrate(url);
  prisma = createPrismaClient(url);
  repository = new PrismaIntelligenceRepository(prisma);
  await resetDatabase(prisma);
  mock = await new MockSource().start();
  mock.route(NVD, (request) => {
    const start = Number(request.query.get('startIndex'));
    // The second page fails once: the job attempt fails and BullMQ retries it.
    if (start === 1 && nvdFailures < 1) {
      nvdFailures += 1;
      return { status: 500 };
    }
    return { body: nvdPage([nvdCve(start + 1)], start, 2) };
  });
  mock.route(KEV, () => ({ body: kevCatalog('v1', [kevEntry(1), kevEntry(2)]) }));

  const env = intelligenceTestEnv(mock, {
    NVD_PAGE_SIZE: '1',
    SOURCE_HTTP_MAX_ATTEMPTS: '1',
    MITRE_CVE_ENABLED: 'false',
    EPSS_ENABLED: 'false',
    GITHUB_ADVISORY_ENABLED: 'false',
  });
  const registry = testRegistry(env);
  const engine = new SyncEngine({
    repository,
    adapters: enabledAdapters(registry),
    logger: silentLogger,
    instanceId: `itest-${suffix}`,
    storeRawPayloads: true,
  });
  scheduler = new SyncScheduler({
    connection: redis,
    engine,
    repository,
    logger: silentLogger,
    sources: registry,
    attempts: 3,
    timeoutMs: 60_000,
    maintenanceCron: '*/5 * * * *',
    staleAfterMs: 600_000,
    epssRetentionDays: 30,
    outboxRetentionDays: 7,
    retryBackoffMs: 100,
    queues: { sync: `itest-${suffix}-source-sync`, maintenance: `itest-${suffix}-maintenance` },
  });
  await scheduler.start();
});

afterAll(async () => {
  await scheduler.queue.queue.obliterate({ force: true });
  await scheduler.stop();
  await redis.quit();
  await resetDatabase(prisma);
  await prisma.$disconnect();
  await mock.stop();
});

beforeEach(() => {
  mock.requests.length = 0;
});

describe('BullMQ scheduling (live Redis and PostgreSQL)', () => {
  it('registers one UTC schedule per enabled source', async () => {
    const schedulers = await scheduler.queue.queue.getJobSchedulers();
    const byId = new Map(schedulers.map((s) => [s.key, s]));
    expect([...byId.keys()].sort()).toEqual(['scheduled.cisa-kev', 'scheduled.nvd']);
    expect(byId.get('scheduled.nvd')).toMatchObject({ pattern: '15 */2 * * *', tz: 'UTC' });
  });

  it('runs a queued job and de-duplicates by job ID', async () => {
    const first = await scheduler.jobQueue.enqueue(
      { source: 'cisa-kev', trigger: 'manual', requestedBy: TEST_REQUESTER },
      `manual.cisa-kev.${suffix}`,
    );
    const again = await scheduler.jobQueue.enqueue(
      { source: 'cisa-kev', trigger: 'manual', requestedBy: TEST_REQUESTER },
      `manual.cisa-kev.${suffix}`,
    );
    expect(first.queued).toBe(true);
    expect(again.queued).toBe(false);
    await vi.waitFor(
      async () => {
        expect((await repository.getSyncState('cisa-kev'))?.lastRunStatus).toBe('succeeded');
      },
      { timeout: 20_000, interval: 100 },
    );
    expect(await prisma.sourceRecord.count({ where: { source: 'cisa-kev' } })).toBe(2);
    expect(await prisma.syncRun.count({ where: { source: 'cisa-kev' } })).toBe(1);
  });

  it('retries a failed attempt, resuming from the checkpoint', async () => {
    await scheduler.jobQueue.enqueue({
      source: 'nvd',
      trigger: 'manual',
      requestedBy: TEST_REQUESTER,
    });
    await vi.waitFor(
      async () => {
        expect((await repository.getSyncState('nvd'))?.lastRunStatus).toBe('succeeded');
      },
      { timeout: 20_000, interval: 100 },
    );
    const runs = await prisma.syncRun.findMany({
      where: { source: 'nvd' },
      orderBy: { startedAt: 'asc' },
    });
    expect(runs.map((r) => [r.status, r.attempt])).toEqual([
      ['failed', 1],
      ['succeeded', 2],
    ]);
    expect(runs[1]?.resumedFromRunId).toBe(runs[0]?.id);
    expect(runs[0]?.jobId).toBe(runs[1]?.jobId);
    // The retry asked only for the page that had failed.
    expect(mock.requestsTo(NVD).map((r) => r.query.get('startIndex'))).toEqual(['0', '1', '1']);
    expect(await prisma.sourceRecord.count({ where: { source: 'nvd' } })).toBe(2);
  });
});
