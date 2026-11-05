import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { createRedisConnection } from '@cve/jobs';

import { DiscoveryScheduler } from '../../src/discovery/discovery-jobs.js';
import { createPrismaClient, type PrismaClient } from '../../src/persistence/prisma.js';
import { MockSource } from '../mock-source.js';
import { sha, silentLogger } from '../support.js';
import {
  createEngine,
  FakeGithub,
  integrationEnv,
  migrate,
  pocDatabaseUrl,
  pocRedisUrl,
  resetDatabase,
  syntheticCveId,
} from './support.js';

// BullMQ end to end: a CVE discovery job queues an inspection job, both run on real workers.

const suffix = randomUUID().slice(0, 8);
const CVE = syntheticCveId(401);

let prisma: PrismaClient;
let mock: MockSource;
let scheduler: DiscoveryScheduler;
let searchFailures = 0;
const redis = createRedisConnection({
  url: pocRedisUrl(),
  connectionName: `poc-service:itest-${suffix}`,
  logger: silentLogger,
  role: 'worker',
});

beforeAll(async () => {
  const url = pocDatabaseUrl();
  migrate(url);
  prisma = createPrismaClient(url);
  await resetDatabase(prisma);
  mock = await new MockSource().start();
  const github = new FakeGithub(mock);
  github.add({
    id: 401,
    name: `${CVE}-poc`,
    commit: { sha: sha('c401'), treeSha: sha('t401'), files: [{ path: 'poc.go', sha: sha('g') }] },
  });
  // The first search fails: the job attempt fails and BullMQ retries it.
  const search = '/search/repositories';
  const env = integrationEnv(mock.origin);
  mock.route(search, (request) => {
    if (searchFailures < 1) {
      searchFailures += 1;
      return { status: 503 };
    }
    return {
      body: {
        total_count: 1,
        incomplete_results: false,
        items:
          request.query.get('q')?.includes(CVE) === true
            ? [github.payload({ id: 401, name: `${CVE}-poc` })]
            : [],
      },
    };
  });
  const holder: { scheduler?: DiscoveryScheduler } = {};
  const engine = createEngine(prisma, env, {
    enqueueDiscovery: (payload, jobId) => {
      if (holder.scheduler === undefined) throw new Error('scheduler not started');
      return holder.scheduler.jobQueue.enqueueDiscovery(payload, jobId);
    },
    enqueueInspection: (input) => {
      if (holder.scheduler === undefined) throw new Error('scheduler not started');
      return holder.scheduler.jobQueue.enqueueInspection(input);
    },
  });
  scheduler = new DiscoveryScheduler({
    connection: redis,
    prisma,
    engine,
    logger: silentLogger,
    githubEnabled: true,
    attempts: 3,
    timeoutMs: 60_000,
    inspectionConcurrency: 2,
    sweepCron: '0 0 1 1 *',
    sweepBatchSize: 10,
    recentCron: '0 0 1 1 *',
    maintenanceCron: '0 0 1 1 *',
    retention: { processedEventDays: 7, outboxDays: 7, runDays: 90 },
    retryBackoffMs: 100,
    queues: {
      discovery: `itest-${suffix}-discovery`,
      inspection: `itest-${suffix}-inspection`,
      scheduling: `itest-${suffix}-scheduling`,
      maintenance: `itest-${suffix}-maintenance`,
    },
  });
  holder.scheduler = scheduler;
  await scheduler.start();
});

afterAll(async () => {
  await scheduler.stop();
  await redis.quit();
  await resetDatabase(prisma);
  await prisma.$disconnect();
  await mock.stop();
});

describe('DiscoveryScheduler', () => {
  it('runs a CVE discovery (with a retry) and the inspection it queues', async () => {
    const first = await scheduler.jobQueue.enqueueDiscovery(
      { connector: 'github', mode: 'cve', trigger: 'manual', cveId: CVE, requestedBy: 'itest' },
      `manual.itest.${suffix}`,
    );
    expect(first.queued).toBe(true);
    // Same job ID: not queued twice.
    await expect(
      scheduler.jobQueue.enqueueDiscovery(
        { connector: 'github', mode: 'cve', trigger: 'manual', cveId: CVE, requestedBy: 'itest' },
        `manual.itest.${suffix}`,
      ),
    ).resolves.toEqual({ jobId: first.jobId, queued: false });

    await vi.waitFor(
      async () => {
        expect(await prisma.pocArtifact.count()).toBe(1);
      },
      { timeout: 30_000, interval: 200 },
    );
    const runs = await prisma.discoveryRun.findMany({ orderBy: { startedAt: 'asc' } });
    expect(runs.map((run) => [run.mode, run.status, run.attempt])).toEqual([
      ['cve', 'failed', 1],
      ['cve', 'succeeded', 2],
      ['repository', 'succeeded', 1],
    ]);
    expect(searchFailures).toBe(1);
    const association = await prisma.pocAssociation.findFirstOrThrow({ where: { cveId: CVE } });
    expect(association.confidenceLevel).not.toBe('low');
  });
});
