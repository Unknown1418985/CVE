import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  EMPTY_SYNC_RUN_STATS,
  INTELLIGENCE_EVENT_TYPES,
  type IntelligenceSource,
} from '@cve/contracts';

import { PrismaOutboxStore } from '../../src/outbox/prisma-outbox.store.js';
import { MAX_STORED_ISSUES_PER_RUN } from '../../src/persistence/ports.js';
import { createPrismaClient, type PrismaClient } from '../../src/persistence/prisma.js';
import { PrismaIntelligenceRepository } from '../../src/persistence/prisma-intelligence.repository.js';
import {
  epssPage,
  kevCatalog,
  kevEntry,
  nvdCve,
  nvdPage,
  syntheticCveId,
} from '../fixtures/index.js';
import { MockSource } from '../mock-source.js';
import { expectSucceeded, intelligenceTestEnv, runSource, testEngine } from '../support.js';
import { intelligenceDatabaseUrl, migrate, resetDatabase, TEST_REQUESTER } from './support.js';

const NVD = '/rest/json/cves/2.0';
let prisma: PrismaClient;
let repository: PrismaIntelligenceRepository;
let mock: MockSource;

const run = (source: IntelligenceSource, overrides: Parameters<typeof runSource>[2] = {}) =>
  runSource(
    testEngine(
      repository,
      intelligenceTestEnv(mock, { NVD_PAGE_SIZE: '2', SOURCE_HTTP_MAX_ATTEMPTS: '1' }),
    ),
    source,
    {
      requestedBy: TEST_REQUESTER,
      ...overrides,
    },
  );

beforeAll(async () => {
  const url = intelligenceDatabaseUrl();
  migrate(url);
  prisma = createPrismaClient(url);
  repository = new PrismaIntelligenceRepository(prisma);
  mock = await new MockSource().start();
});
afterAll(async () => {
  await resetDatabase(prisma);
  await prisma.$disconnect();
  await mock.stop();
});
beforeEach(async () => {
  await resetDatabase(prisma);
  mock.requests.length = 0;
});

function serveNvd(cves: unknown[], failAt?: { startIndex: number; times: number }) {
  let failures = 0;
  mock.route(NVD, (request) => {
    const start = Number(request.query.get('startIndex'));
    if (start === failAt?.startIndex && failures < failAt.times) {
      failures += 1;
      return { status: 503 };
    }
    return { body: nvdPage(cves.slice(start, start + 2), start, cves.length) };
  });
}

describe('PostgreSQL persistence (live)', () => {
  it('stores records, revisions, provenance and outbox events atomically', async () => {
    serveNvd([1, 2, 3].map((n) => nvdCve(n)));
    const first = expectSucceeded(await run('nvd'));
    expect(first.stats).toMatchObject({ created: 3, events: 3 });
    expect(await prisma.sourceRecord.count({ where: { source: 'nvd' } })).toBe(3);
    expect(await prisma.sourceRecordRevision.count()).toBe(3);
    const record = await prisma.sourceRecord.findUniqueOrThrow({
      where: { source_externalId: { source: 'nvd', externalId: syntheticCveId(1) } },
    });
    expect(record).toMatchObject({ cveId: syntheticCveId(1), revision: 1, removedAt: null });
    expect(record.raw).toMatchObject({ id: syntheticCveId(1) });
    const types = (await prisma.outboxEvent.findMany()).map((row) => row.eventType).sort();
    expect(types).toEqual(
      [
        ...Array.from({ length: 3 }, () => INTELLIGENCE_EVENT_TYPES.cveObserved),
        INTELLIGENCE_EVENT_TYPES.syncCompleted,
      ].sort(),
    );
    expect((await repository.getSyncState('nvd'))?.cursor).toEqual(first.cursorAfter);

    // Second run: identical content is detected as duplicate; one changed record is revised.
    serveNvd([nvdCve(1), nvdCve(2), nvdCve(3, { lastModified: '2026-11-04T13:00:00.000' })]);
    const second = expectSucceeded(await run('nvd'));
    expect(second.stats).toMatchObject({ unchanged: 2, updated: 1, events: 1 });
    expect(await prisma.sourceRecordRevision.count()).toBe(4);
    const revised = await prisma.sourceRecord.findUniqueOrThrow({
      where: { source_externalId: { source: 'nvd', externalId: syntheticCveId(3) } },
      include: { revisions: true },
    });
    expect(revised.revision).toBe(2);
    expect(revised.revisions.map((r) => r.revision).sort()).toEqual([1, 2]);

    // The relay can claim and publish the rows.
    const store = new PrismaOutboxStore(prisma);
    const claimed = await store.claimDue(100, new Date());
    expect(claimed).toHaveLength(6);
    expect(await store.claimDue(100, new Date())).toHaveLength(0);
  });

  it('resumes a failed run from the stored checkpoint', async () => {
    serveNvd(
      [1, 2, 3, 4].map((n) => nvdCve(n)),
      { startIndex: 2, times: 1 },
    );
    const failed = await run('nvd');
    expect(failed.status).toBe('failed');
    const stored = await prisma.syncRun.findFirstOrThrow({ where: { status: 'failed' } });
    expect(stored.checkpoint).toMatchObject({ startIndex: 2 });
    expect(stored.error).toMatch(/HTTP 503/);
    expect((await repository.getSyncState('nvd'))?.consecutiveFailures).toBe(1);

    mock.requests.length = 0;
    const resumed = expectSucceeded(await run('nvd'));
    expect(resumed.resumedFromRunId).toBe(stored.id);
    expect(mock.requestsTo(NVD).map((r) => r.query.get('startIndex'))).toEqual(['2']);
    expect(await prisma.sourceRecord.count()).toBe(4);
    // A run can be resumed only once.
    await expect(
      repository.createRun({
        source: 'nvd',
        trigger: 'manual',
        jobId: null,
        attempt: 1,
        requestedBy: TEST_REQUESTER,
        resumedFromRunId: stored.id,
        startedAt: new Date(),
        cursorBefore: null,
        checkpoint: null,
      }),
    ).rejects.toThrow();
  });

  it('applies CISA KEV snapshots with tombstones', async () => {
    const feed = '/feeds/known_exploited_vulnerabilities.json';
    mock.route(feed, () => ({ body: kevCatalog('v1', [kevEntry(1), kevEntry(2)]) }));
    expectSucceeded(await run('cisa-kev'));
    mock.route(feed, () => ({ body: kevCatalog('v2', [kevEntry(1)]) }));
    const second = expectSucceeded(await run('cisa-kev'));
    expect(second.stats).toMatchObject({ removed: 1, unchanged: 1 });
    const removed = await prisma.sourceRecord.findUniqueOrThrow({
      where: { source_externalId: { source: 'cisa-kev', externalId: syntheticCveId(2) } },
      include: { revisions: { orderBy: { revision: 'asc' } } },
    });
    expect(removed.removedAt).not.toBeNull();
    expect(removed.revisions.map((r) => r.removed)).toEqual([false, true]);
    expect(await repository.findActiveRecordIds('cisa-kev')).toEqual([syntheticCveId(1)]);
  });

  it('stores each EPSS (CVE, date) once', async () => {
    const path = '/data/v1/epss';
    mock.route(path, (request) => ({
      body: epssPage(
        '2026-11-03',
        [
          { n: 1, epss: '0.123456789', percentile: '0.5' },
          { n: 2, epss: '0.2', percentile: '0.6' },
        ].slice(0, Number(request.query.get('limit'))),
        0,
        2,
      ),
    }));
    expectSucceeded(await run('first-epss'));
    await prisma.sourceSyncState.update({
      where: { source: 'first-epss' },
      data: { cursor: { lastScoreDate: '2026-11-02' } },
    });
    const again = expectSucceeded(await run('first-epss'));
    expect(again.stats).toMatchObject({ created: 0, unchanged: 2, events: 0 });
    const score = await prisma.epssScore.findFirstOrThrow({ where: { cveId: syntheticCveId(1) } });
    expect(score.score.toString()).toBe('0.123456789');
    expect(await repository.purgeEpssScoresBefore('2026-11-04')).toBe(2);
  });

  it('grants the lease to one owner at a time and abandons orphaned runs', async () => {
    const now = new Date();
    const results = await Promise.all(
      ['a', 'b', 'c'].map((owner) =>
        repository.acquireLease('github-advisory', owner, new Date(now.getTime() + 60_000), now),
      ),
    );
    expect(results.filter((r) => r.acquired)).toHaveLength(1);
    const winner = ['a', 'b', 'c'][results.findIndex((r) => r.acquired)] ?? '';
    const orphan = await repository.createRun({
      source: 'github-advisory',
      trigger: 'scheduled',
      jobId: null,
      attempt: 1,
      requestedBy: TEST_REQUESTER,
      resumedFromRunId: null,
      startedAt: now,
      cursorBefore: null,
      checkpoint: null,
    });
    // The partial unique index allows one running run per source.
    await expect(
      repository.createRun({
        source: 'github-advisory',
        trigger: 'manual',
        jobId: null,
        attempt: 1,
        requestedBy: TEST_REQUESTER,
        resumedFromRunId: null,
        startedAt: now,
        cursorBefore: null,
        checkpoint: null,
      }),
    ).rejects.toThrow();
    expect(
      await repository.renewLease('github-advisory', 'intruder', new Date(), orphan.id, now),
    ).toBe(false);
    expect(
      await repository.renewLease(
        'github-advisory',
        winner,
        new Date(now.getTime() + 60_000),
        orphan.id,
        now,
      ),
    ).toBe(true);
    // The lease expires; the next owner abandons the orphan.
    const later = new Date(now.getTime() + 120_000);
    const next = await repository.acquireLease(
      'github-advisory',
      'd',
      new Date(later.getTime() + 60_000),
      later,
    );
    expect(next).toEqual({ acquired: true, abandonedRunIds: [orphan.id] });
    expect((await repository.findRun(orphan.id))?.status).toBe('abandoned');
  });

  it('caps stored issues, lists history with filters and finds stale runs', async () => {
    const started = new Date(Date.now() - 3_600_000);
    const created = await repository.createRun({
      source: 'mitre-cve',
      trigger: 'manual',
      jobId: 'j',
      attempt: 1,
      requestedBy: TEST_REQUESTER,
      resumedFromRunId: null,
      startedAt: started,
      cursorBefore: null,
      checkpoint: null,
    });
    const issues = Array.from({ length: MAX_STORED_ISSUES_PER_RUN + 25 }, (_, i) => ({
      sourceRecordId: syntheticCveId(i + 1),
      message: `issue ${i}`,
    }));
    await repository.saveProgress(created.id, {
      checkpoint: { offset: 1 },
      stats: { ...EMPTY_SYNC_RUN_STATS, invalid: issues.length },
      issues,
      now: started,
    });
    expect((await repository.findRun(created.id))?.issueCount).toBe(issues.length);
    expect(await repository.listRunIssues(created.id, 1_000)).toHaveLength(
      MAX_STORED_ISSUES_PER_RUN,
    );
    expect((await repository.findStaleRuns(new Date())).map((r) => r.id)).toEqual([created.id]);
    expect(
      await repository.failRun(created.id, {
        status: 'abandoned',
        finishedAt: new Date(),
        stats: null,
        error: 'stale',
        events: [],
      }),
    ).toBe(true);
    expect(
      await repository.failRun(created.id, {
        status: 'abandoned',
        finishedAt: new Date(),
        stats: null,
        error: 'stale',
        events: [],
      }),
    ).toBe(false);
    const page = await repository.listRuns({
      page: 1,
      pageSize: 10,
      source: 'mitre-cve',
      status: 'abandoned',
    });
    expect(page.total).toBe(1);
    expect(page.items[0]?.checkpoint).toEqual({ offset: 1 });
  });
});
