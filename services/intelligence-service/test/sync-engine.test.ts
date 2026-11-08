import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { INTELLIGENCE_EVENT_TYPES, syncRunFinishedPayloadSchema } from '@cve/contracts';
import { PermanentJobError } from '@cve/jobs';

import { runMaintenance, SourceBusyError, sourceSyncHandler } from '../src/sync/sync-jobs.js';
import { kevCatalog, kevEntry, nvdCve, nvdPage } from './fixtures/index.js';
import { InMemoryIntelligenceRepository } from './in-memory-repository.js';
import { MockSource } from './mock-source.js';
import {
  expectSucceeded,
  intelligenceTestEnv,
  runSource,
  silentLogger,
  testEngine,
} from './support.js';

const NVD = '/rest/json/cves/2.0';
const KEV = '/feeds/known_exploited_vulnerabilities.json';
let mock: MockSource;
let repository: InMemoryIntelligenceRepository;

beforeAll(async () => {
  mock = await new MockSource().start();
});
afterAll(async () => {
  await mock.stop();
});
beforeEach(() => {
  mock.requests.length = 0;
  repository = new InMemoryIntelligenceRepository();
  mock.route(NVD, (request) => {
    const start = Number(request.query.get('startIndex'));
    const cves = [nvdCve(1), nvdCve(2), nvdCve(3)];
    return { body: nvdPage(cves.slice(start, start + 1), start, cves.length) };
  });
  mock.route(KEV, () => ({ body: kevCatalog('v1', [kevEntry(1)]) }));
});

const context = (overrides: Partial<{ attempt: number; maxAttempts: number }> = {}) => ({
  jobId: 'job-1',
  attempt: 1,
  maxAttempts: 3,
  signal: new AbortController().signal,
  logger: silentLogger,
  ...overrides,
});

describe('source lease', () => {
  it('lets only one run of a source proceed at a time; other sources are independent', async () => {
    const env = intelligenceTestEnv(mock, { NVD_PAGE_SIZE: '1' });
    const engine = testEngine(repository, env);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    mock.route(NVD, async (request) => {
      await gate;
      const start = Number(request.query.get('startIndex'));
      return { body: nvdPage([nvdCve(start + 1)], start, 1) };
    });
    const first = runSource(engine, 'nvd');
    await vi.waitFor(() => {
      expect(mock.requestsTo(NVD)).toHaveLength(1);
    });
    await expect(runSource(engine, 'nvd')).resolves.toEqual({
      status: 'skipped',
      reason: 'locked',
    });
    expectSucceeded(await runSource(engine, 'cisa-kev'));
    release();
    expectSucceeded(await first);
    expect(repository.states.get('nvd')?.leaseOwner).toBeNull();
  });

  it('skips disabled sources', async () => {
    const engine = testEngine(repository, intelligenceTestEnv(mock, { NVD_ENABLED: 'false' }));
    await expect(runSource(engine, 'nvd')).resolves.toEqual({
      status: 'skipped',
      reason: 'disabled',
    });
  });
});

describe('failed job recovery', () => {
  it('keeps the checkpoint when persistence fails, then resumes', async () => {
    const env = intelligenceTestEnv(mock, { NVD_PAGE_SIZE: '1' });
    const engine = testEngine(repository, env);
    let writes = 0;
    repository.beforeApply = () => {
      writes += 1;
      if (writes === 2) throw new Error('database unavailable');
    };
    const failed = await runSource(engine, 'nvd', { attempt: 1, maxAttempts: 4 });
    expect(failed).toMatchObject({ status: 'failed', retryable: true });
    const failedEvent = syncRunFinishedPayloadSchema.parse(
      repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.syncFailed)[0]?.payload,
    );
    expect(failedEvent).toMatchObject({
      status: 'failed',
      willRetry: true,
      error: 'database unavailable',
    });
    expect(repository.states.get('nvd')).toMatchObject({
      consecutiveFailures: 1,
      lastRunStatus: 'failed',
    });

    repository.beforeApply = undefined;
    mock.requests.length = 0;
    const resumed = expectSucceeded(await runSource(engine, 'nvd', { attempt: 2, maxAttempts: 4 }));
    expect(mock.requestsTo(NVD).map((r) => r.query.get('startIndex'))).toEqual(['1', '2']);
    expect(resumed.stats.created).toBe(2);
    expect(repository.states.get('nvd')).toMatchObject({
      consecutiveFailures: 0,
      lastRunStatus: 'succeeded',
    });
    expect(repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.cveObserved)).toHaveLength(3);
  });

  it('abandons runs whose worker died, publishes the failure and queues a recovery run', async () => {
    const env = intelligenceTestEnv(mock);
    const engine = testEngine(repository, env);
    // Relative to the real clock: the recovery run below resumes only within the resume window.
    const now = new Date();
    const crashedAt = new Date(now.getTime() - 60 * 60_000);
    const crashed = await repository.createRun({
      source: 'nvd',
      trigger: 'scheduled',
      jobId: 'scheduled.nvd.1',
      attempt: 1,
      requestedBy: null,
      resumedFromRunId: null,
      startedAt: crashedAt,
      cursorBefore: null,
      checkpoint: { windowStart: null, runEnd: crashedAt.toISOString(), startIndex: 1 },
    });
    const enqueue = vi.fn(() => Promise.resolve());
    const result = await runMaintenance({
      repository,
      engine,
      enqueue,
      staleAfterMs: 10 * 60_000,
      epssRetentionDays: 30,
      outboxRetentionDays: 7,
      logger: silentLogger,
      now: () => now,
    });
    expect(result.recovered).toBe(1);
    expect(enqueue).toHaveBeenCalledWith(
      { source: 'nvd', trigger: 'recovery' },
      `recovery.nvd.${crashed.id}`,
    );
    expect((await repository.findRun(crashed.id))?.status).toBe('abandoned');
    expect(
      syncRunFinishedPayloadSchema.parse(
        repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.syncFailed)[0]?.payload,
      ),
    ).toMatchObject({ status: 'abandoned', runId: crashed.id });

    // The recovery run continues where the crashed run stopped.
    const recovered = expectSucceeded(await runSource(engine, 'nvd', { trigger: 'recovery' }));
    expect(recovered.resumedFromRunId).toBe(crashed.id);
    expect(mock.requestsTo(NVD)[0]?.query.get('startIndex')).toBe('1');
  });

  it('abandons a running run when its lease has expired', async () => {
    const engine = testEngine(repository, intelligenceTestEnv(mock));
    await repository.acquireLease(
      'cisa-kev',
      'dead-worker',
      new Date(Date.now() - 1_000),
      new Date(Date.now() - 60_000),
    );
    const orphan = await repository.createRun({
      source: 'cisa-kev',
      trigger: 'scheduled',
      jobId: null,
      attempt: 1,
      requestedBy: null,
      resumedFromRunId: null,
      startedAt: new Date(Date.now() - 60_000),
      cursorBefore: null,
      checkpoint: null,
    });
    expectSucceeded(await runSource(engine, 'cisa-kev'));
    expect((await repository.findRun(orphan.id))?.status).toBe('abandoned');
  });

  it('purges EPSS scores older than the retention', async () => {
    repository.epss.set('a', {
      cveId: 'CVE-2026-90001',
      score: 0.1,
      percentile: 0.2,
      scoreDate: '2026-09-01',
    });
    repository.epss.set('b', {
      cveId: 'CVE-2026-90001',
      score: 0.1,
      percentile: 0.2,
      scoreDate: '2026-11-01',
    });
    await runMaintenance({
      repository,
      engine: testEngine(repository, intelligenceTestEnv(mock)),
      enqueue: () => Promise.resolve(),
      staleAfterMs: 60_000,
      epssRetentionDays: 30,
      outboxRetentionDays: 7,
      logger: silentLogger,
      now: () => new Date('2026-11-04T00:00:00Z'),
    });
    expect([...repository.epss.keys()]).toEqual(['b']);
  });
});

describe('BullMQ job handler', () => {
  it('maps outcomes to retries, permanent failures and skips', async () => {
    const env = intelligenceTestEnv(mock);
    const engine = testEngine(repository, env);
    const handler = sourceSyncHandler(engine);
    await expect(
      handler(
        { source: 'cisa-kev', trigger: 'manual', requestedBy: null, fresh: false },
        context(),
      ),
    ).resolves.toBeUndefined();

    await repository.acquireLease('cisa-kev', 'other', new Date(Date.now() + 60_000), new Date());
    await expect(
      handler(
        { source: 'cisa-kev', trigger: 'scheduled', requestedBy: null, fresh: false },
        context(),
      ),
    ).resolves.toBeUndefined();
    await expect(
      handler(
        { source: 'cisa-kev', trigger: 'manual', requestedBy: null, fresh: false },
        context(),
      ),
    ).rejects.toBeInstanceOf(SourceBusyError);
    await repository.releaseLease('cisa-kev', 'other');

    mock.route(KEV, () => ({ status: 404 }));
    await expect(
      handler(
        { source: 'cisa-kev', trigger: 'manual', requestedBy: null, fresh: false },
        context(),
      ),
    ).rejects.toBeInstanceOf(PermanentJobError);
    mock.route(KEV, () => ({ status: 503 }));
    const retryable = handler(
      { source: 'cisa-kev', trigger: 'manual', requestedBy: null, fresh: false },
      context(),
    );
    await expect(retryable).rejects.toThrow(/HTTP 503/);
    await expect(retryable).rejects.not.toBeInstanceOf(PermanentJobError);

    const disabled = sourceSyncHandler(
      testEngine(repository, intelligenceTestEnv(mock, { CISA_KEV_ENABLED: 'false' })),
    );
    await expect(
      disabled(
        { source: 'cisa-kev', trigger: 'manual', requestedBy: null, fresh: false },
        context(),
      ),
    ).rejects.toBeInstanceOf(PermanentJobError);
  });
});
