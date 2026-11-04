import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  cveObservationRecordedPayloadSchema,
  INTELLIGENCE_EVENT_TYPES,
  syncRunFinishedPayloadSchema,
} from '@cve/contracts';

import { mapNvdCve, NVD_MAX_RANGE_MS } from '../../src/sources/nvd/nvd.adapter.js';
import { nvdCve, nvdPage, syntheticCveId, V31_CRITICAL, V40_BASE } from '../fixtures/index.js';
import { InMemoryIntelligenceRepository } from '../in-memory-repository.js';
import { MockSource } from '../mock-source.js';
import { expectSucceeded, intelligenceTestEnv, runSource, testEngine } from '../support.js';

const PATH = '/rest/json/cves/2.0';
const API_KEY = 'nvd-test-api-key-0000000000000000';
let mock: MockSource;

beforeAll(async () => {
  mock = await new MockSource().start();
});
afterAll(async () => {
  await mock.stop();
});

let repository: InMemoryIntelligenceRepository;
beforeEach(() => {
  mock.requests.length = 0;
  repository = new InMemoryIntelligenceRepository();
});

/** Serves `cves` in pages of `pageSize`, honouring `startIndex`. */
function servePages(cves: unknown[]) {
  mock.route(PATH, (request) => {
    const start = Number(request.query.get('startIndex'));
    const size = Number(request.query.get('resultsPerPage'));
    return { body: nvdPage(cves.slice(start, start + size), start, cves.length) };
  });
}

describe('NVD mapping', () => {
  it('keeps every source-specific metric, weakness and reference with its provenance', () => {
    const { draft, issues } = mapNvdCve(nvdCve(1));
    expect(issues).toEqual([]);
    expect(draft.publishedAt).toBe('2026-03-01T10:00:00.000Z');
    expect(draft.description).toContain('Synthetic NVD record 1');
    expect(draft.cvssMetrics).toEqual([
      {
        version: '4.0',
        source: 'cna@example.test',
        type: 'secondary',
        vectorString: V40_BASE,
        baseScore: 9.3,
      },
      {
        version: '3.1',
        source: 'nvd@nist.gov',
        type: 'primary',
        vectorString: V31_CRITICAL,
        baseScore: 9.8,
      },
    ]);
    expect(draft.weaknesses).toEqual([
      { cweId: 'CWE-79', source: 'nvd@nist.gov' },
      { cweId: 'NVD-CWE-noinfo', source: 'cna@example.test' },
    ]);
    // Platform entries (`vulnerable: false`) are not affected products.
    expect(draft.affectedProducts).toEqual([
      expect.objectContaining({
        vendor: 'example_vendor',
        product: 'example_product',
        versionStartIncluding: '1.0.0',
        versionEndExcluding: '1.4.2',
      }),
      expect.objectContaining({
        vendor: 'example_vendor',
        product: 'example_product',
        version: '2.0.0',
      }),
    ]);
  });

  it('marks rejected records', () => {
    expect(mapNvdCve(nvdCve(2, { vulnStatus: 'Rejected' }) as never).draft.state).toBe('rejected');
  });
});

describe('NVD synchronisation (mocked NVD API)', () => {
  it('paginates, authenticates, publishes events and commits the cursor', async () => {
    const cves = [1, 2, 3, 4, 5].map((n) => nvdCve(n));
    servePages(cves);
    const env = intelligenceTestEnv(mock, { NVD_PAGE_SIZE: '2', NVD_API_KEY: API_KEY });
    const now = new Date('2026-11-04T12:00:00.000Z');
    const run = expectSucceeded(
      await runSource(testEngine(repository, env, { now: () => now }), 'nvd'),
    );

    const requests = mock.requestsTo(PATH);
    expect(requests.map((r) => r.query.get('startIndex'))).toEqual(['0', '2', '4']);
    expect(requests.every((r) => r.headers['apikey'] === API_KEY)).toBe(true);
    // The first run without NVD_INITIAL_SYNC_FROM reads the whole catalog (no date filter).
    expect(requests[0]?.query.has('lastModStartDate')).toBe(false);
    expect(run.stats).toMatchObject({
      requests: 3,
      fetched: 5,
      created: 5,
      updated: 0,
      unchanged: 0,
      events: 5,
    });
    expect(run.cursorAfter).toEqual({ lastModifiedThrough: now.toISOString() });

    const events = repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.cveObserved);
    expect(events).toHaveLength(5);
    const payload = cveObservationRecordedPayloadSchema.parse(events[0]?.payload);
    expect(payload).toMatchObject({
      source: 'nvd',
      cveId: syntheticCveId(1),
      change: 'created',
      revision: 1,
      sourceUrl: `https://nvd.nist.gov/vuln/detail/${syntheticCveId(1)}`,
      runId: run.id,
    });
    expect(payload.attribution).toMatch(/not endorsed or certified by the NVD/);
    expect(payload.content.cvssMetrics.map((m) => m.source)).toEqual([
      'cna@example.test',
      'nvd@nist.gov',
    ]);
    // Duplicate reference tags are collapsed; the raw payload is kept.
    expect(payload.content.references[1]?.tags).toEqual(['Patch']);
    expect(repository.record('nvd', syntheticCveId(1))?.raw).toEqual(cves[0]);

    const completed = repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.syncCompleted);
    expect(syncRunFinishedPayloadSchema.parse(completed[0]?.payload)).toMatchObject({
      status: 'succeeded',
      source: 'nvd',
    });
  });

  it('is incremental and detects duplicates: unchanged records publish nothing', async () => {
    servePages([nvdCve(1), nvdCve(2)]);
    const env = intelligenceTestEnv(mock);
    let now = new Date('2026-11-04T12:00:00.000Z');
    const engine = testEngine(repository, env, { now: () => now });
    expectSucceeded(await runSource(engine, 'nvd'));
    const eventsAfterFirst = repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.cveObserved).length;

    servePages([
      nvdCve(1),
      nvdCve(2, {
        lastModified: '2026-11-04T12:30:00.000',
        descriptions: [
          { lang: 'en', value: 'Synthetic NVD record 2, revised. Not a real vulnerability.' },
        ],
      }),
    ]);
    now = new Date('2026-11-04T14:00:00.000Z');
    mock.requests.length = 0;
    const second = expectSucceeded(await runSource(engine, 'nvd'));

    const query = mock.requestsTo(PATH)[0]?.query;
    // The window starts at the previous cursor minus a five-minute overlap.
    expect(query?.get('lastModStartDate')).toBe('2026-11-04T11:55:00.000Z');
    expect(query?.get('lastModEndDate')).toBe('2026-11-04T14:00:00.000Z');
    expect(second.stats).toMatchObject({
      fetched: 2,
      created: 0,
      updated: 1,
      unchanged: 1,
      events: 1,
    });
    const updates = repository
      .eventsOfType(INTELLIGENCE_EVENT_TYPES.cveObserved)
      .slice(eventsAfterFirst);
    expect(updates).toHaveLength(1);
    expect(cveObservationRecordedPayloadSchema.parse(updates[0]?.payload)).toMatchObject({
      cveId: syntheticCveId(2),
      change: 'updated',
      revision: 2,
    });
    // Both revisions are preserved.
    expect(
      repository.revisions.filter((r) => r.externalId === syntheticCveId(2)).map((r) => r.revision),
    ).toEqual([1, 2]);
  });

  it('splits long ranges into windows of at most 120 days', async () => {
    servePages([]);
    const env = intelligenceTestEnv(mock, { NVD_INITIAL_SYNC_FROM: '2026-01-01T00:00:00Z' });
    const now = new Date('2026-11-04T00:00:00.000Z');
    expectSucceeded(await runSource(testEngine(repository, env, { now: () => now }), 'nvd'));
    const windows = mock
      .requestsTo(PATH)
      .map((r) => [r.query.get('lastModStartDate'), r.query.get('lastModEndDate')] as const);
    expect(windows).toHaveLength(3);
    for (const [start, end] of windows) {
      expect(Date.parse(end ?? '') - Date.parse(start ?? '')).toBeLessThanOrEqual(NVD_MAX_RANGE_MS);
    }
    expect(windows[0]?.[0]).toBe('2026-01-01T00:00:00.000Z');
    expect(windows.at(-1)?.[1]).toBe(now.toISOString());
  });

  it('reports invalid records and dropped values as run issues instead of failing', async () => {
    servePages([
      nvdCve(1, {
        metrics: {
          cvssMetricV31: [
            {
              source: 'nvd@nist.gov',
              type: 'Primary',
              cvssData: { version: '3.1', vectorString: 'CVSS:3.1/AV:X', baseScore: 1 },
            },
          ],
        },
      }),
      { id: 'CVE-1990-0001', descriptions: [{ lang: 'en', value: 'Synthetic.' }] },
      nvdCve(3, { descriptions: [] }),
    ]);
    const run = expectSucceeded(
      await runSource(testEngine(repository, intelligenceTestEnv(mock)), 'nvd'),
    );
    expect(run.stats).toMatchObject({ fetched: 3, created: 1, invalid: 3 });
    const issues = await repository.listRunIssues(run.id, 50);
    expect(issues.map((issue) => issue.sourceRecordId).sort()).toEqual(
      ['CVE-1990-0001', syntheticCveId(1), syntheticCveId(3)].sort(),
    );
    expect(issues.find((i) => i.sourceRecordId === syntheticCveId(1))?.message).toMatch(
      /cvssMetrics\[0\] dropped/,
    );
    expect(issues.find((i) => i.sourceRecordId === syntheticCveId(3))?.message).toMatch(
      /no description/,
    );
  });

  it('retries throttling (403) and server errors with backoff', async () => {
    let calls = 0;
    mock.route(PATH, () => {
      calls += 1;
      if (calls === 1) return { status: 403, body: { message: 'rate limit' } };
      if (calls === 2) return { status: 503, body: '' };
      return { body: nvdPage([nvdCve(1)], 0, 1) };
    });
    const run = expectSucceeded(
      await runSource(testEngine(repository, intelligenceTestEnv(mock)), 'nvd'),
    );
    expect(calls).toBe(3);
    expect(run.stats.requests).toBe(3);
  });

  it('resumes a failed run from its checkpoint without re-reading persisted pages', async () => {
    const cves = [1, 2, 3, 4].map((n) => nvdCve(n));
    let failPage2 = true;
    mock.route(PATH, (request) => {
      const start = Number(request.query.get('startIndex'));
      if (start === 2 && failPage2) return { status: 500, body: '' };
      return { body: nvdPage(cves.slice(start, start + 2), start, cves.length) };
    });
    const env = intelligenceTestEnv(mock, { NVD_PAGE_SIZE: '2', SOURCE_HTTP_MAX_ATTEMPTS: '1' });
    const engine = testEngine(repository, env);
    const failed = await runSource(engine, 'nvd');
    expect(failed.status).toBe('failed');
    if (failed.status !== 'failed' || failed.run === null) throw new Error('expected a failed run');
    expect(failed.retryable).toBe(true);
    const stored = await repository.findRun(failed.run.id);
    expect(stored).toMatchObject({
      status: 'failed',
      checkpoint: expect.objectContaining({ startIndex: 2 }) as unknown,
    });
    expect(repository.states.get('nvd')?.cursor).toBeNull();
    expect(repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.syncFailed)).toHaveLength(1);

    failPage2 = false;
    mock.requests.length = 0;
    const resumed = expectSucceeded(await runSource(engine, 'nvd'));
    expect(resumed.resumedFromRunId).toBe(failed.run.id);
    expect(mock.requestsTo(PATH).map((r) => r.query.get('startIndex'))).toEqual(['2']);
    expect(repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.cveObserved)).toHaveLength(4);
    expect(repository.states.get('nvd')?.cursor).toEqual(resumed.cursorAfter);
  });

  it('starts over when asked for a fresh run', async () => {
    let fail = true;
    mock.route(PATH, (request) => {
      const start = Number(request.query.get('startIndex'));
      if (start === 1 && fail) return { status: 500 };
      return { body: nvdPage([nvdCve(start + 1)], start, 2) };
    });
    const engine = testEngine(
      repository,
      intelligenceTestEnv(mock, { NVD_PAGE_SIZE: '1', SOURCE_HTTP_MAX_ATTEMPTS: '1' }),
    );
    expect((await runSource(engine, 'nvd')).status).toBe('failed');
    fail = false;
    mock.requests.length = 0;
    const fresh = expectSucceeded(await runSource(engine, 'nvd', { fresh: true }));
    expect(fresh.resumedFromRunId).toBeNull();
    expect(mock.requestsTo(PATH).map((r) => r.query.get('startIndex'))).toEqual(['0', '1']);
    expect(fresh.stats).toMatchObject({ created: 1, unchanged: 1 });
  });
});
