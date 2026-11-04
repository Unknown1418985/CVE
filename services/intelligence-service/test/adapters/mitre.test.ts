import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { cveObservationRecordedPayloadSchema, INTELLIGENCE_EVENT_TYPES } from '@cve/contracts';

import { mapCveRecordV5 } from '../../src/sources/mitre/mitre.adapter.js';
import {
  cveRecordV5,
  deltaLogEntry,
  syntheticCveId,
  V31_CRITICAL,
  V31_MEDIUM,
} from '../fixtures/index.js';
import { InMemoryIntelligenceRepository } from '../in-memory-repository.js';
import { MockSource } from '../mock-source.js';
import { expectSucceeded, intelligenceTestEnv, runSource, testEngine } from '../support.js';

const DELTA = '/cvelist/deltaLog.json';
const record = (n: number) => `/api/cve/${syntheticCveId(n)}`;
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
});

describe('CVE JSON 5 mapping', () => {
  it('keeps CNA and ADP data apart and merges duplicate references', () => {
    const { draft, issues } = mapCveRecordV5(cveRecordV5(1) as never);
    expect(issues).toEqual([]);
    expect(draft).toMatchObject({
      state: 'published',
      title: 'Synthetic CVE List record 1',
      assigner: 'ExampleCNA',
    });
    expect(draft.cvssMetrics).toEqual([
      {
        version: '3.1',
        source: 'ExampleCNA',
        type: 'secondary',
        vectorString: V31_MEDIUM,
        baseScore: 6.1,
      },
      {
        version: '3.1',
        source: 'CISA-ADP',
        type: 'secondary',
        vectorString: V31_CRITICAL,
        baseScore: 9.8,
      },
    ]);
    expect(draft.weaknesses).toEqual([
      { cweId: 'CWE-89', source: 'ExampleCNA' },
      { cweId: 'CWE-79', source: 'CISA-ADP' },
    ]);
    expect(draft.references).toEqual([
      {
        url: 'https://example.test/advisories/1',
        source: 'ExampleCNA',
        tags: ['vendor-advisory', 'exploit'],
      },
    ]);
    expect(draft.affectedProducts).toEqual([
      expect.objectContaining({
        vendor: 'Example Vendor',
        product: 'Example Product',
        versionStartIncluding: '1.0.0',
        versionEndExcluding: '1.4.2',
        status: 'affected',
      }),
      expect.objectContaining({ version: '2.0.0' }),
      expect.objectContaining({ version: 'before 3 (free text)' }),
      { vendor: 'n/a', product: 'example-lib', source: 'ExampleCNA', status: 'affected' },
    ]);
  });

  it('uses the rejection reason as the description of rejected records', () => {
    const rejected = cveRecordV5(2, {
      state: 'REJECTED',
      cna: {
        descriptions: undefined,
        rejectedReasons: [{ lang: 'en', value: 'Synthetic: rejected as a duplicate.' }],
      },
    });
    expect(mapCveRecordV5(rejected as never).draft).toMatchObject({
      state: 'rejected',
      description: 'Synthetic: rejected as a duplicate.',
    });
  });
});

describe('MITRE CVE synchronisation (mocked delta log and CVE Services API)', () => {
  it('reads changed records from the delta log, validates them and advances the cursor', async () => {
    mock
      .route(DELTA, () => ({
        headers: { 'content-type': 'text/plain; charset=utf-8', etag: '"delta-1"' },
        body: [
          deltaLogEntry('2026-11-04T11:00:00.000Z', { new: [1], updated: [2] }),
          deltaLogEntry('2026-11-04T10:00:00.000Z', { updated: [2, 3] }),
          // Older than the initial look-back: ignored.
          deltaLogEntry('2026-11-01T10:00:00.000Z', { updated: [9] }),
        ],
      }))
      .route(record(1), () => ({ body: cveRecordV5(1) }))
      .route(record(2), () => ({ body: cveRecordV5(2) }))
      .route(record(3), () => ({ status: 404, body: { error: 'CVE_RECORD_DNE' } }));
    const now = new Date('2026-11-04T12:00:00.000Z');
    const run = expectSucceeded(
      await runSource(
        testEngine(repository, intelligenceTestEnv(mock), { now: () => now }),
        'mitre-cve',
      ),
    );

    expect(mock.requestsTo(record(9))).toHaveLength(0);
    // Record 3 is missing; records 1 and 2 are stored with one dropped version each.
    expect(run.stats).toMatchObject({ fetched: 3, created: 2, invalid: 3, events: 2 });
    expect(run.cursorAfter).toEqual({
      lastFetchTime: '2026-11-04T11:00:00.000Z',
      deltaLogEtag: '"delta-1"',
    });
    const issues = await repository.listRunIssues(run.id, 10);
    expect(issues.find((i) => i.sourceRecordId === syntheticCveId(3))?.message).toMatch(
      /not found/,
    );
    // The free-text version cannot become a version bound; it is reported, the rest is kept.
    expect(issues.find((i) => i.sourceRecordId === syntheticCveId(1))?.message).toMatch(
      /affectedProducts\[2\] dropped/,
    );
    const payload = cveObservationRecordedPayloadSchema.parse(
      repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.cveObserved)[0]?.payload,
    );
    expect(payload).toMatchObject({
      source: 'mitre-cve',
      sourceUrl: `https://www.cve.org/CVERecord?id=${syntheticCveId(1)}`,
    });
    expect(payload.attribution).toMatch(/CVE Program/);
  });

  it('sends the stored ETag and does nothing when the delta log is unchanged', async () => {
    mock
      .route(DELTA, (request) =>
        request.headers['if-none-match'] === '"delta-1"'
          ? { status: 304 }
          : {
              headers: { etag: '"delta-1"' },
              body: [deltaLogEntry('2026-11-04T11:00:00.000Z', { new: [1] })],
            },
      )
      .route(record(1), () => ({ body: cveRecordV5(1) }));
    const now = new Date('2026-11-04T12:00:00.000Z');
    const engine = testEngine(repository, intelligenceTestEnv(mock), { now: () => now });
    expectSucceeded(await runSource(engine, 'mitre-cve'));
    mock.requests.length = 0;
    const second = expectSucceeded(await runSource(engine, 'mitre-cve'));
    expect(mock.requests.map((r) => r.path)).toEqual([DELTA]);
    expect(second.stats).toMatchObject({ fetched: 0, events: 0 });
  });

  it('reports a gap when the delta log no longer reaches back to the cursor', async () => {
    mock.route(DELTA, () => ({ body: [deltaLogEntry('2026-11-04T11:00:00.000Z', {})] }));
    repository.states.set('mitre-cve', {
      source: 'mitre-cve',
      cursor: { lastFetchTime: '2026-09-01T00:00:00.000Z' },
      lastRunAt: null,
      lastRunStatus: null,
      lastSuccessAt: null,
      consecutiveFailures: 0,
      leaseOwner: null,
      leaseExpiresAt: null,
    });
    const run = expectSucceeded(
      await runSource(testEngine(repository, intelligenceTestEnv(mock)), 'mitre-cve'),
    );
    expect((await repository.listRunIssues(run.id, 5))[0]?.message).toMatch(/not covered/);
  });
});
