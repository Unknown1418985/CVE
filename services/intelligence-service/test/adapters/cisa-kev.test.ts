import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  INTELLIGENCE_EVENT_TYPES,
  kevEntryChangedPayloadSchema,
  kevEntryRemovedPayloadSchema,
} from '@cve/contracts';

import { kevCatalog, kevEntry, syntheticCveId } from '../fixtures/index.js';
import { InMemoryIntelligenceRepository } from '../in-memory-repository.js';
import { MockSource } from '../mock-source.js';
import { expectSucceeded, intelligenceTestEnv, runSource, testEngine } from '../support.js';

const FEED = '/feeds/known_exploited_vulnerabilities.json';
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

const serve = (version: string, entries: unknown[], etag = `"${version}"`) =>
  mock.route(FEED, (request) =>
    request.headers['if-none-match'] === etag
      ? { status: 304 }
      : {
          headers: { etag, 'last-modified': 'Wed, 04 Nov 2026 12:00:00 GMT' },
          body: kevCatalog(version, entries),
        },
  );

describe('CISA KEV synchronisation (mocked feed)', () => {
  it('publishes additions, updates and removals from complete snapshots', async () => {
    const engine = testEngine(repository, intelligenceTestEnv(mock));
    serve('2026.11.01', [
      kevEntry(1),
      kevEntry(2),
      kevEntry(3, { knownRansomwareCampaignUse: 'Known' }),
    ]);
    const first = expectSucceeded(await runSource(engine, 'cisa-kev'));
    expect(first.stats).toMatchObject({ fetched: 3, created: 3, events: 3 });
    expect(first.cursorAfter).toMatchObject({ catalogVersion: '2026.11.01', etag: '"2026.11.01"' });
    const added = repository
      .eventsOfType(INTELLIGENCE_EVENT_TYPES.kevAdded)
      .map((e) => kevEntryChangedPayloadSchema.parse(e.payload));
    expect(added.find((p) => p.cveId === syntheticCveId(3))?.entry.knownRansomwareCampaignUse).toBe(
      'known',
    );
    expect(added[0]).toMatchObject({
      catalog: { catalogVersion: '2026.11.01' },
      entry: { source: 'cisa-kev', dateAdded: '2026-04-01', dueDate: '2026-04-22' },
      cweIds: ['CWE-79'],
    });

    // Not modified: nothing happens.
    mock.requests.length = 0;
    const unchanged = expectSucceeded(await runSource(engine, 'cisa-kev'));
    expect(mock.requestsTo(FEED)[0]?.headers['if-none-match']).toBe('"2026.11.01"');
    expect(unchanged.stats.fetched).toBe(0);

    // New catalog: entry 2 changed, entry 3 removed, entry 4 added.
    serve('2026.11.04', [kevEntry(1), kevEntry(2, { dueDate: '2026-05-01' }), kevEntry(4)]);
    const second = expectSucceeded(await runSource(engine, 'cisa-kev'));
    expect(second.stats).toMatchObject({
      fetched: 3,
      created: 1,
      updated: 1,
      unchanged: 1,
      removed: 1,
      events: 3,
    });
    expect(
      repository
        .eventsOfType(INTELLIGENCE_EVENT_TYPES.kevUpdated)
        .map((e) => kevEntryChangedPayloadSchema.parse(e.payload).cveId),
    ).toEqual([syntheticCveId(2)]);
    expect(
      kevEntryRemovedPayloadSchema.parse(
        repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.kevRemoved)[0]?.payload,
      ),
    ).toMatchObject({ cveId: syntheticCveId(3), catalog: { catalogVersion: '2026.11.04' } });
    expect(repository.record('cisa-kev', syntheticCveId(3))?.removedAt).not.toBeNull();

    // An entry that comes back is announced as added again.
    serve('2026.11.05', [
      kevEntry(1),
      kevEntry(2, { dueDate: '2026-05-01' }),
      kevEntry(3, { knownRansomwareCampaignUse: 'Known' }),
      kevEntry(4),
    ]);
    expectSucceeded(await runSource(engine, 'cisa-kev'));
    expect(
      repository
        .eventsOfType(INTELLIGENCE_EVENT_TYPES.kevAdded)
        .map((e) => kevEntryChangedPayloadSchema.parse(e.payload).cveId)
        .filter((id) => id === syntheticCveId(3)),
    ).toHaveLength(2);
  });

  it('rejects a snapshot that would remove most of the catalog', async () => {
    const engine = testEngine(repository, intelligenceTestEnv(mock));
    serve(
      'v1',
      Array.from({ length: 30 }, (_, i) => kevEntry(i + 1)),
    );
    expectSucceeded(await runSource(engine, 'cisa-kev'));
    serve('v2', [kevEntry(1)]);
    const outcome = await runSource(engine, 'cisa-kev');
    expect(outcome).toMatchObject({ status: 'failed', retryable: false });
    expect(repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.kevRemoved)).toHaveLength(0);
    expect(repository.states.get('cisa-kev')?.cursor).toMatchObject({ catalogVersion: 'v1' });
  });

  it('skips invalid entries and reports them', async () => {
    serve('v1', [kevEntry(1), kevEntry(2, { cveID: 'not-a-cve' }), { foo: 'bar' }]);
    const run = expectSucceeded(
      await runSource(testEngine(repository, intelligenceTestEnv(mock)), 'cisa-kev'),
    );
    expect(run.stats).toMatchObject({ fetched: 3, created: 1, invalid: 2 });
    expect(await repository.listRunIssues(run.id, 5)).toHaveLength(2);
  });
});
