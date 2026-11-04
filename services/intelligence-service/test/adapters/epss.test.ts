import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { epssScoresPublishedPayloadSchema, INTELLIGENCE_EVENT_TYPES } from '@cve/contracts';

import { parseProbability } from '../../src/sources/epss/epss.adapter.js';
import { epssPage, syntheticCveId } from '../fixtures/index.js';
import { InMemoryIntelligenceRepository } from '../in-memory-repository.js';
import { MockSource } from '../mock-source.js';
import { expectSucceeded, intelligenceTestEnv, runSource, testEngine } from '../support.js';

const PATH = '/data/v1/epss';
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

const rows = (count: number) =>
  Array.from({ length: count }, (_, i) => ({
    n: i + 1,
    epss: (0.001 * (i + 1)).toFixed(9),
    percentile: (0.01 * (i + 1)).toFixed(9),
  }));

/** Serves `days` (date → rows) with offset/limit pagination; no `date` means the newest day. */
function serve(days: Record<string, { n: number; epss: string; percentile: string }[]>) {
  const newest = Object.keys(days).sort().at(-1) ?? '';
  mock.route(PATH, (request) => {
    const date = request.query.get('date') ?? newest;
    const all = days[date] ?? [];
    const offset = Number(request.query.get('offset') ?? 0);
    const limit = Number(request.query.get('limit') ?? 100);
    return { body: epssPage(date, all.slice(offset, offset + limit), offset, all.length) };
  });
}

describe('EPSS parsing', () => {
  it('parses probability strings and rejects values outside 0–1', () => {
    expect(parseProbability('0.000430000')).toBe(0.00043);
    expect(parseProbability(' 1.0 ')).toBe(1);
    expect(parseProbability('1.2')).toBeNull();
    expect(parseProbability('abc')).toBeNull();
  });
});

describe('FIRST EPSS synchronisation (mocked API)', () => {
  it('paginates the newest score date and publishes batched events', async () => {
    serve({ '2026-11-03': rows(5) });
    const env = intelligenceTestEnv(mock, { EPSS_PAGE_SIZE: '2' });
    const run = expectSucceeded(await runSource(testEngine(repository, env), 'first-epss'));
    const pages = mock.requestsTo(PATH).filter((r) => r.query.get('date') !== null);
    expect(pages.map((r) => r.query.get('offset'))).toEqual(['0', '2', '4']);
    expect(run.stats).toMatchObject({ fetched: 5, created: 5, events: 3 });
    expect(run.cursorAfter).toEqual({ lastScoreDate: '2026-11-03' });
    const payload = epssScoresPublishedPayloadSchema.parse(
      repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.epssPublished)[0]?.payload,
    );
    expect(payload).toMatchObject({
      source: 'first-epss',
      scoreDate: '2026-11-03',
      scores: [
        { cveId: syntheticCveId(1), score: 0.001, percentile: 0.01 },
        { cveId: syntheticCveId(2) },
      ],
    });
    expect(payload.attribution).toMatch(/FIRST/);
  });

  it('skips runs when no newer date exists and backfills missed dates', async () => {
    serve({ '2026-11-01': rows(2) });
    const engine = testEngine(repository, intelligenceTestEnv(mock));
    expectSucceeded(await runSource(engine, 'first-epss'));
    mock.requests.length = 0;
    const same = expectSucceeded(await runSource(engine, 'first-epss'));
    expect(same.stats.fetched).toBe(0);
    expect(mock.requests).toHaveLength(1);

    serve({ '2026-11-01': rows(2), '2026-11-02': rows(2), '2026-11-03': rows(3) });
    mock.requests.length = 0;
    const catchUp = expectSucceeded(await runSource(engine, 'first-epss'));
    expect(
      mock
        .requestsTo(PATH)
        .map((r) => r.query.get('date'))
        .filter((d) => d !== null),
    ).toEqual(['2026-11-02', '2026-11-03']);
    expect(catchUp.cursorAfter).toEqual({ lastScoreDate: '2026-11-03' });
    expect(catchUp.stats.created).toBe(5);
  });

  it('never publishes the same (CVE, date) twice', async () => {
    serve({ '2026-11-03': rows(3) });
    const engine = testEngine(repository, intelligenceTestEnv(mock));
    expectSucceeded(await runSource(engine, 'first-epss'));
    // Force the same date again (e.g. a manual fresh run after the cursor was reset).
    repository.states.delete('first-epss');
    const again = expectSucceeded(await runSource(engine, 'first-epss', { fresh: true }));
    expect(again.stats).toMatchObject({ fetched: 3, created: 0, unchanged: 3, events: 0 });
    expect(repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.epssPublished)).toHaveLength(1);
  });

  it('reports invalid rows', async () => {
    mock.route(PATH, (request) => ({
      body: {
        ...epssPage(
          '2026-11-03',
          [
            { n: 1, epss: '0.5', percentile: '0.9' },
            { n: 2, epss: '7', percentile: '0.9' },
          ],
          0,
          3,
        ),
        data: [
          { cve: syntheticCveId(1), epss: '0.5', percentile: '0.9', date: '2026-11-03' },
          { cve: syntheticCveId(2), epss: '7', percentile: '0.9', date: '2026-11-03' },
          { cve: 'CVE-1', epss: '0.1', percentile: '0.1', date: '2026-11-03' },
        ].slice(0, request.query.get('limit') === '1' ? 1 : 3),
      },
    }));
    const run = expectSucceeded(
      await runSource(testEngine(repository, intelligenceTestEnv(mock)), 'first-epss'),
    );
    expect(run.stats).toMatchObject({ created: 1, invalid: 2 });
  });
});
