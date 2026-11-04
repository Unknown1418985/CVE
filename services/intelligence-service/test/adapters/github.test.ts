import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { cveObservationRecordedPayloadSchema, INTELLIGENCE_EVENT_TYPES } from '@cve/contracts';

import { nextLink, parseVersionRange } from '../../src/sources/github/github-advisory.adapter.js';
import { advisory, syntheticCveId, syntheticGhsaId } from '../fixtures/index.js';
import { InMemoryIntelligenceRepository } from '../in-memory-repository.js';
import { MockSource } from '../mock-source.js';
import { expectSucceeded, intelligenceTestEnv, runSource, testEngine } from '../support.js';

const PATH = '/advisories';
const TOKEN = 'github_pat_test_token_000000000000';
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

describe('GitHub helpers', () => {
  it('parses version ranges and Link headers', () => {
    expect(parseVersionRange('>= 1.0.0, < 1.4.2')).toEqual({
      versionStartIncluding: '1.0.0',
      versionEndExcluding: '1.4.2',
    });
    expect(parseVersionRange('= 2.0.0')).toEqual({ version: '2.0.0' });
    expect(parseVersionRange('<= 0.9')).toEqual({ versionEndIncluding: '0.9' });
    expect(parseVersionRange('between 1 and 2')).toBeNull();
    expect(
      nextLink(
        '<https://api.github.com/advisories?after=abc>; rel="next", <https://x>; rel="prev"',
      ),
    ).toBe('https://api.github.com/advisories?after=abc');
    expect(nextLink(null)).toBeNull();
  });
});

describe('GitHub Advisory Database synchronisation (mocked REST API)', () => {
  it('follows cursor pagination, sends the token and maps advisories with a CVE ID', async () => {
    mock.route(PATH, (request) => {
      if (request.query.get('after') === 'page2') {
        return {
          body: [
            advisory(3, { cve_id: null }),
            advisory(4, {
              withdrawn_at: '2026-03-04T00:00:00Z',
              updated_at: '2026-03-04T00:00:00Z',
            }),
          ],
        };
      }
      return {
        headers: { link: `<${mock.origin}/advisories?after=page2&per_page=100>; rel="next"` },
        body: [advisory(1), advisory(2, { updated_at: '2026-03-05T10:00:00Z' })],
      };
    });
    const env = intelligenceTestEnv(mock, { GITHUB_TOKEN: TOKEN });
    const now = new Date('2026-11-04T12:00:00.000Z');
    const run = expectSucceeded(
      await runSource(testEngine(repository, env, { now: () => now }), 'github-advisory'),
    );

    const [first, second] = mock.requestsTo(PATH);
    expect(first?.query.get('updated')).toBe('>=2026-10-05T12:00:00Z');
    expect(first?.query.get('sort')).toBe('updated');
    expect(first?.query.get('direction')).toBe('asc');
    expect(first?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(first?.headers['x-github-api-version']).toBe('2022-11-28');
    expect(second?.query.get('after')).toBe('page2');
    // Advisory 3 has no CVE ID (stored only); advisory 4 is withdrawn (stored as removed).
    expect(run.stats).toMatchObject({ fetched: 4, created: 3, removed: 1, events: 2 });
    expect(run.cursorAfter).toEqual({ updatedSince: '2026-03-05T10:00:00.000Z' });
    const payload = cveObservationRecordedPayloadSchema.parse(
      repository.eventsOfType(INTELLIGENCE_EVENT_TYPES.cveObserved)[0]?.payload,
    );
    expect(payload).toMatchObject({
      source: 'github-advisory',
      sourceRecordId: syntheticGhsaId(1),
      cveId: syntheticCveId(1),
    });
    expect(payload.content.affectedProducts).toEqual([
      expect.objectContaining({
        vendor: 'npm',
        product: 'example-package',
        versionStartIncluding: '1.0.0',
        versionEndExcluding: '1.4.2',
      }),
      expect.objectContaining({ vendor: 'pip', product: 'example-py', versionEndIncluding: '0.9' }),
    ]);
    expect(payload.content.cvssMetrics.map((m) => m.version)).toEqual(['4.0', '3.1']);
    expect(payload.attribution).toMatch(/CC BY 4.0/);
    expect(repository.record('github-advisory', syntheticGhsaId(3))?.cveId).toBeNull();
  });

  it('refuses pagination links to other hosts', async () => {
    mock.route(PATH, () => ({
      headers: { link: '<https://evil.example/advisories?after=x>; rel="next"' },
      body: [advisory(1)],
    }));
    const outcome = await runSource(
      testEngine(repository, intelligenceTestEnv(mock)),
      'github-advisory',
    );
    expect(outcome).toMatchObject({ status: 'failed', retryable: false });
    expect(outcome.status === 'failed' && outcome.error.message).toMatch(/not allowlisted/);
  });

  it('waits for the quota reset reported by x-ratelimit headers', async () => {
    let calls = 0;
    mock.route(PATH, () => {
      calls += 1;
      if (calls === 1) {
        return {
          status: 403,
          headers: {
            'x-ratelimit-remaining': '0',
            'x-ratelimit-reset': String(Math.ceil(Date.now() / 1000) + 1),
          },
          body: { message: 'API rate limit exceeded' },
        };
      }
      return { body: [advisory(1)] };
    });
    const started = Date.now();
    expectSucceeded(
      await runSource(testEngine(repository, intelligenceTestEnv(mock)), 'github-advisory'),
    );
    expect(calls).toBe(2);
    expect(Date.now() - started).toBeGreaterThanOrEqual(200);
  });
});
