import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { DisallowedUrlError, SourceHttpError } from '@cve/source-http';

import { mapGithubRepository } from '../src/connectors/github/github-mapping.js';
import { isUnavailable, type GithubConnector } from '../src/connectors/github/github-connector.js';
import { createConnectorRegistry } from '../src/connectors/registry.js';
import { MockSource } from './mock-source.js';
import { githubRepo, pocTestEnv, sha, silentLogger } from './support.js';

const TOKEN = 'ghp_synthetic_test_token_000000';
const LIMITS = {
  search: { maxRequests: 1_000, windowMs: 60_000 },
  core: { maxRequests: 1_000, windowMs: 60_000 },
};

function connector(origin: string, overrides: Record<string, string> = {}): GithubConnector {
  const registry = createConnectorRegistry(
    pocTestEnv({
      GITHUB_API_URL: origin,
      GITHUB_TOKEN: TOKEN,
      POC_GITHUB_MAX_SEARCH_PAGES: '2',
      SOURCE_HTTP_MAX_ATTEMPTS: '2',
      ...overrides,
    }),
    { logger: silentLogger, rateLimits: LIMITS, retryBaseDelayMs: 1 },
  );
  if (registry.github === null) throw new Error('GitHub connector disabled');
  return registry.github;
}

describe('GithubConnector', () => {
  let api: MockSource;

  beforeEach(async () => {
    api = await new MockSource().start();
  });

  afterEach(async () => {
    await api.stop();
  });

  it('searches a CVE ID in the configured fields and follows pagination up to the page limit', async () => {
    let page = 0;
    api.route('/search/repositories', (request) => {
      page += 1;
      const next = new URL(`${api.origin}/search/repositories`);
      next.searchParams.set('q', request.query.get('q') ?? '');
      next.searchParams.set('page', String(page + 1));
      return {
        headers: { link: `<${next.href}>; rel="next"` },
        body: {
          total_count: 250,
          incomplete_results: false,
          items: [githubRepo({ id: page, name: `CVE-2026-900001-poc-${String(page)}` })],
        },
      };
    });
    const github = connector(api.origin);
    const pages = [];
    for await (const result of github.searchCve('CVE-2026-900001', {})) pages.push(result);

    // maxSearchPages = 2 stops pagination although a next link exists.
    expect(pages).toHaveLength(2);
    expect(pages[0]?.totalCount).toBe(250);
    expect(pages[0]?.repositories[0]).toMatchObject({
      ok: true,
      repository: { fullName: 'zz-test-owner/CVE-2026-900001-poc-1' },
    });
    const requests = api.requestsTo('/search/repositories');
    expect(requests).toHaveLength(2);
    expect(requests[0]?.query.get('q')).toBe('"CVE-2026-900001" in:name,description,topics,readme');
    expect(requests[0]?.query.get('per_page')).toBe('100');
    expect(requests[1]?.query.get('page')).toBe('2');
    expect(requests[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(requests[0]?.headers['x-github-api-version']).toBeDefined();
  });

  it('refuses a pagination link that leaves the search endpoint', async () => {
    api.route('/search/repositories', () => ({
      headers: { link: `<${api.origin}/repos/zz-test-owner/x>; rel="next"` },
      body: { total_count: 1, incomplete_results: false, items: [] },
    }));
    const github = connector(api.origin);
    await expect(
      github.searchPage(github.searchUrl(github.cveQuery('CVE-2026-900002')), {}),
    ).rejects.toThrow(/outside the search endpoint/);
  });

  it('refuses a pagination link to another origin', async () => {
    api.route('/search/repositories', () => ({
      headers: { link: '<https://attacker.example/search/repositories?page=2>; rel="next"' },
      body: { total_count: 1, incomplete_results: false, items: [] },
    }));
    const github = connector(api.origin);
    await expect(
      github.searchPage(github.searchUrl(github.cveQuery('CVE-2026-900003')), {}),
    ).rejects.toBeInstanceOf(DisallowedUrlError);
  });

  it('builds a pushed-window query for the recent sweep', () => {
    const github = connector(api.origin);
    expect(
      github.recentQuery(new Date('2026-11-01T00:00:00.123Z'), new Date('2026-11-01T06:00:00Z')),
    ).toBe('CVE in:name,description,topics pushed:2026-11-01T00:00:00Z..2026-11-01T06:00:00Z');
  });

  it('reads the head commit and treats 409 as an empty repository', async () => {
    const commitSha = sha('commit');
    const treeSha = sha('tree');
    api.route('/repos/zz-test-owner/poc/commits/main', () => ({
      body: {
        sha: commitSha,
        commit: { tree: { sha: treeSha }, committer: { date: '2026-10-01T12:00:00Z' } },
      },
    }));
    api.route('/repos/zz-test-owner/empty/commits/main', () => ({
      status: 409,
      body: { message: 'Git Repository is empty.' },
    }));
    const github = connector(api.origin);
    await expect(github.headCommit('zz-test-owner/poc', 'main', {})).resolves.toEqual({
      kind: 'commit',
      sha: commitSha,
      treeSha,
      committedAt: new Date('2026-10-01T12:00:00Z'),
    });
    await expect(github.headCommit('zz-test-owner/empty', 'main', {})).resolves.toEqual({
      kind: 'empty',
    });
  });

  it('lists a tree recursively without requesting file contents', async () => {
    const treeSha = sha('tree');
    api.route(`/repos/zz-test-owner/poc/git/trees/${treeSha}`, () => ({
      body: {
        sha: treeSha,
        truncated: false,
        tree: [
          { path: 'exploit.py', mode: '100644', type: 'blob', sha: sha('blob'), size: 120 },
          { path: 'src', mode: '040000', type: 'tree', sha: sha('dir') },
        ],
      },
    }));
    const github = connector(api.origin);
    const listing = await github.tree('zz-test-owner/poc', treeSha, {});
    expect(listing.entries).toEqual([
      { path: 'exploit.py', mode: '100644', type: 'blob', sha: sha('blob'), size: 120 },
      { path: 'src', mode: '040000', type: 'tree', sha: sha('dir'), size: null },
    ]);
    expect(
      api.requestsTo(`/repos/zz-test-owner/poc/git/trees/${treeSha}`)[0]?.query.get('recursive'),
    ).toBe('1');
    expect(api.requests.every((request) => !request.path.includes('/contents/'))).toBe(true);
    await expect(github.tree('zz-test-owner/poc', '../../etc', {})).rejects.toThrow(
      /Invalid tree SHA/,
    );
  });

  it('reports deleted repositories as unavailable', async () => {
    api.route('/repositories/42', () => ({ status: 404, body: { message: 'Not Found' } }));
    const github = connector(api.origin);
    const error: unknown = await github.repository('42', {}).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(SourceHttpError);
    expect(isUnavailable(error)).toBe(true);
    await expect(github.repository('../42', {})).rejects.toThrow(/Invalid GitHub repository ID/);
  });

  it('retries server errors before failing', async () => {
    api.sequence('/repositories/7', [
      { status: 503 },
      { body: githubRepo({ id: 7, name: 'retried' }) },
    ]);
    const github = connector(api.origin);
    await expect(github.repository('7', {})).resolves.toMatchObject({ ok: true });
    expect(api.requestsTo('/repositories/7')).toHaveLength(2);
  });

  it('sends no authorization header without a token', async () => {
    api.route('/repositories/8', () => ({ body: githubRepo({ id: 8, name: 'anon' }) }));
    const registry = createConnectorRegistry(pocTestEnv({ GITHUB_API_URL: api.origin }), {
      logger: silentLogger,
      rateLimits: LIMITS,
    });
    expect(registry.github?.authenticated).toBe(false);
    await registry.github?.repository('8', {});
    expect(api.requestsTo('/repositories/8')[0]?.headers.authorization).toBeUndefined();
  });

  it('is absent when the connector is not enabled', () => {
    const registry = createConnectorRegistry(pocTestEnv({ POC_CONNECTORS_ENABLED: 'none' }), {
      logger: silentLogger,
    });
    expect(registry.github).toBeNull();
    expect(registry.referencesEnabled).toBe(false);
    expect(registry.info.every((info) => !info.enabled)).toBe(true);
  });
});

describe('mapGithubRepository', () => {
  it('builds the canonical URL itself and sanitises the description', () => {
    const mapped = mapGithubRepository({
      ...githubRepo({ id: 1, name: 'poc' }),
      html_url: 'https://attacker.example/phish',
      description: 'PoC‮ for CVE-2026-900001 \u0007<script>',
      topics: ['cve-2026-900001', 'INVALID TOPIC'],
    });
    expect(mapped.ok).toBe(true);
    if (!mapped.ok) return;
    expect(mapped.repository.url).toBe('https://github.com/zz-test-owner/poc');
    const description = mapped.repository.description ?? '';
    expect(description.includes('\u202e')).toBe(false);
    expect(description.includes('\u0007')).toBe(false);
    expect(mapped.repository.topics).toEqual(['cve-2026-900001']);
  });

  it('refuses private repositories and mismatched names', () => {
    expect(mapGithubRepository({ ...githubRepo({ id: 2, name: 'p' }), private: true })).toEqual({
      ok: false,
      externalId: '2',
      issue: 'private repository',
    });
    expect(
      mapGithubRepository({ ...githubRepo({ id: 3, name: 'p' }), full_name: 'other/p' }),
    ).toMatchObject({ ok: false, issue: 'full_name does not match owner and name' });
    expect(mapGithubRepository({ id: 4 })).toMatchObject({ ok: false, externalId: '4' });
  });
});
