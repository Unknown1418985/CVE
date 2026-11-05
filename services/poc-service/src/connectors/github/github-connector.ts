import { z } from 'zod';

import {
  githubHeaders,
  nextLink,
  SourceHttpError,
  type RequestMeter,
  type SourceHttpClient,
} from '@cve/source-http';

import type { TreeEntry } from '../../domain/files.js';
import { mapGithubRepository, type MappedRepository } from './github-mapping.js';
import {
  githubCommitSchema,
  githubSearchResponseSchema,
  githubTreeSchema,
} from './github-schemas.js';

/** GitHub returns at most 1 000 results per search query (10 pages of 100). */
export const GITHUB_SEARCH_RESULT_LIMIT = 1_000;
export const GITHUB_SEARCH_PAGE_SIZE = 100;

export interface GithubConnectorOptions {
  /** Client of the search API (its own, much smaller quota). */
  readonly searchClient: SourceHttpClient;
  /** Client of the core API (repositories, commits, trees). */
  readonly coreClient: SourceHttpClient;
  /** `https://api.github.com` */
  readonly apiUrl: string;
  readonly token: string | undefined;
  /** Fields searched for a CVE ID, e.g. `name,description,topics,readme`. */
  readonly searchIn: readonly string[];
  /** Pages requested per CVE search (each up to 100 repositories). */
  readonly maxSearchPages: number;
}

export interface SearchPage {
  readonly totalCount: number;
  readonly incomplete: boolean;
  readonly repositories: readonly MappedRepository[];
  readonly nextUrl: string | null;
}

export type HeadCommit =
  | {
      readonly kind: 'commit';
      readonly sha: string;
      readonly treeSha: string;
      readonly committedAt: Date | null;
    }
  | { readonly kind: 'empty' };

export interface TreeListing {
  readonly sha: string;
  readonly truncated: boolean;
  readonly entries: readonly TreeEntry[];
}

/** HTTP statuses meaning the repository is no longer served (deleted, private, DMCA). */
const UNAVAILABLE_STATUSES = new Set([404, 410, 451]);

export function isUnavailable(error: unknown): boolean {
  return error instanceof SourceHttpError && UNAVAILABLE_STATUSES.has(error.status);
}

/**
 * GitHub connector (REST API, metadata only). It searches repositories, reads repository
 * metadata, the head commit and the tree listing (names, modes and blob IDs). It never requests
 * file contents, archives or clones, and nothing it returns is executed.
 */
export class GithubConnector {
  private readonly apiUrl: string;

  constructor(private readonly options: GithubConnectorOptions) {
    options.searchClient.assertAllowed(options.apiUrl);
    options.coreClient.assertAllowed(options.apiUrl);
    this.apiUrl = options.apiUrl.replace(/\/+$/, '');
    if (options.maxSearchPages < 1 || options.maxSearchPages > 10) {
      throw new Error('maxSearchPages must be between 1 and 10');
    }
  }

  get authenticated(): boolean {
    return this.options.token !== undefined;
  }

  private headers() {
    return githubHeaders(this.options.token);
  }

  /** Query for repositories mentioning one CVE ID. */
  cveQuery(cveId: string): string {
    return `"${cveId}" in:${this.options.searchIn.join(',')}`;
  }

  /** Query for repositories mentioning CVEs pushed within `[from, to)` (seconds precision). */
  recentQuery(from: Date, to: Date): string {
    const format = (date: Date) => date.toISOString().replace(/\.\d{3}Z$/, 'Z');
    return `CVE in:name,description,topics pushed:${format(from)}..${format(to)}`;
  }

  searchUrl(query: string, sort?: 'updated'): string {
    const url = new URL(`${this.apiUrl}/search/repositories`);
    url.searchParams.set('q', query);
    url.searchParams.set('per_page', String(GITHUB_SEARCH_PAGE_SIZE));
    if (sort !== undefined) {
      url.searchParams.set('sort', sort);
      url.searchParams.set('order', 'asc');
    }
    return url.href;
  }

  /** Pagination links must stay on the search endpoint of the configured API. */
  private checkedNextUrl(link: string | null): string | null {
    if (link === null) return null;
    const url = this.options.searchClient.assertAllowed(link);
    if (url.pathname !== new URL(`${this.apiUrl}/search/repositories`).pathname) {
      throw new Error('GitHub pagination link points outside the search endpoint');
    }
    return url.href;
  }

  async searchPage(
    url: string,
    options: { signal?: AbortSignal; meter?: RequestMeter },
  ): Promise<SearchPage> {
    const response = await this.options.searchClient.getJson(url, githubSearchResponseSchema, {
      ...options,
      headers: this.headers(),
      accept: ['application/json'],
    });
    return {
      totalCount: response.body.total_count,
      incomplete: response.body.incomplete_results,
      repositories: response.body.items.map(mapGithubRepository),
      nextUrl: this.checkedNextUrl(nextLink(response.headers.get('link'))),
    };
  }

  /** Every page of a CVE search, up to `maxSearchPages`. */
  async *searchCve(
    cveId: string,
    options: { signal?: AbortSignal; meter?: RequestMeter },
  ): AsyncGenerator<SearchPage> {
    let url: string | null = this.searchUrl(this.cveQuery(cveId));
    for (let page = 0; url !== null && page < this.options.maxSearchPages; page += 1) {
      const result = await this.searchPage(url, options);
      yield result;
      url = result.nextUrl;
    }
  }

  /** Repository metadata by its stable ID (follows renames and transfers). */
  async repository(
    externalId: string,
    options: { signal?: AbortSignal; meter?: RequestMeter },
  ): Promise<MappedRepository> {
    if (!/^[1-9]\d{0,19}$/.test(externalId)) throw new Error('Invalid GitHub repository ID');
    const response = await this.options.coreClient.getJson(
      `${this.apiUrl}/repositories/${externalId}`,
      // Validated by mapGithubRepository, which reports issues instead of failing.
      z.unknown(),
      { ...options, headers: this.headers() },
    );
    return mapGithubRepository(response.body);
  }

  /** Repository metadata by `owner/name` (used for references found in CVE records). */
  async repositoryByName(
    owner: string,
    name: string,
    options: { signal?: AbortSignal; meter?: RequestMeter },
  ): Promise<MappedRepository> {
    const response = await this.options.coreClient.getJson(
      `${this.apiUrl}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`,
      z.unknown(),
      { ...options, headers: this.headers() },
    );
    return mapGithubRepository(response.body);
  }

  /** Head commit of a branch; `empty` for a repository without commits. */
  async headCommit(
    fullName: string,
    branch: string,
    options: { signal?: AbortSignal; meter?: RequestMeter },
  ): Promise<HeadCommit> {
    try {
      const response = await this.options.coreClient.getJson(
        `${this.apiUrl}/repos/${fullName}/commits/${encodeURIComponent(branch)}`,
        githubCommitSchema,
        { ...options, headers: this.headers() },
      );
      const date = response.body.commit.committer?.date;
      const parsed = date === undefined ? NaN : Date.parse(date);
      return {
        kind: 'commit',
        sha: response.body.sha,
        treeSha: response.body.commit.tree.sha,
        committedAt: Number.isNaN(parsed) ? null : new Date(parsed),
      };
    } catch (error) {
      // 409 Conflict: "Git Repository is empty."
      if (error instanceof SourceHttpError && error.status === 409) return { kind: 'empty' };
      throw error;
    }
  }

  /** Recursive tree listing (names, modes, blob IDs and sizes; never contents). */
  async tree(
    fullName: string,
    treeSha: string,
    options: { signal?: AbortSignal; meter?: RequestMeter },
  ): Promise<TreeListing> {
    if (!/^[0-9a-f]{40}$/.test(treeSha)) throw new Error('Invalid tree SHA');
    const response = await this.options.coreClient.getJson(
      `${this.apiUrl}/repos/${fullName}/git/trees/${treeSha}?recursive=1`,
      githubTreeSchema,
      { ...options, headers: this.headers() },
    );
    return {
      sha: response.body.sha,
      truncated: response.body.truncated,
      entries: response.body.tree.map((entry) => ({
        path: entry.path,
        mode: entry.mode,
        type: entry.type,
        sha: entry.sha,
        size: entry.size ?? null,
      })),
    };
  }
}
