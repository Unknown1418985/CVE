import { z } from 'zod';

import { validateCveId } from '@cve/contracts';

import type { SourceHttpClient } from '../../http/source-http-client.js';
import { sanitizeCveContent, sourceTimestamp, type CveContentDraft } from '../cve-content.js';
import type {
  AdapterDescription,
  AdapterRunContext,
  CveRecordItem,
  InvalidItem,
  SourceAdapter,
  SyncBatch,
} from '../source-adapter.js';

export const GITHUB_MAX_PAGE_SIZE = 100;
const SOURCE = 'github-advisory';

const cvssSchema = z
  .object({
    vector_string: z.string().nullable().optional(),
    score: z.number().nullable().optional(),
  })
  .nullable()
  .optional();

const advisorySchema = z.looseObject({
  ghsa_id: z.string().regex(/^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/),
  cve_id: z.string().nullable().optional(),
  html_url: z.string().optional(),
  summary: z.string().nullable().optional(),
  description: z.string().nullable().optional(),
  type: z.string().optional(),
  published_at: z.string().nullable().optional(),
  updated_at: z.string(),
  withdrawn_at: z.string().nullable().optional(),
  references: z.array(z.string()).nullable().optional(),
  cvss_severities: z.object({ cvss_v3: cvssSchema, cvss_v4: cvssSchema }).nullable().optional(),
  cwes: z
    .array(z.object({ cwe_id: z.string() }))
    .nullable()
    .optional(),
  vulnerabilities: z
    .array(
      z.looseObject({
        package: z
          .object({ ecosystem: z.string(), name: z.string().nullable() })
          .nullable()
          .optional(),
        vulnerable_version_range: z.string().nullable().optional(),
      }),
    )
    .nullable()
    .optional(),
});
type Advisory = z.infer<typeof advisorySchema>;

export const advisoryListSchema = z.array(z.unknown());

export const githubCursorSchema = z.object({
  /** Newest `updated_at` synchronised; the next run asks for `updated >= this`. */
  updatedSince: z.iso.datetime(),
});
export type GithubCursor = z.infer<typeof githubCursorSchema>;

export const githubCheckpointSchema = z.object({
  updatedSince: z.iso.datetime(),
  /** Next page (`Link: rel="next"`); null when the run has read the last page. */
  nextUrl: z.string().max(4096).nullable(),
  maxUpdatedAt: z.iso.datetime().nullable(),
});
export type GithubCheckpoint = z.infer<typeof githubCheckpointSchema>;

export interface GithubAdvisoryAdapterOptions {
  readonly client: SourceHttpClient;
  /** `https://api.github.com` */
  readonly apiUrl: string;
  readonly token: string | undefined;
  readonly pageSize: number;
  /** First run without a cursor synchronises advisories updated after this time. */
  readonly initialLookbackMs: number;
}

/** `x-ratelimit-remaining: 0` → pause until `x-ratelimit-reset` (epoch seconds). */
export function githubQuotaReset(headers: Headers): number | undefined {
  if (headers.get('x-ratelimit-remaining') !== '0') return undefined;
  const reset = Number(headers.get('x-ratelimit-reset'));
  return Number.isFinite(reset) && reset > 0 ? reset * 1_000 : undefined;
}

/** Extracts the `rel="next"` target from a `Link` header. */
export function nextLink(header: string | null): string | null {
  if (header === null) return null;
  for (const part of header.split(',')) {
    const match = /<([^>]+)>\s*;\s*rel="?next"?/.exec(part.trim());
    if (match?.[1] !== undefined) return match[1];
  }
  return null;
}

interface Bounds {
  version?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

/** Parses a GitHub range such as `>= 1.0.0, < 1.2.3` or `= 2.0.0`; null when unrecognised. */
export function parseVersionRange(range: string): Bounds | null {
  const bounds: Bounds = {};
  for (const part of range.split(',')) {
    const match = /^\s*(>=|<=|>|<|=)\s*(\S+)\s*$/.exec(part);
    if (match === null) return null;
    const [, operator, version = ''] = match;
    if (operator === '>=') bounds.versionStartIncluding = version;
    else if (operator === '>') bounds.versionStartExcluding = version;
    else if (operator === '<=') bounds.versionEndIncluding = version;
    else if (operator === '<') bounds.versionEndExcluding = version;
    else bounds.version = version;
  }
  return bounds;
}

export function mapAdvisory(advisory: Advisory): { draft: CveContentDraft; issues: string[] } {
  const issues: string[] = [];
  const cvssMetrics = [];
  const v4 = advisory.cvss_severities?.cvss_v4;
  if (v4?.vector_string) {
    cvssMetrics.push({
      version: '4.0' as const,
      source: SOURCE,
      type: 'secondary' as const,
      vectorString: v4.vector_string,
      ...(v4.score === null || v4.score === undefined ? {} : { baseScore: v4.score }),
    });
  }
  const v3 = advisory.cvss_severities?.cvss_v3;
  if (v3?.vector_string) {
    if (v3.vector_string.startsWith('CVSS:3.1/')) {
      cvssMetrics.push({
        version: '3.1' as const,
        source: SOURCE,
        type: 'secondary' as const,
        vectorString: v3.vector_string,
      });
    } else {
      issues.push(
        'cvssMetrics: only CVSS 3.1 vectors are stored; the advisory has another 3.x version',
      );
    }
  }
  const affectedProducts = (advisory.vulnerabilities ?? []).flatMap((vulnerability, index) => {
    const pkg = vulnerability.package;
    if (!pkg?.name || pkg.name.trim() === '') return [];
    const base = {
      vendor: pkg.ecosystem,
      product: pkg.name,
      status: 'affected' as const,
      source: SOURCE,
    };
    const range = vulnerability.vulnerable_version_range;
    if (range === null || range === undefined || range.trim() === '') return [base];
    const bounds = parseVersionRange(range);
    if (bounds === null) {
      issues.push(`vulnerabilities[${index}]: unrecognised version range "${range.slice(0, 100)}"`);
      return [base];
    }
    return [{ ...base, ...bounds }];
  });
  const references = [
    ...(advisory.html_url === undefined ? [] : [advisory.html_url]),
    ...(advisory.references ?? []),
  ];
  return {
    issues,
    draft: {
      state: 'published',
      title: advisory.summary ?? null,
      description: advisory.description ?? advisory.summary ?? null,
      assigner: null,
      publishedAt: sourceTimestamp(advisory.published_at),
      lastModifiedAt: sourceTimestamp(advisory.updated_at),
      source: SOURCE,
      cvssMetrics,
      weaknesses: (advisory.cwes ?? []).map((cwe) => ({ cweId: cwe.cwe_id, source: SOURCE })),
      references: [...new Set(references)].map((url) => ({ url, source: SOURCE, tags: [] })),
      affectedProducts,
    },
  };
}

export function advisoryItem(raw: unknown): CveRecordItem | InvalidItem {
  const parsed = advisorySchema.safeParse(raw);
  const rawId =
    raw !== null && typeof raw === 'object' && 'ghsa_id' in raw && typeof raw.ghsa_id === 'string'
      ? raw.ghsa_id.slice(0, 64)
      : null;
  if (!parsed.success) {
    return {
      externalId: rawId,
      issue: `unexpected advisory format: ${parsed.error.issues[0]?.message ?? ''}`,
    };
  }
  const advisory = parsed.data;
  const issues: string[] = [];
  let cveId: string | null = null;
  if (advisory.cve_id !== null && advisory.cve_id !== undefined) {
    const id = validateCveId(advisory.cve_id);
    if (id.ok) cveId = id.cveId;
    else issues.push(`cve_id ignored: ${id.reason}`);
  }
  const sourceModified = sourceTimestamp(advisory.updated_at);
  const base = {
    externalId: advisory.ghsa_id,
    cveId,
    sourceUrl: advisory.html_url ?? `https://github.com/advisories/${advisory.ghsa_id}`,
    sourceModifiedAt: sourceModified === null ? null : new Date(sourceModified),
    raw,
  };
  if (advisory.withdrawn_at !== null && advisory.withdrawn_at !== undefined) {
    return { ...base, content: null, withdrawn: true, issues };
  }
  const { draft, issues: mappingIssues } = mapAdvisory(advisory);
  const sanitized = sanitizeCveContent(draft);
  if (!sanitized.ok) return { externalId: advisory.ghsa_id, issue: sanitized.error };
  return {
    ...base,
    content: sanitized.content,
    issues: [
      ...issues,
      ...mappingIssues,
      ...sanitized.dropped,
      ...sanitized.truncated.map((field) => `${field} truncated to the CVE Service limit`),
    ],
  };
}

/**
 * GitHub Advisory Database adapter (REST `GET /advisories`, reviewed advisories). Incremental by
 * `updated`, sorted ascending, paginated with the `Link` header (cursor pagination). The token
 * is optional; without it GitHub allows 60 requests per hour.
 */
export class GithubAdvisoryAdapter implements SourceAdapter<GithubCursor, GithubCheckpoint> {
  readonly source = 'github-advisory' as const;
  readonly cursorSchema = githubCursorSchema;
  readonly checkpointSchema = githubCheckpointSchema;

  constructor(private readonly options: GithubAdvisoryAdapterOptions) {
    options.client.assertAllowed(options.apiUrl);
    if (options.pageSize < 1 || options.pageSize > GITHUB_MAX_PAGE_SIZE) {
      throw new Error(`GitHub page size must be between 1 and ${GITHUB_MAX_PAGE_SIZE}`);
    }
  }

  describe(): AdapterDescription {
    return {
      baseUrl: this.options.apiUrl,
      authentication: { mode: 'optional', configured: this.options.token !== undefined },
      rateLimit: this.options.client.rateLimit,
    };
  }

  firstPageUrl(updatedSince: string): string {
    const url = new URL(`${this.options.apiUrl.replace(/\/+$/, '')}/advisories`);
    url.searchParams.set('type', 'reviewed');
    url.searchParams.set('sort', 'updated');
    url.searchParams.set('direction', 'asc');
    url.searchParams.set('per_page', String(this.options.pageSize));
    // GitHub expects the search date syntax; seconds precision.
    url.searchParams.set('updated', `>=${updatedSince.replace(/\.\d{3}Z$/, 'Z')}`);
    return url.href;
  }

  /** Pagination links come from the response: they must stay on the advisories endpoint. */
  private checkedNextUrl(link: string | null): string | null {
    if (link === null) return null;
    const url = this.options.client.assertAllowed(link);
    if (url.pathname !== new URL(this.firstPageUrl(new Date(0).toISOString())).pathname) {
      throw new Error('GitHub pagination link points outside the advisories endpoint');
    }
    return url.href;
  }

  async *sync(
    context: AdapterRunContext<GithubCursor, GithubCheckpoint>,
  ): AsyncGenerator<SyncBatch<GithubCheckpoint>, GithubCursor, void> {
    const updatedSince =
      context.cursor?.updatedSince ??
      new Date(context.now.getTime() - this.options.initialLookbackMs).toISOString();
    let checkpoint: GithubCheckpoint = context.checkpoint ?? {
      updatedSince,
      nextUrl: this.firstPageUrl(updatedSince),
      maxUpdatedAt: null,
    };
    const headers: Record<string, string> = {
      'x-github-api-version': '2022-11-28',
      ...(this.options.token === undefined
        ? {}
        : { authorization: `Bearer ${this.options.token}` }),
    };
    while (checkpoint.nextUrl !== null) {
      const response = await this.options.client.getJson(checkpoint.nextUrl, advisoryListSchema, {
        signal: context.signal,
        meter: context.meter,
        accept: ['application/json'],
        headers: { ...headers, accept: 'application/vnd.github+json' },
      });
      const items = response.body.map(advisoryItem);
      const records = items.filter((item): item is CveRecordItem => !('issue' in item));
      let maxUpdatedAt = checkpoint.maxUpdatedAt;
      for (const record of records) {
        const updated = record.sourceModifiedAt?.toISOString();
        if (updated !== undefined && (maxUpdatedAt === null || updated > maxUpdatedAt)) {
          maxUpdatedAt = updated;
        }
      }
      checkpoint = {
        updatedSince: checkpoint.updatedSince,
        nextUrl: this.checkedNextUrl(nextLink(response.headers.get('link'))),
        maxUpdatedAt,
      };
      yield {
        kind: 'cve-records',
        records,
        invalid: items.filter((item): item is InvalidItem => 'issue' in item),
        checkpoint,
      };
    }
    return { updatedSince: checkpoint.maxUpdatedAt ?? checkpoint.updatedSince };
  }
}
