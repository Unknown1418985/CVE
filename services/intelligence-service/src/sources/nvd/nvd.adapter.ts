import { z } from 'zod';

import { validateCveId } from '@cve/contracts';

import type { SourceHttpClient } from '../../http/source-http-client.js';
import {
  parseCpe23,
  sanitizeCveContent,
  sourceIdentifier,
  sourceTimestamp,
  type CveContentDraft,
} from '../cve-content.js';
import type {
  AdapterDescription,
  AdapterRunContext,
  CveRecordItem,
  InvalidItem,
  SourceAdapter,
  SyncBatch,
} from '../source-adapter.js';

/** NVD allows at most 120 consecutive days per `lastModStartDate`/`lastModEndDate` query. */
export const NVD_MAX_RANGE_MS = 120 * 24 * 60 * 60 * 1000;
export const NVD_MAX_PAGE_SIZE = 2_000;
/** Re-read a little before the cursor so records modified during the last run are not missed. */
const CURSOR_OVERLAP_MS = 5 * 60 * 1000;

const localizedTextSchema = z.object({ lang: z.string(), value: z.string() });

const cvssMetricSchema = z.object({
  source: z.string(),
  type: z.string(),
  cvssData: z.looseObject({ version: z.string(), vectorString: z.string(), baseScore: z.number() }),
});

const cpeMatchSchema = z.object({
  vulnerable: z.boolean(),
  criteria: z.string(),
  versionStartIncluding: z.string().optional(),
  versionStartExcluding: z.string().optional(),
  versionEndIncluding: z.string().optional(),
  versionEndExcluding: z.string().optional(),
});

const nvdCveSchema = z.looseObject({
  id: z.string(),
  sourceIdentifier: z.string().optional(),
  published: z.string().optional(),
  lastModified: z.string().optional(),
  vulnStatus: z.string().optional(),
  descriptions: z.array(localizedTextSchema).default([]),
  metrics: z
    .looseObject({
      cvssMetricV31: z.array(cvssMetricSchema).optional(),
      cvssMetricV40: z.array(cvssMetricSchema).optional(),
    })
    .optional(),
  weaknesses: z
    .array(z.object({ source: z.string(), description: z.array(localizedTextSchema).default([]) }))
    .optional(),
  configurations: z
    .array(
      z.object({
        nodes: z.array(z.object({ cpeMatch: z.array(cpeMatchSchema).default([]) })).default([]),
      }),
    )
    .optional(),
  references: z
    .array(
      z.object({
        url: z.string(),
        source: z.string().optional(),
        tags: z.array(z.string()).optional(),
      }),
    )
    .optional(),
});
type NvdCve = z.infer<typeof nvdCveSchema>;

export const nvdResponseSchema = z.object({
  resultsPerPage: z.number().int().min(0),
  startIndex: z.number().int().min(0),
  totalResults: z.number().int().min(0),
  vulnerabilities: z.array(z.object({ cve: z.unknown() })),
});

export const nvdCursorSchema = z.object({ lastModifiedThrough: z.iso.datetime() });
export type NvdCursor = z.infer<typeof nvdCursorSchema>;

export const nvdCheckpointSchema = z.object({
  /** Start of the current window; null for a full (unfiltered) synchronisation. */
  windowStart: z.iso.datetime().nullable(),
  /** End of the whole run; fixed at the start so a resumed run covers the same range. */
  runEnd: z.iso.datetime(),
  startIndex: z.number().int().min(0),
});
export type NvdCheckpoint = z.infer<typeof nvdCheckpointSchema>;

export interface NvdAdapterOptions {
  readonly client: SourceHttpClient;
  /** `https://services.nvd.nist.gov/rest/json/cves/2.0` */
  readonly baseUrl: string;
  readonly apiKey: string | undefined;
  readonly pageSize: number;
  /** First run without a cursor: start here, or synchronise the whole catalog when undefined. */
  readonly initialSyncFrom: Date | undefined;
}

function english(texts: readonly { lang: string; value: string }[]): string | null {
  return (
    (texts.find((text) => text.lang.toLowerCase().startsWith('en')) ?? texts[0])?.value ?? null
  );
}

/** Maps one NVD CVE to the CVE Service write model (provenance on every element). */
export function mapNvdCve(cve: NvdCve): { draft: CveContentDraft; issues: string[] } {
  const issues: string[] = [];
  const metric = (version: '3.1' | '4.0') => (m: z.infer<typeof cvssMetricSchema>) => ({
    version,
    source: sourceIdentifier(m.source) ?? 'nvd',
    type: m.type.toLowerCase() === 'primary' ? ('primary' as const) : ('secondary' as const),
    vectorString: m.cvssData.vectorString,
    baseScore: m.cvssData.baseScore,
  });
  const weaknesses = (cve.weaknesses ?? []).flatMap((w) =>
    w.description.map((d) => ({ cweId: d.value, source: sourceIdentifier(w.source) ?? 'nvd' })),
  );
  const affectedProducts = (cve.configurations ?? [])
    .flatMap((configuration) => configuration.nodes)
    .flatMap((node) => node.cpeMatch)
    // `vulnerable: false` entries describe the platform a product runs on, not affected products.
    .filter((match) => match.vulnerable)
    .flatMap((match) => {
      const cpe = parseCpe23(match.criteria);
      if (cpe === null) {
        issues.push(`affectedProducts: unparseable CPE "${match.criteria.slice(0, 200)}"`);
        return [];
      }
      const ranged =
        match.versionStartIncluding ??
        match.versionStartExcluding ??
        match.versionEndIncluding ??
        match.versionEndExcluding;
      return [
        {
          vendor: cpe.vendor,
          product: cpe.product,
          cpe: match.criteria,
          ...(ranged === undefined && cpe.version !== null ? { version: cpe.version } : {}),
          ...(match.versionStartIncluding === undefined
            ? {}
            : { versionStartIncluding: match.versionStartIncluding }),
          ...(match.versionStartExcluding === undefined
            ? {}
            : { versionStartExcluding: match.versionStartExcluding }),
          ...(match.versionEndIncluding === undefined
            ? {}
            : { versionEndIncluding: match.versionEndIncluding }),
          ...(match.versionEndExcluding === undefined
            ? {}
            : { versionEndExcluding: match.versionEndExcluding }),
          status: 'affected' as const,
          source: 'nvd',
        },
      ];
    });
  return {
    issues,
    draft: {
      state: cve.vulnStatus?.toLowerCase() === 'rejected' ? 'rejected' : 'published',
      title: null,
      description: english(cve.descriptions),
      assigner: cve.sourceIdentifier ?? null,
      publishedAt: sourceTimestamp(cve.published),
      lastModifiedAt: sourceTimestamp(cve.lastModified),
      source: 'nvd',
      cvssMetrics: [
        ...(cve.metrics?.cvssMetricV40 ?? []).map(metric('4.0')),
        ...(cve.metrics?.cvssMetricV31 ?? []).map(metric('3.1')),
      ],
      weaknesses,
      references: (cve.references ?? []).map((reference) => ({
        url: reference.url,
        source: sourceIdentifier(reference.source) ?? 'nvd',
        tags: (reference.tags ?? []).slice(0, 20),
      })),
      affectedProducts,
    },
  };
}

/** Turns one entry of `vulnerabilities[]` into a record item, or an invalid-item report. */
export function nvdItem(raw: unknown): CveRecordItem | InvalidItem {
  const parsed = nvdCveSchema.safeParse(raw);
  const rawId =
    raw !== null && typeof raw === 'object' && 'id' in raw && typeof raw.id === 'string'
      ? raw.id
      : null;
  if (!parsed.success) {
    return {
      externalId: rawId,
      issue: `unexpected NVD record format: ${parsed.error.issues[0]?.message ?? ''}`,
    };
  }
  const cve = parsed.data;
  const id = validateCveId(cve.id);
  if (!id.ok) return { externalId: cve.id, issue: `invalid CVE ID: ${id.reason}` };
  const { draft, issues } = mapNvdCve(cve);
  const sanitized = sanitizeCveContent(draft);
  if (!sanitized.ok) return { externalId: id.cveId, issue: sanitized.error };
  return {
    externalId: id.cveId,
    cveId: id.cveId,
    sourceUrl: `https://nvd.nist.gov/vuln/detail/${id.cveId}`,
    sourceModifiedAt: draft.lastModifiedAt === null ? null : new Date(draft.lastModifiedAt),
    content: sanitized.content,
    raw,
    issues: [
      ...issues,
      ...sanitized.dropped,
      ...sanitized.truncated.map((field) => `${field} truncated to the CVE Service limit`),
    ],
  };
}

function isInvalid(item: CveRecordItem | InvalidItem): item is InvalidItem {
  return 'issue' in item;
}

/**
 * NVD CVE API 2.0 adapter. Incremental by `lastModStartDate`/`lastModEndDate` (windows of at
 * most 120 days), paginated by `startIndex`. Sends the API key in the `apiKey` header.
 */
export class NvdAdapter implements SourceAdapter<NvdCursor, NvdCheckpoint> {
  readonly source = 'nvd' as const;
  readonly cursorSchema = nvdCursorSchema;
  readonly checkpointSchema = nvdCheckpointSchema;

  constructor(private readonly options: NvdAdapterOptions) {
    if (options.pageSize < 1 || options.pageSize > NVD_MAX_PAGE_SIZE) {
      throw new Error(`NVD page size must be between 1 and ${NVD_MAX_PAGE_SIZE}`);
    }
    options.client.assertAllowed(options.baseUrl);
  }

  describe(): AdapterDescription {
    return {
      baseUrl: this.options.baseUrl,
      authentication: { mode: 'optional', configured: this.options.apiKey !== undefined },
      rateLimit: this.options.client.rateLimit,
    };
  }

  private initialCheckpoint(context: AdapterRunContext<NvdCursor, NvdCheckpoint>): NvdCheckpoint {
    const runEnd = context.now.toISOString();
    if (context.cursor !== null) {
      const start = new Date(Date.parse(context.cursor.lastModifiedThrough) - CURSOR_OVERLAP_MS);
      return { windowStart: start.toISOString(), runEnd, startIndex: 0 };
    }
    return {
      windowStart: this.options.initialSyncFrom?.toISOString() ?? null,
      runEnd,
      startIndex: 0,
    };
  }

  pageUrl(checkpoint: NvdCheckpoint): string {
    const url = new URL(this.options.baseUrl);
    url.searchParams.set('resultsPerPage', String(this.options.pageSize));
    url.searchParams.set('startIndex', String(checkpoint.startIndex));
    if (checkpoint.windowStart !== null) {
      const start = Date.parse(checkpoint.windowStart);
      const end = Math.min(start + NVD_MAX_RANGE_MS, Date.parse(checkpoint.runEnd));
      url.searchParams.set('lastModStartDate', new Date(start).toISOString());
      url.searchParams.set('lastModEndDate', new Date(end).toISOString());
    }
    return url.href;
  }

  async *sync(
    context: AdapterRunContext<NvdCursor, NvdCheckpoint>,
  ): AsyncGenerator<SyncBatch<NvdCheckpoint>, NvdCursor, void> {
    let checkpoint = context.checkpoint ?? this.initialCheckpoint(context);
    for (;;) {
      const response = await this.options.client.getJson(
        this.pageUrl(checkpoint),
        nvdResponseSchema,
        {
          signal: context.signal,
          meter: context.meter,
          ...(this.options.apiKey === undefined
            ? {}
            : { headers: { apiKey: this.options.apiKey } }),
        },
      );
      const page = response.body;
      const items = page.vulnerabilities.map((entry) => nvdItem(entry.cve));
      const nextIndex = checkpoint.startIndex + page.vulnerabilities.length;
      let next: NvdCheckpoint | null;
      if (page.vulnerabilities.length > 0 && nextIndex < page.totalResults) {
        next = { ...checkpoint, startIndex: nextIndex };
      } else if (checkpoint.windowStart !== null) {
        const windowEnd = Date.parse(checkpoint.windowStart) + NVD_MAX_RANGE_MS;
        next =
          windowEnd < Date.parse(checkpoint.runEnd)
            ? { ...checkpoint, windowStart: new Date(windowEnd).toISOString(), startIndex: 0 }
            : null;
      } else {
        next = null;
      }
      yield {
        kind: 'cve-records',
        records: items.filter((item): item is CveRecordItem => !isInvalid(item)),
        invalid: items.filter(isInvalid),
        // After the last page the checkpoint points past the end, so a resume finishes at once.
        checkpoint: next ?? { ...checkpoint, startIndex: Math.max(nextIndex, page.totalResults) },
      };
      if (next === null) return { lastModifiedThrough: checkpoint.runEnd };
      checkpoint = next;
    }
  }
}
