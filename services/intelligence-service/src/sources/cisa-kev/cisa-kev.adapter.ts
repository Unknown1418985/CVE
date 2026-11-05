import { z } from 'zod';

import { kevStatusInputSchema, normalizeCweId, validateCveId } from '@cve/contracts';
import type { SourceHttpClient } from '@cve/source-http';

import { cleanText, sourceTimestamp } from '../cve-content.js';
import type {
  AdapterDescription,
  AdapterRunContext,
  InvalidItem,
  KevItem,
  SourceAdapter,
  SyncBatch,
} from '../source-adapter.js';

const kevVulnerabilitySchema = z.looseObject({
  cveID: z.string(),
  vendorProject: z.string().optional(),
  product: z.string().optional(),
  vulnerabilityName: z.string().optional(),
  dateAdded: z.string(),
  shortDescription: z.string().optional(),
  requiredAction: z.string().optional(),
  dueDate: z.string().optional(),
  knownRansomwareCampaignUse: z.string().optional(),
  notes: z.string().optional(),
  cwes: z.array(z.string()).optional(),
});

export const kevCatalogSchema = z.looseObject({
  catalogVersion: z.string().min(1).max(64),
  dateReleased: z.string().optional(),
  count: z.number().int().min(0).optional(),
  vulnerabilities: z.array(z.unknown()),
});

export const kevCursorSchema = z.object({
  catalogVersion: z.string().max(64),
  etag: z.string().max(256).optional(),
  lastModified: z.string().max(64).optional(),
});
export type KevCursor = z.infer<typeof kevCursorSchema>;

/** The catalog is one document, so a run has nothing to resume. */
export const kevCheckpointSchema = z.object({});
export type KevCheckpoint = z.infer<typeof kevCheckpointSchema>;

export interface CisaKevAdapterOptions {
  readonly client: SourceHttpClient;
  /** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` */
  readonly feedUrl: string;
}

const DATE = /^\d{4}-\d{2}-\d{2}$/;

export function kevItem(raw: unknown): KevItem | InvalidItem {
  const parsed = kevVulnerabilitySchema.safeParse(raw);
  const rawId =
    raw !== null && typeof raw === 'object' && 'cveID' in raw && typeof raw.cveID === 'string'
      ? raw.cveID.slice(0, 64)
      : null;
  if (!parsed.success) {
    return {
      externalId: rawId,
      issue: `unexpected KEV entry format: ${parsed.error.issues[0]?.message ?? ''}`,
    };
  }
  const value = parsed.data;
  const id = validateCveId(value.cveID);
  if (!id.ok) return { externalId: rawId, issue: `invalid CVE ID: ${id.reason}` };
  const dueDate = value.dueDate !== undefined && DATE.test(value.dueDate) ? value.dueDate : null;
  const entry = {
    dateAdded: value.dateAdded,
    dueDate: dueDate !== null && dueDate >= value.dateAdded ? dueDate : null,
    vulnerabilityName: cleanText(value.vulnerabilityName, 256),
    requiredAction: cleanText(value.requiredAction, 2_000),
    knownRansomwareCampaignUse:
      value.knownRansomwareCampaignUse?.trim().toLowerCase() === 'known'
        ? ('known' as const)
        : ('unknown' as const),
    notes: cleanText(value.notes, 4_000),
    source: 'cisa-kev',
  };
  const check = kevStatusInputSchema.safeParse(entry);
  if (!check.success) {
    return {
      externalId: id.cveId,
      issue: `invalid KEV entry: ${check.error.issues[0]?.message ?? ''}`,
    };
  }
  return {
    cveId: id.cveId,
    sourceUrl: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id.cveId}`,
    entry,
    vendorProject: cleanText(value.vendorProject, 256),
    product: cleanText(value.product, 256),
    shortDescription: cleanText(value.shortDescription, 4_000),
    cweIds: (value.cwes ?? []).flatMap((cwe) => {
      const normalized = normalizeCweId(cwe);
      return normalized === null ? [] : [normalized];
    }),
    raw,
  };
}

/**
 * CISA KEV adapter. The catalog is a single JSON document without pagination; it is requested
 * conditionally (ETag / Last-Modified) and compared as a complete snapshot, so additions,
 * changes and removals are all detected.
 */
export class CisaKevAdapter implements SourceAdapter<KevCursor, KevCheckpoint> {
  readonly source = 'cisa-kev' as const;
  readonly cursorSchema = kevCursorSchema;
  readonly checkpointSchema = kevCheckpointSchema;

  constructor(private readonly options: CisaKevAdapterOptions) {
    options.client.assertAllowed(options.feedUrl);
  }

  describe(): AdapterDescription {
    return {
      baseUrl: this.options.feedUrl,
      authentication: { mode: 'none', configured: false },
      rateLimit: this.options.client.rateLimit,
    };
  }

  async *sync(
    context: AdapterRunContext<KevCursor, KevCheckpoint>,
  ): AsyncGenerator<SyncBatch<KevCheckpoint>, KevCursor, void> {
    const conditional: Record<string, string> = {};
    if (context.cursor?.etag !== undefined) conditional['if-none-match'] = context.cursor.etag;
    if (context.cursor?.lastModified !== undefined) {
      conditional['if-modified-since'] = context.cursor.lastModified;
    }
    const response = await this.options.client.getJson(this.options.feedUrl, kevCatalogSchema, {
      signal: context.signal,
      meter: context.meter,
      allowNotModified: true,
      headers: conditional,
    });
    if (response.notModified) {
      if (context.cursor === null) throw new Error('KEV catalog not modified without a cursor');
      return context.cursor;
    }
    const catalog = response.body;
    const items = catalog.vulnerabilities.map(kevItem);
    const entries = items.filter((item): item is KevItem => !('issue' in item));
    const invalid = items.filter((item): item is InvalidItem => 'issue' in item);
    const dateReleased = sourceTimestamp(catalog.dateReleased);
    yield {
      kind: 'kev-catalog',
      catalog: {
        catalogVersion: catalog.catalogVersion,
        dateReleased: dateReleased === null ? null : new Date(dateReleased),
      },
      entries,
      invalid,
      checkpoint: {},
    };
    const etag = response.headers.get('etag');
    const lastModified = response.headers.get('last-modified');
    return {
      catalogVersion: catalog.catalogVersion,
      ...(etag === null ? {} : { etag: etag.slice(0, 256) }),
      ...(lastModified === null ? {} : { lastModified: lastModified.slice(0, 64) }),
    };
  }
}
