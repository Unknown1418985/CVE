import { z } from 'zod';

import { validateCveId } from '@cve/contracts';
import { SourceHttpError, type SourceHttpClient } from '@cve/source-http';

import {
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

/** Records fetched (and persisted) per batch. */
const RECORDS_PER_BATCH = 25;
/** The delta log covers about 30 days; it is a JSON file of a few tens of megabytes. */
export const DELTA_LOG_ACCEPT = ['application/json', 'text/plain'];

const deltaChangeSchema = z.object({ cveId: z.string(), dateUpdated: z.string().optional() });
export const deltaLogSchema = z.array(
  z.object({
    fetchTime: z.iso.datetime({ offset: true }),
    new: z.array(deltaChangeSchema).default([]),
    updated: z.array(deltaChangeSchema).default([]),
  }),
);
type DeltaLog = z.infer<typeof deltaLogSchema>;

const localizedTextSchema = z.object({ lang: z.string(), value: z.string() });
const metricSchema = z.looseObject({
  cvssV3_1: z.looseObject({ vectorString: z.string(), baseScore: z.number() }).optional(),
  cvssV4_0: z.looseObject({ vectorString: z.string(), baseScore: z.number() }).optional(),
});
const containerSchema = z.looseObject({
  providerMetadata: z
    .looseObject({ orgId: z.string().optional(), shortName: z.string().optional() })
    .optional(),
  title: z.string().optional(),
  descriptions: z.array(localizedTextSchema).optional(),
  rejectedReasons: z.array(localizedTextSchema).optional(),
  metrics: z.array(metricSchema).optional(),
  problemTypes: z
    .array(
      z.object({
        descriptions: z
          .array(
            z.looseObject({
              cweId: z.string().optional(),
              description: z.string().optional(),
              type: z.string().optional(),
            }),
          )
          .default([]),
      }),
    )
    .optional(),
  references: z
    .array(z.looseObject({ url: z.string(), tags: z.array(z.string()).optional() }))
    .optional(),
  affected: z
    .array(
      z.looseObject({
        vendor: z.string().optional(),
        product: z.string().optional(),
        packageName: z.string().optional(),
        defaultStatus: z.string().optional(),
        versions: z
          .array(
            z.looseObject({
              version: z.string(),
              status: z.string(),
              lessThan: z.string().optional(),
              lessThanOrEqual: z.string().optional(),
            }),
          )
          .optional(),
      }),
    )
    .optional(),
});
type Container = z.infer<typeof containerSchema>;

export const cveRecordV5Schema = z.looseObject({
  dataType: z.literal('CVE_RECORD'),
  cveMetadata: z.looseObject({
    cveId: z.string(),
    state: z.string(),
    assignerShortName: z.string().optional(),
    datePublished: z.string().optional(),
    dateUpdated: z.string().optional(),
  }),
  containers: z.looseObject({
    cna: containerSchema,
    adp: z.array(containerSchema).optional(),
  }),
});
type CveRecordV5 = z.infer<typeof cveRecordV5Schema>;

export const mitreCursorSchema = z.object({
  /** Newest delta-log fetch time fully processed. */
  lastFetchTime: z.iso.datetime(),
  deltaLogEtag: z.string().max(256).optional(),
});
export type MitreCursor = z.infer<typeof mitreCursorSchema>;

export const mitreCheckpointSchema = z.object({
  /** Delta-log entries with `from < fetchTime <= through` are processed by the run. */
  from: z.iso.datetime(),
  through: z.iso.datetime(),
  /** Index into the sorted, de-duplicated list of changed CVE IDs. */
  offset: z.number().int().min(0),
  deltaLogEtag: z.string().max(256).optional(),
});
export type MitreCheckpoint = z.infer<typeof mitreCheckpointSchema>;

export interface MitreAdapterOptions {
  readonly client: SourceHttpClient;
  /** CVE Services API base, e.g. `https://cveawg.mitre.org/api` (records at `/cve/{id}`). */
  readonly apiUrl: string;
  /** cvelistV5 `deltaLog.json` (changes of the last 30 days, updated every few minutes). */
  readonly deltaLogUrl: string;
  /** First run without a cursor processes changes this far back. */
  readonly initialLookbackMs: number;
}

const PLACEHOLDER_VERSIONS = new Set(['', '*', '0', 'n/a', 'unspecified', 'unknown']);

function english(texts: readonly { lang: string; value: string }[] | undefined): string | null {
  if (texts === undefined) return null;
  return (
    (texts.find((text) => text.lang.toLowerCase().startsWith('en')) ?? texts[0])?.value ?? null
  );
}

function affectedStatus(value: string | undefined): 'affected' | 'unaffected' | 'unknown' {
  return value === 'affected' || value === 'unaffected' ? value : 'unknown';
}

function containerSource(container: Container, fallback: string): string {
  return sourceIdentifier(container.providerMetadata?.shortName) ?? fallback;
}

/** Maps a CVE JSON 5 record (CNA and ADP containers) to the CVE Service write model. */
export function mapCveRecordV5(record: CveRecordV5): { draft: CveContentDraft; issues: string[] } {
  const issues: string[] = [];
  const { cna } = record.containers;
  const cnaSource = containerSource(
    cna,
    sourceIdentifier(record.cveMetadata.assignerShortName) ?? 'mitre-cve',
  );
  const containers: [Container, string][] = [
    [cna, cnaSource],
    ...(record.containers.adp ?? []).map((adp, index): [Container, string] => [
      adp,
      containerSource(adp, `adp-${index}`),
    ]),
  ];
  const rejected = record.cveMetadata.state.toUpperCase() === 'REJECTED';

  const cvssMetrics = containers.flatMap(([container, source]) =>
    (container.metrics ?? []).flatMap((metric) => [
      ...(metric.cvssV4_0 === undefined
        ? []
        : [
            {
              version: '4.0' as const,
              source,
              type: 'secondary' as const,
              vectorString: metric.cvssV4_0.vectorString,
              baseScore: metric.cvssV4_0.baseScore,
            },
          ]),
      ...(metric.cvssV3_1 === undefined
        ? []
        : [
            {
              version: '3.1' as const,
              source,
              type: 'secondary' as const,
              vectorString: metric.cvssV3_1.vectorString,
              baseScore: metric.cvssV3_1.baseScore,
            },
          ]),
    ]),
  );

  const weaknesses = containers.flatMap(([container, source]) =>
    (container.problemTypes ?? [])
      .flatMap((problemType) => problemType.descriptions)
      .flatMap((description) => {
        const cweId = description.cweId ?? /\bCWE-\d+\b/.exec(description.description ?? '')?.[0];
        return cweId === undefined ? [] : [{ cweId, source }];
      }),
  );

  // The same URL often appears in several containers: keep one reference and merge the tags.
  const referencesByUrl = new Map<string, { url: string; source: string; tags: string[] }>();
  for (const [container, source] of containers) {
    for (const reference of container.references ?? []) {
      const existing = referencesByUrl.get(reference.url);
      const tags = (reference.tags ?? []).filter((tag) => !tag.startsWith('x_'));
      if (existing) existing.tags = [...new Set([...existing.tags, ...tags])].slice(0, 20);
      else
        referencesByUrl.set(reference.url, { url: reference.url, source, tags: tags.slice(0, 20) });
    }
  }

  const affectedProducts = (cna.affected ?? []).flatMap((affected, index) => {
    const product = affected.product ?? affected.packageName;
    if (product === undefined || product.trim() === '') {
      issues.push(`affected[${index}] skipped: no product or package name`);
      return [];
    }
    const base = { vendor: affected.vendor ?? 'n/a', product, source: cnaSource };
    const versions = affected.versions ?? [];
    if (versions.length === 0) return [{ ...base, status: affectedStatus(affected.defaultStatus) }];
    return versions.map((version) => {
      const start = PLACEHOLDER_VERSIONS.has(version.version.trim().toLowerCase())
        ? undefined
        : version.version;
      const status = affectedStatus(version.status);
      if (version.lessThan !== undefined || version.lessThanOrEqual !== undefined) {
        const lessThan = version.lessThan === '*' ? undefined : version.lessThan;
        const lessThanOrEqual =
          version.lessThanOrEqual === '*' ? undefined : version.lessThanOrEqual;
        return {
          ...base,
          status,
          ...(start === undefined ? {} : { versionStartIncluding: start }),
          ...(lessThan === undefined ? {} : { versionEndExcluding: lessThan }),
          ...(lessThanOrEqual === undefined ? {} : { versionEndIncluding: lessThanOrEqual }),
        };
      }
      return { ...base, status, ...(start === undefined ? {} : { version: start }) };
    });
  });

  return {
    issues,
    draft: {
      state: rejected ? 'rejected' : 'published',
      title: cna.title ?? null,
      description: rejected
        ? (english(cna.rejectedReasons) ?? english(cna.descriptions))
        : english(cna.descriptions),
      assigner: record.cveMetadata.assignerShortName ?? null,
      publishedAt: sourceTimestamp(record.cveMetadata.datePublished),
      lastModifiedAt: sourceTimestamp(record.cveMetadata.dateUpdated),
      source: 'mitre-cve',
      cvssMetrics,
      weaknesses,
      references: [...referencesByUrl.values()],
      affectedProducts,
    },
  };
}

export function mitreItem(cveId: string, raw: unknown): CveRecordItem | InvalidItem {
  const parsed = cveRecordV5Schema.safeParse(raw);
  if (!parsed.success) {
    return {
      externalId: cveId,
      issue: `unexpected CVE JSON 5 format: ${parsed.error.issues[0]?.message ?? ''}`,
    };
  }
  if (parsed.data.cveMetadata.cveId.toUpperCase() !== cveId) {
    return {
      externalId: cveId,
      issue: `record describes ${parsed.data.cveMetadata.cveId.slice(0, 32)}`,
    };
  }
  const { draft, issues } = mapCveRecordV5(parsed.data);
  const sanitized = sanitizeCveContent(draft);
  if (!sanitized.ok) return { externalId: cveId, issue: sanitized.error };
  return {
    externalId: cveId,
    cveId,
    sourceUrl: `https://www.cve.org/CVERecord?id=${cveId}`,
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

/** Sorted, de-duplicated CVE IDs changed in `(from, through]`, plus invalid IDs found. */
export function changedCveIds(
  log: DeltaLog,
  from: string,
  through: string,
): { ids: string[]; invalid: InvalidItem[] } {
  const fromTime = Date.parse(from);
  const throughTime = Date.parse(through);
  const ids = new Set<string>();
  const invalid = new Map<string, InvalidItem>();
  for (const entry of log) {
    const time = Date.parse(entry.fetchTime);
    if (time <= fromTime || time > throughTime) continue;
    for (const change of [...entry.new, ...entry.updated]) {
      const id = validateCveId(change.cveId);
      if (id.ok) ids.add(id.cveId);
      else
        invalid.set(change.cveId, {
          externalId: change.cveId.slice(0, 64),
          issue: `invalid CVE ID in delta log: ${id.reason}`,
        });
    }
  }
  return { ids: [...ids].sort(), invalid: [...invalid.values()] };
}

/**
 * MITRE CVE List adapter. Changes come from the cvelistV5 delta log (conditional request with
 * ETag); each changed record is read from the CVE Services API. CNA and ADP containers are kept
 * apart: every metric, weakness and reference names the organisation that provided it.
 */
export class MitreCveAdapter implements SourceAdapter<MitreCursor, MitreCheckpoint> {
  readonly source = 'mitre-cve' as const;
  readonly cursorSchema = mitreCursorSchema;
  readonly checkpointSchema = mitreCheckpointSchema;

  constructor(private readonly options: MitreAdapterOptions) {
    options.client.assertAllowed(options.apiUrl);
    options.client.assertAllowed(options.deltaLogUrl);
  }

  describe(): AdapterDescription {
    return {
      baseUrl: this.options.apiUrl,
      authentication: { mode: 'none', configured: false },
      rateLimit: this.options.client.rateLimit,
    };
  }

  recordUrl(cveId: string): string {
    return `${this.options.apiUrl.replace(/\/+$/, '')}/cve/${encodeURIComponent(cveId)}`;
  }

  async *sync(
    context: AdapterRunContext<MitreCursor, MitreCheckpoint>,
  ): AsyncGenerator<SyncBatch<MitreCheckpoint>, MitreCursor, void> {
    const etag = context.checkpoint === null ? context.cursor?.deltaLogEtag : undefined;
    const logResponse = await this.options.client.getJson(
      this.options.deltaLogUrl,
      deltaLogSchema,
      {
        signal: context.signal,
        meter: context.meter,
        accept: DELTA_LOG_ACCEPT,
        allowNotModified: true,
        ...(etag === undefined ? {} : { headers: { 'if-none-match': etag } }),
      },
    );
    if (logResponse.notModified) {
      if (context.cursor === null) throw new Error('delta log not modified without a cursor');
      return context.cursor;
    }
    const log = logResponse.body;
    const newEtag = logResponse.headers.get('etag') ?? undefined;
    const newest = log.reduce<string | null>(
      (max, entry) => (max === null || entry.fetchTime > max ? entry.fetchTime : max),
      null,
    );
    const oldest = log.reduce<string | null>(
      (min, entry) => (min === null || entry.fetchTime < min ? entry.fetchTime : min),
      null,
    );

    let checkpoint: MitreCheckpoint;
    if (context.checkpoint !== null) {
      checkpoint = context.checkpoint;
    } else {
      const from =
        context.cursor?.lastFetchTime ??
        new Date(context.now.getTime() - this.options.initialLookbackMs).toISOString();
      const through = newest === null || newest < from ? from : new Date(newest).toISOString();
      checkpoint = {
        from,
        through,
        offset: 0,
        ...(newEtag === undefined ? {} : { deltaLogEtag: newEtag }),
      };
      if (context.cursor !== null && oldest !== null && Date.parse(oldest) > Date.parse(from)) {
        yield {
          kind: 'notice',
          issue: `The delta log starts at ${oldest}; changes between ${from} and then are not covered by this run (use an NVD synchronisation to fill the gap).`,
          checkpoint,
        };
      }
    }

    const { ids, invalid } = changedCveIds(log, checkpoint.from, checkpoint.through);
    if (invalid.length > 0 && checkpoint.offset === 0) {
      yield { kind: 'cve-records', records: [], invalid, checkpoint };
    }
    for (let offset = checkpoint.offset; offset < ids.length; offset += RECORDS_PER_BATCH) {
      const records: CveRecordItem[] = [];
      const failures: InvalidItem[] = [];
      for (const cveId of ids.slice(offset, offset + RECORDS_PER_BATCH)) {
        try {
          const response = await this.options.client.getJson(this.recordUrl(cveId), z.unknown(), {
            signal: context.signal,
            meter: context.meter,
          });
          const item = mitreItem(cveId, response.body);
          if ('issue' in item) failures.push(item);
          else records.push(item);
        } catch (error) {
          // A record listed in the delta log but not served (yet) is reported, not fatal.
          if (error instanceof SourceHttpError && error.status === 404) {
            failures.push({
              externalId: cveId,
              issue: 'record listed in the delta log was not found',
            });
          } else {
            throw error;
          }
        }
      }
      checkpoint = { ...checkpoint, offset: Math.min(ids.length, offset + RECORDS_PER_BATCH) };
      yield { kind: 'cve-records', records, invalid: failures, checkpoint };
    }
    return {
      lastFetchTime: checkpoint.through,
      ...(checkpoint.deltaLogEtag === undefined ? {} : { deltaLogEtag: checkpoint.deltaLogEtag }),
    };
  }
}
