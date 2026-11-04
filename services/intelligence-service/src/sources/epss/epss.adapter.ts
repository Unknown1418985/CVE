import { z } from 'zod';

import { validateCveId, type EpssScore } from '@cve/contracts';

import type { SourceHttpClient } from '../../http/source-http-client.js';
import type {
  AdapterDescription,
  AdapterRunContext,
  InvalidItem,
  SourceAdapter,
  SyncBatch,
} from '../source-adapter.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

const probabilityText = z.union([z.string(), z.number()]);

export const epssResponseSchema = z.looseObject({
  status: z.string().optional(),
  total: z.number().int().min(0),
  offset: z.number().int().min(0),
  limit: z.number().int().min(0),
  model_version: z.string().optional(),
  data: z.array(
    z.looseObject({
      cve: z.string(),
      epss: probabilityText,
      percentile: probabilityText,
      date: z.string(),
    }),
  ),
});
type EpssResponse = z.infer<typeof epssResponseSchema>;

export const epssCursorSchema = z.object({ lastScoreDate: z.iso.date() });
export type EpssCursor = z.infer<typeof epssCursorSchema>;

export const epssCheckpointSchema = z.object({
  /** Score dates still to synchronise, oldest first; the first one is in progress. */
  pendingDates: z.array(z.iso.date()).max(31),
  offset: z.number().int().min(0),
  /** Newest score date already synchronised completely by this run. */
  completedThrough: z.iso.date().optional(),
});
export type EpssCheckpoint = z.infer<typeof epssCheckpointSchema>;

export interface EpssAdapterOptions {
  readonly client: SourceHttpClient;
  /** `https://api.first.org/data/v1/epss` */
  readonly baseUrl: string;
  readonly pageSize: number;
  /** After an outage, synchronise at most this many missed score dates (oldest dropped). */
  readonly maxBackfillDays: number;
}

function addDays(date: string, days: number): string {
  return new Date(Date.parse(`${date}T00:00:00Z`) + days * DAY_MS).toISOString().slice(0, 10);
}

/** Parses a probability string such as `"0.000430000"`; null when out of range. */
export function parseProbability(value: string | number): number | null {
  const number = typeof value === 'number' ? value : Number(value.trim());
  if (!Number.isFinite(number) || number < 0 || number > 1) return null;
  // EPSS publishes at most nine decimals; rounding removes binary representation noise.
  return Math.round(number * 1e9) / 1e9;
}

export function epssScores(
  page: EpssResponse,
  scoreDate: string,
): { scores: EpssScore[]; invalid: InvalidItem[] } {
  const scores: EpssScore[] = [];
  const invalid: InvalidItem[] = [];
  const seen = new Set<string>();
  for (const row of page.data) {
    const id = validateCveId(row.cve);
    if (!id.ok) {
      invalid.push({ externalId: row.cve.slice(0, 64), issue: `invalid CVE ID: ${id.reason}` });
      continue;
    }
    if (row.date !== scoreDate) {
      invalid.push({
        externalId: id.cveId,
        issue: `score date ${row.date.slice(0, 32)} instead of ${scoreDate}`,
      });
      continue;
    }
    const score = parseProbability(row.epss);
    const percentile = parseProbability(row.percentile);
    if (score === null || percentile === null) {
      invalid.push({ externalId: id.cveId, issue: 'score or percentile outside 0–1' });
      continue;
    }
    if (seen.has(id.cveId)) continue;
    seen.add(id.cveId);
    scores.push({ cveId: id.cveId, score, percentile });
  }
  return { scores, invalid };
}

/**
 * FIRST EPSS adapter. Each run finds the newest published score date and synchronises every
 * date after the cursor (up to `maxBackfillDays`), page by page with `offset`/`limit`.
 */
export class EpssAdapter implements SourceAdapter<EpssCursor, EpssCheckpoint> {
  readonly source = 'first-epss' as const;
  readonly cursorSchema = epssCursorSchema;
  readonly checkpointSchema = epssCheckpointSchema;

  constructor(private readonly options: EpssAdapterOptions) {
    options.client.assertAllowed(options.baseUrl);
    if (options.pageSize < 1 || options.pageSize > 10_000) {
      throw new Error('EPSS page size must be between 1 and 10000');
    }
  }

  describe(): AdapterDescription {
    return {
      baseUrl: this.options.baseUrl,
      authentication: { mode: 'none', configured: false },
      rateLimit: this.options.client.rateLimit,
    };
  }

  pageUrl(scoreDate: string | null, offset: number, limit: number): string {
    const url = new URL(this.options.baseUrl);
    if (scoreDate !== null) url.searchParams.set('date', scoreDate);
    url.searchParams.set('limit', String(limit));
    url.searchParams.set('offset', String(offset));
    return url.href;
  }

  private async latestScoreDate(
    context: AdapterRunContext<EpssCursor, EpssCheckpoint>,
  ): Promise<string> {
    const response = await this.options.client.getJson(
      this.pageUrl(null, 0, 1),
      epssResponseSchema,
      {
        signal: context.signal,
        meter: context.meter,
      },
    );
    const date = response.body.data[0]?.date;
    if (date === undefined || !DATE.test(date)) {
      throw new Error('EPSS did not report a current score date');
    }
    return date;
  }

  async *sync(
    context: AdapterRunContext<EpssCursor, EpssCheckpoint>,
  ): AsyncGenerator<SyncBatch<EpssCheckpoint>, EpssCursor, void> {
    let checkpoint: EpssCheckpoint | null = context.checkpoint;
    if (checkpoint === null) {
      const latest = await this.latestScoreDate(context);
      const last = context.cursor?.lastScoreDate;
      if (last !== undefined && last >= latest) return { lastScoreDate: last };
      const pendingDates: string[] = [];
      const first = last === undefined ? latest : addDays(last, 1);
      for (let date = first; date <= latest; date = addDays(date, 1)) pendingDates.push(date);
      const kept = pendingDates.slice(-this.options.maxBackfillDays);
      checkpoint = { pendingDates: kept, offset: 0 };
      if (kept.length < pendingDates.length) {
        yield {
          kind: 'notice',
          issue: `Skipped ${pendingDates.length - kept.length} EPSS score date(s) before ${kept[0] ?? latest}: more than ${this.options.maxBackfillDays} days behind.`,
          checkpoint,
        };
      }
    }
    while (checkpoint.pendingDates.length > 0) {
      const state: EpssCheckpoint = checkpoint;
      const [scoreDate = '', ...rest] = state.pendingDates;
      const response = await this.options.client.getJson(
        this.pageUrl(scoreDate, state.offset, this.options.pageSize),
        epssResponseSchema,
        { signal: context.signal, meter: context.meter },
      );
      const page = response.body;
      const { scores, invalid } = epssScores(page, scoreDate);
      const nextOffset = state.offset + page.data.length;
      const dateDone = page.data.length === 0 || nextOffset >= page.total;
      if (dateDone && page.total === 0) {
        invalid.push({ externalId: null, issue: `EPSS returned no scores for ${scoreDate}` });
      }
      checkpoint = dateDone
        ? { pendingDates: rest, offset: 0, completedThrough: scoreDate }
        : { ...state, offset: nextOffset };
      yield {
        kind: 'epss-scores',
        scoreDate,
        modelVersion: page.model_version?.slice(0, 32) ?? null,
        scores,
        invalid,
        checkpoint,
      };
    }
    const lastCompleted = checkpoint.completedThrough ?? context.cursor?.lastScoreDate;
    if (lastCompleted === undefined)
      throw new Error('EPSS synchronisation finished without a score date');
    return { lastScoreDate: lastCompleted };
  }
}
