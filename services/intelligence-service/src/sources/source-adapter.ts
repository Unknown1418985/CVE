import type { z } from 'zod';

import type { EpssScore, IntelligenceSource } from '@cve/contracts';
import type { Logger } from '@cve/logger';

import type { RequestMeter } from '../http/source-http-client.js';
import type { CveContentInput } from './cve-content.js';

/** JSON-serialisable value stored as cursor or checkpoint. */
export type JsonObject = Record<string, unknown>;

/** One CVE record as reported by a source (NVD, MITRE, GitHub). */
export interface CveRecordItem {
  /** Identifier at the source (CVE ID, GHSA ID). */
  readonly externalId: string;
  /** CVE ID the item describes; items without one are stored but not published. */
  readonly cveId: string | null;
  readonly sourceUrl: string;
  readonly sourceModifiedAt: Date | null;
  /** Normalised content, or null when the item has nothing publishable (e.g. withdrawn). */
  readonly content: CveContentInput | null;
  /** True when the source withdrew the item. */
  readonly withdrawn?: boolean;
  /** Original payload (stored only where the source permits it). */
  readonly raw: unknown;
  /** Problems found while mapping (dropped values); recorded as run issues. */
  readonly issues: readonly string[];
}

export interface KevItem {
  readonly cveId: string;
  readonly sourceUrl: string;
  readonly entry: {
    readonly dateAdded: string;
    readonly dueDate: string | null;
    readonly vulnerabilityName: string | null;
    readonly requiredAction: string | null;
    readonly knownRansomwareCampaignUse: 'known' | 'unknown';
    readonly notes: string | null;
    readonly source: string;
  };
  readonly vendorProject: string | null;
  readonly product: string | null;
  readonly shortDescription: string | null;
  readonly cweIds: readonly string[];
  readonly raw: unknown;
}

/** An item the source returned that could not be used at all. */
export interface InvalidItem {
  readonly externalId: string | null;
  readonly issue: string;
}

export type SyncBatch<TCheckpoint extends JsonObject> =
  | {
      readonly kind: 'cve-records';
      readonly records: readonly CveRecordItem[];
      /** Items refused by validation (identifier and reason). */
      readonly invalid: readonly InvalidItem[];
      readonly checkpoint: TCheckpoint;
    }
  | {
      /** A complete catalog snapshot: stored entries missing from it are removed. */
      readonly kind: 'kev-catalog';
      readonly catalog: { readonly catalogVersion: string; readonly dateReleased: Date | null };
      readonly entries: readonly KevItem[];
      /** Items refused by validation (identifier and reason). */
      readonly invalid: readonly InvalidItem[];
      readonly checkpoint: TCheckpoint;
    }
  | {
      readonly kind: 'epss-scores';
      readonly scoreDate: string;
      readonly modelVersion: string | null;
      readonly scores: readonly EpssScore[];
      readonly invalid: readonly InvalidItem[];
      readonly checkpoint: TCheckpoint;
    }
  | {
      /** A run-level problem that does not stop the run (e.g. a gap in the source's change log). */
      readonly kind: 'notice';
      readonly issue: string;
      readonly checkpoint: TCheckpoint;
    };

export interface AdapterRunContext<TCursor, TCheckpoint> {
  /** Cursor committed by the last successful run, or null for the first run. */
  readonly cursor: TCursor | null;
  /** Checkpoint of the failed run being resumed, or null for a fresh run. */
  readonly checkpoint: TCheckpoint | null;
  readonly signal: AbortSignal;
  readonly logger: Logger;
  readonly meter: RequestMeter;
  /** Start time of the run; adapters use it as the upper bound of time windows. */
  readonly now: Date;
}

export interface AdapterDescription {
  readonly baseUrl: string;
  readonly authentication: {
    readonly mode: 'none' | 'optional' | 'required';
    readonly configured: boolean;
  };
  readonly rateLimit: { readonly maxRequests: number; readonly windowMs: number };
}

/**
 * An independent adapter for one external source. `sync` yields batches in order; the engine
 * persists each batch and then the batch's checkpoint, so a failed run can resume after the last
 * persisted batch. The generator's return value is the new cursor, committed only on success.
 */
export interface SourceAdapter<
  TCursor extends JsonObject = JsonObject,
  TCheckpoint extends JsonObject = JsonObject,
> {
  readonly source: IntelligenceSource;
  readonly cursorSchema: z.ZodType<TCursor>;
  readonly checkpointSchema: z.ZodType<TCheckpoint>;
  describe(): AdapterDescription;
  sync(
    context: AdapterRunContext<TCursor, TCheckpoint>,
  ): AsyncGenerator<SyncBatch<TCheckpoint>, TCursor, void>;
}
