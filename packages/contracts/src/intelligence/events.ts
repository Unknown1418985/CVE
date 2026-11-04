import { z } from 'zod';

import { cveIdSchema } from '../cve/identifiers.js';
import { cveContentSchema, kevStatusInputSchema } from '../cve/schemas.js';
import {
  intelligenceSourceSchema,
  syncRunStatsSchema,
  syncRunStatusSchema,
  syncTriggerSchema,
} from './sources.js';

/** Domain events published by the Intelligence Service (routing key = event type). */
export const INTELLIGENCE_EVENT_TYPES = {
  cveObserved: 'intelligence.cve-observation.recorded',
  kevAdded: 'intelligence.kev-entry.added',
  kevUpdated: 'intelligence.kev-entry.updated',
  kevRemoved: 'intelligence.kev-entry.removed',
  epssPublished: 'intelligence.epss-scores.published',
  syncCompleted: 'intelligence.sync-run.completed',
  syncFailed: 'intelligence.sync-run.failed',
} as const;
export type IntelligenceEventType =
  (typeof INTELLIGENCE_EVENT_TYPES)[keyof typeof INTELLIGENCE_EVENT_TYPES];

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

/** Where an observation came from, so consumers can attribute it (CLAUDE.md §5, §6). */
export const observationProvenanceSchema = z.object({
  source: intelligenceSourceSchema,
  /** Identifier of the item at the source: a CVE ID, a GHSA ID, … */
  sourceRecordId: z.string().min(1).max(128),
  /** Human-readable location of the item at the source. */
  sourceUrl: z.url(),
  /** Attribution text required or requested by the source's terms of use. */
  attribution: z.string().min(1).max(512),
  /** Incremented every time the source's content for this item changes. */
  revision: z.number().int().min(1),
  /** SHA-256 of the normalised content, for duplicate detection by consumers. */
  contentHash: sha256Schema,
  /** When the Intelligence Service observed this content. */
  observedAt: z.iso.datetime(),
  /** Last modification time reported by the source, if any. */
  sourceModifiedAt: z.iso.datetime().nullable(),
  /** Synchronisation run that produced the observation. */
  runId: z.uuid(),
});
export type ObservationProvenance = z.infer<typeof observationProvenanceSchema>;

/**
 * One source's view of a CVE record. `content` is the CVE Service write model
 * (`cveContentSchema`); every metric, weakness, reference and product carries its `source`.
 * Consumers must merge it per source and never let it overwrite another source's data.
 */
export const cveObservationRecordedPayloadSchema = observationProvenanceSchema.extend({
  cveId: cveIdSchema,
  change: z.enum(['created', 'updated']),
  content: cveContentSchema,
  /** Lists that were cut to the CVE Service's limits (the full data stays in the raw record). */
  truncated: z.array(z.enum(['references', 'affectedProducts', 'weaknesses', 'cvssMetrics'])),
});
export type CveObservationRecordedPayload = z.output<typeof cveObservationRecordedPayloadSchema>;
export type CveObservationRecordedInput = z.input<typeof cveObservationRecordedPayloadSchema>;

const kevCatalogSchema = z.object({
  catalogVersion: z.string().min(1).max(64),
  dateReleased: z.iso.datetime().nullable(),
});

export const kevEntryChangedPayloadSchema = observationProvenanceSchema.extend({
  cveId: cveIdSchema,
  catalog: kevCatalogSchema,
  /** The CVE Service KEV write model (`PUT /cves/:cveId/kev`). */
  entry: kevStatusInputSchema,
  /** Fields that only exist in the catalog and are not part of the KEV status model. */
  vendorProject: z.string().nullable(),
  product: z.string().nullable(),
  shortDescription: z.string().nullable(),
  cweIds: z.array(z.string()),
});
export type KevEntryChangedPayload = z.output<typeof kevEntryChangedPayloadSchema>;
export type KevEntryChangedInput = z.input<typeof kevEntryChangedPayloadSchema>;

export const kevEntryRemovedPayloadSchema = z.object({
  source: intelligenceSourceSchema,
  cveId: cveIdSchema,
  catalog: kevCatalogSchema,
  observedAt: z.iso.datetime(),
  runId: z.uuid(),
});
export type KevEntryRemovedPayload = z.infer<typeof kevEntryRemovedPayloadSchema>;

/** Maximum number of scores carried by one `intelligence.epss-scores.published` event. */
export const MAX_EPSS_SCORES_PER_EVENT = 1_000;

export const epssScoreSchema = z.object({
  cveId: cveIdSchema,
  score: z.number().min(0).max(1),
  percentile: z.number().min(0).max(1),
});
export type EpssScore = z.infer<typeof epssScoreSchema>;

/**
 * A batch of daily EPSS scores from FIRST. Each (CVE, score date) is published at most once;
 * scores are immutable per date, so consumers can store them as append-only observations.
 */
export const epssScoresPublishedPayloadSchema = z.object({
  source: intelligenceSourceSchema,
  scoreDate: z.iso.date(),
  modelVersion: z.string().max(32).nullable(),
  attribution: z.string().min(1).max(512),
  observedAt: z.iso.datetime(),
  runId: z.uuid(),
  scores: z.array(epssScoreSchema).min(1).max(MAX_EPSS_SCORES_PER_EVENT),
});
export type EpssScoresPublishedPayload = z.infer<typeof epssScoresPublishedPayloadSchema>;

export const syncRunFinishedPayloadSchema = z.object({
  runId: z.uuid(),
  source: intelligenceSourceSchema,
  trigger: syncTriggerSchema,
  status: syncRunStatusSchema,
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime(),
  stats: syncRunStatsSchema,
  /** Run whose checkpoint this run continued from. */
  resumedFromRunId: z.uuid().nullable(),
  error: z.string().nullable(),
  /** True when the job is retried automatically (the retry resumes from the checkpoint). */
  willRetry: z.boolean(),
});
export type SyncRunFinishedPayload = z.infer<typeof syncRunFinishedPayloadSchema>;
