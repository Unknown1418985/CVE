import { z } from 'zod';

/**
 * External intelligence sources synchronised by the Intelligence Service. The name is also the
 * provenance identifier (`source`) written to every observation derived from that source.
 */
export const INTELLIGENCE_SOURCES = [
  'nvd',
  'mitre-cve',
  'cisa-kev',
  'first-epss',
  'github-advisory',
] as const;
export const intelligenceSourceSchema = z.enum(INTELLIGENCE_SOURCES);
export type IntelligenceSource = z.infer<typeof intelligenceSourceSchema>;

export function isIntelligenceSource(value: string): value is IntelligenceSource {
  return (INTELLIGENCE_SOURCES as readonly string[]).includes(value);
}

/** Lifecycle of one synchronisation run. */
export const SYNC_RUN_STATUSES = [
  /** In progress (heartbeat is renewed while it runs). */
  'running',
  'succeeded',
  /** The run stopped with an error; its checkpoint lets the next run resume. */
  'failed',
  /** The worker stopped sending heartbeats (crash, restart); recovered like a failed run. */
  'abandoned',
] as const;
export const syncRunStatusSchema = z.enum(SYNC_RUN_STATUSES);
export type SyncRunStatus = z.infer<typeof syncRunStatusSchema>;

export const SYNC_TRIGGERS = ['scheduled', 'manual', 'recovery'] as const;
export const syncTriggerSchema = z.enum(SYNC_TRIGGERS);
export type SyncTrigger = z.infer<typeof syncTriggerSchema>;

/** Counters reported by every run. */
export const syncRunStatsSchema = z.object({
  /** HTTP requests sent to the source, including retries. */
  requests: z.number().int().min(0),
  /** Items received from the source. */
  fetched: z.number().int().min(0),
  created: z.number().int().min(0),
  updated: z.number().int().min(0),
  /** Items identical to the stored observation (duplicates); no event is published. */
  unchanged: z.number().int().min(0),
  /** Items no longer present in a complete snapshot (CISA KEV) or withdrawn at the source. */
  removed: z.number().int().min(0),
  /** Items, or parts of items, refused by validation (listed as run issues). */
  invalid: z.number().int().min(0),
  /** Domain events written to the outbox. */
  events: z.number().int().min(0),
});
export type SyncRunStats = z.infer<typeof syncRunStatsSchema>;

export const EMPTY_SYNC_RUN_STATS: SyncRunStats = {
  requests: 0,
  fetched: 0,
  created: 0,
  updated: 0,
  unchanged: 0,
  removed: 0,
  invalid: 0,
  events: 0,
};
