import { z } from 'zod';

import { paginationQuerySchema } from '../api.js';
import {
  intelligenceSourceSchema,
  syncRunStatsSchema,
  syncRunStatusSchema,
  syncTriggerSchema,
} from './sources.js';

export const sourceSyncStateSchema = z.object({
  /** True while a run holds the source's lease. */
  running: z.boolean(),
  lastRunAt: z.iso.datetime().nullable(),
  lastRunStatus: syncRunStatusSchema.nullable(),
  lastSuccessAt: z.iso.datetime().nullable(),
  /** Consecutive runs that did not succeed. */
  consecutiveFailures: z.number().int().min(0),
  /** Source-specific incremental position (for example the last modification time synced). */
  cursor: z.record(z.string(), z.unknown()).nullable(),
});
export type SourceSyncState = z.infer<typeof sourceSyncStateSchema>;

export const sourceStatusSchema = z.object({
  source: intelligenceSourceSchema,
  name: z.string(),
  description: z.string(),
  enabled: z.boolean(),
  /** Cron expression (UTC) of the scheduled synchronisation, or null when not scheduled. */
  schedule: z.string().nullable(),
  baseUrl: z.string(),
  authentication: z.object({
    /** `optional`: the source works without credentials, with lower quotas. */
    mode: z.enum(['none', 'optional', 'required']),
    configured: z.boolean(),
  }),
  rateLimit: z.object({ maxRequests: z.number().int(), windowMs: z.number().int() }),
  license: z.string(),
  termsUrl: z.string(),
  attribution: z.string(),
  /** Whether the raw upstream payloads are retained. */
  storesRawPayloads: z.boolean(),
  state: sourceSyncStateSchema,
});
export type SourceStatus = z.infer<typeof sourceStatusSchema>;

/** `POST /api/v1/sources/:source/sync` */
export const triggerSyncRequestSchema = z
  .strictObject({
    /** Ignore the checkpoint of a failed previous run and start from the stored cursor. */
    fresh: z.boolean().default(false),
  })
  .default({ fresh: false });
export type TriggerSyncRequest = z.output<typeof triggerSyncRequestSchema>;

export const triggerSyncResponseSchema = z.object({
  source: intelligenceSourceSchema,
  jobId: z.string(),
  /** False when a job with the same idempotency key was already queued. */
  queued: z.boolean(),
});
export type TriggerSyncResponse = z.infer<typeof triggerSyncResponseSchema>;

export const syncRunSchema = z.object({
  id: z.uuid(),
  source: intelligenceSourceSchema,
  trigger: syncTriggerSchema,
  status: syncRunStatusSchema,
  jobId: z.string().nullable(),
  attempt: z.number().int().min(1),
  requestedBy: z.string().nullable(),
  resumedFromRunId: z.uuid().nullable(),
  startedAt: z.iso.datetime(),
  heartbeatAt: z.iso.datetime(),
  finishedAt: z.iso.datetime().nullable(),
  /** Cursor at the start of the run and the cursor it committed on success. */
  cursorBefore: z.record(z.string(), z.unknown()).nullable(),
  cursorAfter: z.record(z.string(), z.unknown()).nullable(),
  /** Last persisted position inside the run, used to resume after a failure. */
  checkpoint: z.record(z.string(), z.unknown()).nullable(),
  stats: syncRunStatsSchema,
  error: z.string().nullable(),
  issueCount: z.number().int().min(0),
});
export type SyncRun = z.infer<typeof syncRunSchema>;

export const syncRunIssueSchema = z.object({
  /** Item at the source the issue refers to, when known. */
  sourceRecordId: z.string().nullable(),
  message: z.string(),
  createdAt: z.iso.datetime(),
});
export type SyncRunIssue = z.infer<typeof syncRunIssueSchema>;

export const syncRunDetailSchema = syncRunSchema.extend({
  /** At most the first 200 issues of the run. */
  issues: z.array(syncRunIssueSchema),
});
export type SyncRunDetail = z.infer<typeof syncRunDetailSchema>;

export const listSyncRunsQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  source: intelligenceSourceSchema.optional(),
  status: syncRunStatusSchema.optional(),
  trigger: syncTriggerSchema.optional(),
});
export type ListSyncRunsQuery = z.infer<typeof listSyncRunsQuerySchema>;
