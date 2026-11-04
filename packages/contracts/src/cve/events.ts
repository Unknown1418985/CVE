import { z } from 'zod';

import { RECORD_SEVERITIES, CVSS_VERSIONS } from './cvss.js';
import { CVE_STATES } from './schemas.js';

/** Domain events published by the CVE Service (routing key = event type). */
export const CVE_EVENT_TYPES = {
  created: 'cve.record.created',
  updated: 'cve.record.updated',
  deleted: 'cve.record.deleted',
} as const;
export type CveEventType = (typeof CVE_EVENT_TYPES)[keyof typeof CVE_EVENT_TYPES];

/** Parts of a CVE record an `updated` event can report as changed. */
export const CVE_CHANGE_FIELDS = [
  'state',
  'title',
  'description',
  'assigner',
  'publishedAt',
  'lastModifiedAt',
  'source',
  'cvssMetrics',
  'weaknesses',
  'references',
  'affectedProducts',
  'kev',
  'epss',
] as const;
export type CveChangeField = (typeof CVE_CHANGE_FIELDS)[number];

export const eventActorSchema = z.object({
  type: z.enum(['user', 'service']),
  id: z.string(),
  username: z.string().nullable(),
});
export type EventActor = z.infer<typeof eventActorSchema>;

/** State of the record after the change: enough for consumers to filter without a lookup. */
export const cveRecordSnapshotSchema = z.object({
  recordId: z.uuid(),
  cveId: z.string(),
  version: z.number().int().min(1),
  state: z.enum(CVE_STATES),
  severity: z.enum(RECORD_SEVERITIES),
  cvssScore: z.number().nullable(),
  cvssVersion: z.enum(CVSS_VERSIONS).nullable(),
  inKev: z.boolean(),
  epssScore: z.number().nullable(),
  epssPercentile: z.number().nullable(),
  cweIds: z.array(z.string()),
  publishedAt: z.iso.datetime().nullable(),
  lastModifiedAt: z.iso.datetime().nullable(),
});
export type CveRecordSnapshot = z.infer<typeof cveRecordSnapshotSchema>;

export const cveRecordCreatedPayloadSchema = cveRecordSnapshotSchema.extend({
  actor: eventActorSchema,
});
export type CveRecordCreatedPayload = z.infer<typeof cveRecordCreatedPayloadSchema>;

export const cveRecordUpdatedPayloadSchema = cveRecordSnapshotSchema.extend({
  actor: eventActorSchema,
  changedFields: z.array(z.enum(CVE_CHANGE_FIELDS)).min(1),
  previousSeverity: z.enum(RECORD_SEVERITIES),
});
export type CveRecordUpdatedPayload = z.infer<typeof cveRecordUpdatedPayloadSchema>;

export const cveRecordDeletedPayloadSchema = z.object({
  recordId: z.uuid(),
  cveId: z.string(),
  /** Version of the record when it was deleted. */
  version: z.number().int().min(1),
  actor: eventActorSchema,
});
export type CveRecordDeletedPayload = z.infer<typeof cveRecordDeletedPayloadSchema>;
