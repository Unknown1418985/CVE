import { z } from 'zod';

import { eventActorSchema } from '../cve/events.js';
import { cveIdSchema } from '../cve/identifiers.js';
import {
  artifactVerificationStatusSchema,
  pocAssociationOriginSchema,
  associationReviewStatusSchema,
  associationSignalKindSchema,
  confidenceLevelSchema,
  discoveryModeSchema,
  discoveryRunStatsSchema,
  discoveryRunStatusSchema,
  discoveryTriggerSchema,
  duplicateKindSchema,
  pocConnectorSchema,
  pocReferenceKindSchema,
  pocRepositorySourceSchema,
  repositoryStatusSchema,
  riskIndicatorSchema,
} from './schemas.js';

/** Domain events published by the PoC Service (routing key = event type). */
export const POC_EVENT_TYPES = {
  repositoryDiscovered: 'poc.repository.discovered',
  repositoryUpdated: 'poc.repository.updated',
  associationDiscovered: 'poc.cve-association.discovered',
  associationUpdated: 'poc.cve-association.updated',
  associationReviewed: 'poc.cve-association.reviewed',
  artifactDiscovered: 'poc.artifact.discovered',
  artifactVerificationChanged: 'poc.artifact.verification-changed',
  referenceDiscovered: 'poc.reference.discovered',
  discoveryRunCompleted: 'poc.discovery-run.completed',
  discoveryRunFailed: 'poc.discovery-run.failed',
} as const;
export type PocEventType = (typeof POC_EVENT_TYPES)[keyof typeof POC_EVENT_TYPES];

const gitShaSchema = z.string().regex(/^[0-9a-f]{40}$/);

export const REPOSITORY_CHANGE_FIELDS = ['metadata', 'owner', 'name', 'status', 'commit'] as const;

/** Identity of a repository, so consumers can act without a lookup. */
export const repositorySnapshotSchema = z.object({
  repositoryId: z.uuid(),
  source: pocRepositorySourceSchema,
  externalId: z.string(),
  fullName: z.string(),
  url: z.string(),
  ownerLogin: z.string(),
  ownerExternalId: z.string(),
  status: repositoryStatusSchema,
  latestCommitSha: gitShaSchema.nullable(),
  version: z.number().int().min(1),
});
export type RepositorySnapshot = z.infer<typeof repositorySnapshotSchema>;

export const repositoryDiscoveredPayloadSchema = repositorySnapshotSchema.extend({
  connector: pocConnectorSchema,
  runId: z.uuid().nullable(),
});
export type RepositoryDiscoveredPayload = z.infer<typeof repositoryDiscoveredPayloadSchema>;

export const repositoryUpdatedPayloadSchema = repositorySnapshotSchema.extend({
  changedFields: z.array(z.enum(REPOSITORY_CHANGE_FIELDS)).min(1),
  runId: z.uuid().nullable(),
});
export type RepositoryUpdatedPayload = z.infer<typeof repositoryUpdatedPayloadSchema>;

/**
 * A CVE association changed. Consumers must use `confidence` and `reviewStatus`; a candidate is
 * a lead for analysts, not a confirmed PoC.
 */
export const associationChangedPayloadSchema = z.object({
  associationId: z.uuid(),
  repositoryId: z.uuid(),
  repositoryUrl: z.string(),
  cveId: cveIdSchema,
  confidence: z.number().min(0).max(1),
  confidenceLevel: confidenceLevelSchema,
  previousConfidence: z.number().min(0).max(1).nullable(),
  signalKinds: z.array(associationSignalKindSchema),
  scoringVersion: z.number().int().min(1),
  origin: pocAssociationOriginSchema,
  reviewStatus: associationReviewStatusSchema,
  actor: eventActorSchema,
});
export type AssociationChangedPayload = z.infer<typeof associationChangedPayloadSchema>;

/**
 * A new repository snapshot (one commit). The Download Service schedules downloads from it;
 * nothing has been downloaded yet and the content is untrusted.
 */
export const artifactDiscoveredPayloadSchema = z.object({
  artifactId: z.uuid(),
  repositoryId: z.uuid(),
  repositoryUrl: z.string(),
  repositoryFullName: z.string(),
  commitSha: gitShaSchema,
  treeSha: gitShaSchema,
  fingerprint: z.string().regex(/^[0-9a-f]{64}$/),
  fileCount: z.number().int().min(0),
  totalBytes: z.number().int().min(0),
  riskIndicators: z.array(riskIndicatorSchema),
  duplicate: z
    .object({
      kind: duplicateKindSchema,
      ofArtifactId: z.uuid(),
      similarity: z.number().min(0).max(1),
    })
    .nullable(),
  /** Non-rejected CVE associations of the repository when the snapshot was taken. */
  cveIds: z.array(cveIdSchema),
  verificationStatus: artifactVerificationStatusSchema,
});
export type ArtifactDiscoveredPayload = z.infer<typeof artifactDiscoveredPayloadSchema>;

export const artifactVerificationChangedPayloadSchema = z.object({
  artifactId: z.uuid(),
  repositoryId: z.uuid(),
  commitSha: gitShaSchema,
  fromStatus: artifactVerificationStatusSchema,
  toStatus: artifactVerificationStatusSchema,
  reason: z.string(),
  version: z.number().int().min(1),
  actor: eventActorSchema,
});
export type ArtifactVerificationChangedPayload = z.infer<
  typeof artifactVerificationChangedPayloadSchema
>;

export const referenceDiscoveredPayloadSchema = z.object({
  referenceId: z.uuid(),
  cveId: cveIdSchema,
  url: z.string(),
  kind: pocReferenceKindSchema,
  source: z.string(),
  tags: z.array(z.string()),
  repositoryId: z.uuid().nullable(),
});
export type ReferenceDiscoveredPayload = z.infer<typeof referenceDiscoveredPayloadSchema>;

export const discoveryRunFinishedPayloadSchema = z.object({
  runId: z.uuid(),
  connector: pocConnectorSchema,
  mode: discoveryModeSchema,
  trigger: discoveryTriggerSchema,
  status: discoveryRunStatusSchema,
  cveId: z.string().nullable(),
  repositoryId: z.uuid().nullable(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime(),
  stats: discoveryRunStatsSchema,
  error: z.string().nullable(),
  /** True when BullMQ retries the job. */
  willRetry: z.boolean(),
});
export type DiscoveryRunFinishedPayload = z.infer<typeof discoveryRunFinishedPayloadSchema>;
