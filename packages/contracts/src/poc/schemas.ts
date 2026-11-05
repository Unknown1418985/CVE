import { z } from 'zod';

import { paginationQuerySchema } from '../api.js';
import { cveIdSchema } from '../cve/identifiers.js';
import { booleanParam, listParam, textSchema, timestampSchema } from '../cve/schemas.js';

// ---------------------------------------------------------------------------- connectors

/**
 * Approved PoC discovery connectors. Only connectors in this list can be enabled; each one is
 * restricted to its own allowlisted origins.
 * - `github`: GitHub repository search and repository metadata (REST API). Metadata only: no
 *   repository content is cloned, downloaded or executed.
 * - `cve-references`: references of CVE records observed by the Intelligence Service that point
 *   to public PoC locations (GitHub repositories, Exploit-DB, …).
 */
export const POC_CONNECTORS = ['github', 'cve-references'] as const;
export const pocConnectorSchema = z.enum(POC_CONNECTORS);
export type PocConnector = z.infer<typeof pocConnectorSchema>;

/** Where repositories are hosted. Only GitHub is supported so far. */
export const POC_REPOSITORY_SOURCES = ['github'] as const;
export const pocRepositorySourceSchema = z.enum(POC_REPOSITORY_SOURCES);
export type PocRepositorySource = z.infer<typeof pocRepositorySourceSchema>;

// ---------------------------------------------------------------------------- discovery runs

/**
 * - `cve`: search the connector for one CVE ID.
 * - `recent`: sweep repositories pushed since the connector's cursor.
 * - `repository`: re-inspect one known repository (metadata and latest commit).
 */
export const DISCOVERY_MODES = ['cve', 'recent', 'repository'] as const;
export const discoveryModeSchema = z.enum(DISCOVERY_MODES);
export type DiscoveryMode = z.infer<typeof discoveryModeSchema>;

export const DISCOVERY_TRIGGERS = ['scheduled', 'manual', 'event'] as const;
export const discoveryTriggerSchema = z.enum(DISCOVERY_TRIGGERS);
export type DiscoveryTrigger = z.infer<typeof discoveryTriggerSchema>;

export const DISCOVERY_RUN_STATUSES = ['running', 'succeeded', 'failed'] as const;
export const discoveryRunStatusSchema = z.enum(DISCOVERY_RUN_STATUSES);
export type DiscoveryRunStatus = z.infer<typeof discoveryRunStatusSchema>;

export const discoveryRunStatsSchema = z.object({
  /** HTTP requests sent to the connector, including retries. */
  requests: z.number().int().min(0),
  /** Repositories returned by the connector. */
  candidates: z.number().int().min(0),
  repositoriesCreated: z.number().int().min(0),
  repositoriesUpdated: z.number().int().min(0),
  /** Repositories identical to what is stored. */
  unchanged: z.number().int().min(0),
  associationsCreated: z.number().int().min(0),
  associationsUpdated: z.number().int().min(0),
  /** Candidate associations below the minimum confidence; not stored. */
  associationsDiscarded: z.number().int().min(0),
  artifactsCreated: z.number().int().min(0),
  duplicatesDetected: z.number().int().min(0),
  referencesCreated: z.number().int().min(0),
  /** Items refused by validation. */
  invalid: z.number().int().min(0),
  /** Repository inspections queued. */
  inspectionsQueued: z.number().int().min(0),
});
export type DiscoveryRunStats = z.infer<typeof discoveryRunStatsSchema>;

export const EMPTY_DISCOVERY_RUN_STATS: DiscoveryRunStats = {
  requests: 0,
  candidates: 0,
  repositoriesCreated: 0,
  repositoriesUpdated: 0,
  unchanged: 0,
  associationsCreated: 0,
  associationsUpdated: 0,
  associationsDiscarded: 0,
  artifactsCreated: 0,
  duplicatesDetected: 0,
  referencesCreated: 0,
  invalid: 0,
  inspectionsQueued: 0,
};

// ---------------------------------------------------------------------------- associations

export const CONFIDENCE_LEVELS = ['high', 'medium', 'low'] as const;
export const confidenceLevelSchema = z.enum(CONFIDENCE_LEVELS);
export type ConfidenceLevel = z.infer<typeof confidenceLevelSchema>;

/**
 * Evidence that a repository relates to a CVE. Repository names, descriptions, topics and file
 * names are written by the repository owner and are never trusted on their own: every signal
 * only contributes a bounded weight to the confidence score.
 */
export const ASSOCIATION_SIGNAL_KINDS = [
  /** The CVE ID appears as a token in the repository name. */
  'name',
  /** The CVE ID is a repository topic. */
  'topic',
  /** The CVE ID appears in the (untrusted) description. */
  'description',
  /** The CVE ID appears in a file or directory name of the latest commit. */
  'file-path',
  /** A CVE record lists the repository as a reference. */
  'cve-reference',
  /** A CVE record lists the repository as a reference tagged as an exploit. */
  'cve-exploit-reference',
  /** The connector's search returned the repository for this CVE without literal evidence. */
  'search-match',
  /** An analyst associated the repository with the CVE. */
  'manual',
] as const;
export const associationSignalKindSchema = z.enum(ASSOCIATION_SIGNAL_KINDS);
export type AssociationSignalKind = z.infer<typeof associationSignalKindSchema>;

/** Factors that lower the confidence of every text-derived signal. */
export const ASSOCIATION_PENALTY_KINDS = [
  /** The repository mentions many CVE IDs (a collection or list, not a specific PoC). */
  'multi-cve',
  /** The repository is a fork: its text is copied from the parent. */
  'fork',
  /** The repository has no files. */
  'empty-repository',
  /** The latest commit contains no source code or scripts (only documents or binaries). */
  'no-source-code',
  /** The repository was created more than a year before the CVE ID's year. */
  'predates-cve',
] as const;
export const associationPenaltyKindSchema = z.enum(ASSOCIATION_PENALTY_KINDS);
export type AssociationPenaltyKind = z.infer<typeof associationPenaltyKindSchema>;

export const associationSignalSchema = z.object({
  kind: associationSignalKindSchema,
  weight: z.number().min(0).max(1),
  /** Short, sanitised excerpt explaining the match (untrusted text, render as plain text). */
  evidence: z.string().max(300).nullable(),
});
export type AssociationSignal = z.infer<typeof associationSignalSchema>;

export const associationPenaltySchema = z.object({
  kind: associationPenaltyKindSchema,
  factor: z.number().min(0).max(1),
  detail: z.string().max(300).nullable(),
});
export type AssociationPenalty = z.infer<typeof associationPenaltySchema>;

/**
 * Analyst review of an association. Discovery never confirms on its own; a rejected
 * association stays rejected when the repository is discovered again.
 */
export const ASSOCIATION_REVIEW_STATUSES = ['candidate', 'confirmed', 'rejected'] as const;
export const associationReviewStatusSchema = z.enum(ASSOCIATION_REVIEW_STATUSES);
export type AssociationReviewStatus = z.infer<typeof associationReviewStatusSchema>;

export const POC_ASSOCIATION_ORIGINS = ['discovered', 'manual'] as const;
export const pocAssociationOriginSchema = z.enum(POC_ASSOCIATION_ORIGINS);
export type PocAssociationOrigin = z.infer<typeof pocAssociationOriginSchema>;

// ---------------------------------------------------------------------------- artifacts

/**
 * Verification state of an artifact (one repository snapshot at a commit). Every new commit
 * creates a new artifact that starts `unverified`: a verdict never carries over to content
 * nobody has reviewed.
 */
export const ARTIFACT_VERIFICATION_STATUSES = [
  'unverified',
  'in-review',
  /** An analyst confirmed it is a genuine PoC. */
  'verified',
  /** Not a working PoC (fake, broken, unrelated). */
  'rejected',
  /** Contains malware or harmful content; leaving this state needs `quarantine:manage`. */
  'malicious',
] as const;
export const artifactVerificationStatusSchema = z.enum(ARTIFACT_VERIFICATION_STATUSES);
export type ArtifactVerificationStatus = z.infer<typeof artifactVerificationStatusSchema>;

/** Allowed transitions (from → to). */
export const ARTIFACT_VERIFICATION_TRANSITIONS: Readonly<
  Record<ArtifactVerificationStatus, readonly ArtifactVerificationStatus[]>
> = {
  unverified: ['in-review', 'verified', 'rejected', 'malicious'],
  'in-review': ['unverified', 'verified', 'rejected', 'malicious'],
  verified: ['in-review', 'rejected', 'malicious'],
  rejected: ['in-review', 'malicious'],
  malicious: ['in-review'],
};

export function canTransitionVerification(
  from: ArtifactVerificationStatus,
  to: ArtifactVerificationStatus,
): boolean {
  return ARTIFACT_VERIFICATION_TRANSITIONS[from].includes(to);
}

export const DUPLICATE_KINDS = [
  /** Same Git tree as an artifact discovered earlier: byte-identical content. */
  'exact',
  /** Most significant files are byte-identical to an earlier artifact. */
  'near',
] as const;
export const duplicateKindSchema = z.enum(DUPLICATE_KINDS);
export type DuplicateKind = z.infer<typeof duplicateKindSchema>;

/**
 * Metadata-only warnings derived from the file listing (no file is downloaded). They do not
 * decide anything; they tell reviewers what to look at first.
 */
export const RISK_INDICATORS = [
  'contains-executables',
  'contains-archives',
  'contains-macro-documents',
  'no-source-code',
  'empty',
  'listing-truncated',
  'duplicate-of-malicious',
] as const;
export const riskIndicatorSchema = z.enum(RISK_INDICATORS);
export type RiskIndicator = z.infer<typeof riskIndicatorSchema>;

export const REPOSITORY_STATUSES = [
  'active',
  /** The source no longer serves the repository (deleted, made private, blocked). */
  'unavailable',
] as const;
export const repositoryStatusSchema = z.enum(REPOSITORY_STATUSES);
export type RepositoryStatus = z.infer<typeof repositoryStatusSchema>;

export const OWNER_TYPES = ['user', 'organization', 'bot', 'unknown'] as const;
export const ownerTypeSchema = z.enum(OWNER_TYPES);
export type OwnerType = z.infer<typeof ownerTypeSchema>;

/** Kinds of public PoC references found in CVE records. */
export const POC_REFERENCE_KINDS = [
  'github-repository',
  'github-gist',
  'exploit-db',
  'packet-storm',
  'other',
] as const;
export const pocReferenceKindSchema = z.enum(POC_REFERENCE_KINDS);
export type PocReferenceKind = z.infer<typeof pocReferenceKindSchema>;

// ---------------------------------------------------------------------------- read models

const gitShaSchema = z.string().regex(/^[0-9a-f]{40}$/);
const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);

export const pocOwnerSchema = z.object({
  id: z.uuid(),
  source: pocRepositorySourceSchema,
  externalId: z.string(),
  login: z.string(),
  type: ownerTypeSchema,
  url: z.string(),
  repositoryCount: z.number().int().min(0),
  firstSeenAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime(),
});
export type PocOwner = z.infer<typeof pocOwnerSchema>;

export const repositoryCommitSchema = z.object({
  sha: gitShaSchema,
  treeSha: gitShaSchema,
  /** Committer date reported by the source (set by the committer; not trustworthy). */
  committedAt: z.iso.datetime().nullable(),
  observedAt: z.iso.datetime(),
});
export type RepositoryCommit = z.infer<typeof repositoryCommitSchema>;

export const pocRepositorySchema = z.object({
  id: z.uuid(),
  source: pocRepositorySourceSchema,
  /** Stable identifier at the source (GitHub repository ID); survives renames. */
  externalId: z.string(),
  fullName: z.string(),
  name: z.string(),
  /** Canonical URL built by the service from the validated owner and name. */
  url: z.string(),
  owner: pocOwnerSchema.pick({ id: true, login: true, type: true, url: true }),
  /** Written by the repository owner: untrusted, render as plain text only. */
  description: z.string().nullable(),
  topics: z.array(z.string()),
  language: z.string().nullable(),
  stars: z.number().int().min(0),
  forks: z.number().int().min(0),
  isFork: z.boolean(),
  parentFullName: z.string().nullable(),
  isArchived: z.boolean(),
  defaultBranch: z.string().nullable(),
  sizeKb: z.number().int().min(0),
  status: repositoryStatusSchema,
  sourceCreatedAt: z.iso.datetime().nullable(),
  sourcePushedAt: z.iso.datetime().nullable(),
  latestCommit: repositoryCommitSchema.nullable(),
  /** Highest confidence among the non-rejected CVE associations. */
  maxConfidence: z.number().min(0).max(1).nullable(),
  cveIds: z.array(z.string()),
  discoveredBy: pocConnectorSchema,
  firstDiscoveredAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime(),
  lastInspectedAt: z.iso.datetime().nullable(),
  version: z.number().int().min(1),
});
export type PocRepository = z.infer<typeof pocRepositorySchema>;

export const pocAssociationSchema = z.object({
  id: z.uuid(),
  repositoryId: z.uuid(),
  repositoryFullName: z.string(),
  repositoryUrl: z.string(),
  cveId: z.string(),
  confidence: z.number().min(0).max(1),
  confidenceLevel: confidenceLevelSchema,
  signals: z.array(associationSignalSchema),
  penalties: z.array(associationPenaltySchema),
  scoringVersion: z.number().int().min(1),
  origin: pocAssociationOriginSchema,
  reviewStatus: associationReviewStatusSchema,
  reviewedBy: z.string().nullable(),
  reviewedAt: z.iso.datetime().nullable(),
  reviewNote: z.string().nullable(),
  firstDiscoveredAt: z.iso.datetime(),
  lastEvaluatedAt: z.iso.datetime(),
  version: z.number().int().min(1),
});
export type PocAssociation = z.infer<typeof pocAssociationSchema>;

export const artifactFileSchema = z.object({
  /** Path inside the repository (untrusted text; never used as a filesystem path). */
  path: z.string(),
  blobSha: gitShaSchema,
  sizeBytes: z.number().int().min(0).nullable(),
  category: z.enum(['source', 'document', 'executable', 'archive', 'macro-document', 'other']),
});
export type ArtifactFile = z.infer<typeof artifactFileSchema>;

export const pocArtifactSchema = z.object({
  id: z.uuid(),
  repositoryId: z.uuid(),
  repositoryFullName: z.string(),
  repositoryUrl: z.string(),
  commitSha: gitShaSchema,
  treeSha: gitShaSchema,
  /** SHA-256 over the sorted file listing (path, mode, blob SHA): a content fingerprint. */
  fingerprint: sha256Schema,
  fileCount: z.number().int().min(0),
  totalBytes: z.number().int().min(0),
  listingTruncated: z.boolean(),
  riskIndicators: z.array(riskIndicatorSchema),
  duplicate: z
    .object({
      kind: duplicateKindSchema,
      ofArtifactId: z.uuid(),
      ofRepositoryFullName: z.string(),
      similarity: z.number().min(0).max(1),
    })
    .nullable(),
  verificationStatus: artifactVerificationStatusSchema,
  verificationUpdatedAt: z.iso.datetime().nullable(),
  verificationUpdatedBy: z.string().nullable(),
  discoveredAt: z.iso.datetime(),
  version: z.number().int().min(1),
});
export type PocArtifact = z.infer<typeof pocArtifactSchema>;

export const pocArtifactDetailSchema = pocArtifactSchema.extend({
  files: z.array(artifactFileSchema),
});
export type PocArtifactDetail = z.infer<typeof pocArtifactDetailSchema>;

export const verificationEventSchema = z.object({
  id: z.uuid(),
  artifactId: z.uuid(),
  fromStatus: artifactVerificationStatusSchema,
  toStatus: artifactVerificationStatusSchema,
  reason: z.string(),
  actorId: z.string(),
  actorUsername: z.string().nullable(),
  createdAt: z.iso.datetime(),
});
export type VerificationEvent = z.infer<typeof verificationEventSchema>;

export const pocReferenceSchema = z.object({
  id: z.uuid(),
  cveId: z.string(),
  url: z.string(),
  kind: pocReferenceKindSchema,
  /** Intelligence source whose CVE record lists the reference (`nvd`, `mitre-cve`, …). */
  source: z.string(),
  tags: z.array(z.string()),
  repositoryId: z.uuid().nullable(),
  firstSeenAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime(),
});
export type PocReference = z.infer<typeof pocReferenceSchema>;

export const discoveryRunSchema = z.object({
  id: z.uuid(),
  connector: pocConnectorSchema,
  mode: discoveryModeSchema,
  trigger: discoveryTriggerSchema,
  status: discoveryRunStatusSchema,
  cveId: z.string().nullable(),
  repositoryId: z.uuid().nullable(),
  jobId: z.string().nullable(),
  attempt: z.number().int().min(1),
  requestedBy: z.string().nullable(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime().nullable(),
  stats: discoveryRunStatsSchema,
  error: z.string().nullable(),
});
export type DiscoveryRun = z.infer<typeof discoveryRunSchema>;

export const pocConnectorStatusSchema = z.object({
  connector: pocConnectorSchema,
  name: z.string(),
  description: z.string(),
  approved: z.boolean(),
  enabled: z.boolean(),
  allowedOrigins: z.array(z.string()),
  authentication: z.object({
    mode: z.enum(['none', 'optional']),
    configured: z.boolean(),
  }),
  schedule: z.string().nullable(),
  termsUrl: z.string().nullable(),
  cursor: z.record(z.string(), z.unknown()).nullable(),
  lastRunAt: z.iso.datetime().nullable(),
  lastRunStatus: discoveryRunStatusSchema.nullable(),
});
export type PocConnectorStatus = z.infer<typeof pocConnectorStatusSchema>;

// ---------------------------------------------------------------------------- queries

const sortOrder = z.enum(['asc', 'desc']).default('desc');
const confidenceParam = z.coerce.number().min(0).max(1);

export const POC_REPOSITORY_SORT_FIELDS = [
  'firstDiscoveredAt',
  'lastSeenAt',
  'stars',
  'maxConfidence',
  'sourcePushedAt',
] as const;

export const listPocRepositoriesQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  /** Substring of the full name (case-insensitive). */
  q: z.string().trim().min(2).max(200).optional(),
  cveId: cveIdSchema.optional(),
  owner: z.string().trim().min(1).max(64).optional(),
  status: repositoryStatusSchema.optional(),
  minConfidence: confidenceParam.optional(),
  isFork: booleanParam.optional(),
  sort: z.enum(POC_REPOSITORY_SORT_FIELDS).default('firstDiscoveredAt'),
  order: sortOrder,
});
export type ListPocRepositoriesQuery = z.output<typeof listPocRepositoriesQuerySchema>;

export const listPocOwnersQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  q: z.string().trim().min(1).max(64).optional(),
  sort: z.enum(['login', 'repositoryCount', 'firstSeenAt']).default('repositoryCount'),
  order: sortOrder,
});
export type ListPocOwnersQuery = z.output<typeof listPocOwnersQuerySchema>;

export const listPocAssociationsQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  cveId: cveIdSchema.optional(),
  repositoryId: z.uuid().optional(),
  reviewStatus: listParam(associationReviewStatusSchema, 3).optional(),
  confidenceLevel: listParam(confidenceLevelSchema, 3).optional(),
  minConfidence: confidenceParam.optional(),
  sort: z.enum(['confidence', 'firstDiscoveredAt', 'lastEvaluatedAt']).default('confidence'),
  order: sortOrder,
});
export type ListPocAssociationsQuery = z.output<typeof listPocAssociationsQuerySchema>;

export const listPocArtifactsQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  repositoryId: z.uuid().optional(),
  cveId: cveIdSchema.optional(),
  verificationStatus: listParam(
    artifactVerificationStatusSchema,
    ARTIFACT_VERIFICATION_STATUSES.length,
  ).optional(),
  duplicate: booleanParam.optional(),
  fingerprint: sha256Schema.optional(),
  sort: z.enum(['discoveredAt', 'verificationUpdatedAt']).default('discoveredAt'),
  order: sortOrder,
});
export type ListPocArtifactsQuery = z.output<typeof listPocArtifactsQuerySchema>;

export const listPocReferencesQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  cveId: cveIdSchema.optional(),
  kind: listParam(pocReferenceKindSchema, POC_REFERENCE_KINDS.length).optional(),
  order: sortOrder,
});
export type ListPocReferencesQuery = z.output<typeof listPocReferencesQuerySchema>;

export const listDiscoveryRunsQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  connector: pocConnectorSchema.optional(),
  mode: discoveryModeSchema.optional(),
  status: discoveryRunStatusSchema.optional(),
  cveId: cveIdSchema.optional(),
  startedFrom: timestampSchema.optional(),
});
export type ListDiscoveryRunsQuery = z.output<typeof listDiscoveryRunsQuerySchema>;

// ---------------------------------------------------------------------------- write models

const reasonSchema = textSchema(2_000);

/** `POST /api/v1/poc-discovery-runs`: queue a discovery job. */
export const triggerDiscoveryRequestSchema = z.discriminatedUnion('mode', [
  z.strictObject({ mode: z.literal('cve'), connector: z.literal('github'), cveId: cveIdSchema }),
  z.strictObject({ mode: z.literal('recent'), connector: z.literal('github') }),
  z.strictObject({
    mode: z.literal('repository'),
    connector: z.literal('github'),
    repositoryId: z.uuid(),
  }),
]);
export type TriggerDiscoveryRequest = z.output<typeof triggerDiscoveryRequestSchema>;

export const triggerDiscoveryResponseSchema = z.object({
  jobId: z.string(),
  /** False when a job with the same idempotency key already exists. */
  queued: z.boolean(),
});
export type TriggerDiscoveryResponse = z.infer<typeof triggerDiscoveryResponseSchema>;

/** `PATCH /api/v1/poc-associations/:id`: analyst review. */
export const reviewAssociationRequestSchema = z.strictObject({
  reviewStatus: associationReviewStatusSchema,
  note: reasonSchema.nullable().default(null),
});
export type ReviewAssociationRequest = z.output<typeof reviewAssociationRequestSchema>;

/** `POST /api/v1/poc-associations`: manual association of a known repository with a CVE. */
export const createAssociationRequestSchema = z.strictObject({
  repositoryId: z.uuid(),
  cveId: cveIdSchema,
  note: reasonSchema.nullable().default(null),
});
export type CreateAssociationRequest = z.output<typeof createAssociationRequestSchema>;

/** `POST /api/v1/poc-artifacts/:id/verification`. */
export const changeVerificationRequestSchema = z.strictObject({
  status: artifactVerificationStatusSchema,
  reason: reasonSchema,
});
export type ChangeVerificationRequest = z.output<typeof changeVerificationRequestSchema>;
