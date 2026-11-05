import { z } from 'zod';

import { paginationQuerySchema } from '../api.js';
import { cveIdSchema } from '../cve/identifiers.js';
import { listParam, textSchema, timestampSchema } from '../cve/schemas.js';
import { artifactVerificationStatusSchema } from '../poc/schemas.js';

// ---------------------------------------------------------------------------- sources

/**
 * Approved download sources. Each one builds its own canonical URLs and is restricted to its own
 * host allowlist (every redirect hop is checked against it again).
 * - `github-archive`: the gzip tarball of a public GitHub repository at a fixed commit SHA
 *   (`codeload.github.com`). Commit SHAs are immutable, so the content cannot change later.
 * - `exploit-db`: the raw exploit file of an Exploit-DB entry.
 */
export const DOWNLOAD_SOURCES = ['github-archive', 'exploit-db'] as const;
export const downloadSourceSchema = z.enum(DOWNLOAD_SOURCES);
export type DownloadSource = z.infer<typeof downloadSourceSchema>;

/** Why a download was requested. */
export const DOWNLOAD_TRIGGERS = ['event', 'manual'] as const;
export const downloadTriggerSchema = z.enum(DOWNLOAD_TRIGGERS);
export type DownloadTrigger = z.infer<typeof downloadTriggerSchema>;

// ---------------------------------------------------------------------------- requests

/**
 * - `pending`: waiting for its scheduled time or a worker (also between retries);
 * - `downloading`: a worker is fetching it;
 * - `stored`: new content, uploaded to the quarantine bucket;
 * - `duplicate`: the content (SHA-256) was already stored; linked to the existing artifact;
 * - `failed`: every attempt failed with a retryable error (network, 429, 5xx);
 * - `rejected`: refused by policy (allowlist, private address, size, MIME type, HTTP 4xx);
 * - `cancelled`: cancelled before it ran.
 */
export const DOWNLOAD_REQUEST_STATUSES = [
  'pending',
  'downloading',
  'stored',
  'duplicate',
  'failed',
  'rejected',
  'cancelled',
] as const;
export const downloadRequestStatusSchema = z.enum(DOWNLOAD_REQUEST_STATUSES);
export type DownloadRequestStatus = z.infer<typeof downloadRequestStatusSchema>;

/** Machine-readable failure reasons of a download attempt. */
export const DOWNLOAD_ERROR_CODES = [
  'source-disabled',
  'url-not-allowed',
  'host-not-allowed',
  'address-blocked',
  'dns-failure',
  'too-many-redirects',
  'invalid-redirect',
  'connect-failed',
  'tls-failure',
  'timeout',
  'http-error',
  'rate-limited',
  'unsupported-encoding',
  'content-type-not-allowed',
  'file-type-not-allowed',
  'size-limit-exceeded',
  'size-mismatch',
  'empty-response',
  'storage-failure',
  'internal-error',
] as const;
export const downloadErrorCodeSchema = z.enum(DOWNLOAD_ERROR_CODES);
export type DownloadErrorCode = z.infer<typeof downloadErrorCodeSchema>;

export const DOWNLOAD_ATTEMPT_OUTCOMES = ['succeeded', 'failed', 'rejected'] as const;
export const downloadAttemptOutcomeSchema = z.enum(DOWNLOAD_ATTEMPT_OUTCOMES);
export type DownloadAttemptOutcome = z.infer<typeof downloadAttemptOutcomeSchema>;

/** One hop of the request chain, as recorded for provenance. */
export const downloadHopSchema = z.object({
  url: z.string(),
  /** Addresses DNS returned; every one was checked before connecting. */
  resolvedAddresses: z.array(z.string()),
  /** Address the connection was pinned to. */
  connectedAddress: z.string().nullable(),
  status: z.number().int().nullable(),
  location: z.string().nullable(),
});
export type DownloadHop = z.infer<typeof downloadHopSchema>;

export const downloadAttemptSchema = z.object({
  id: z.uuid(),
  attempt: z.number().int().min(1),
  jobId: z.string().nullable(),
  outcome: downloadAttemptOutcomeSchema.nullable(),
  errorCode: downloadErrorCodeSchema.nullable(),
  error: z.string().nullable(),
  retryable: z.boolean().nullable(),
  httpStatus: z.number().int().nullable(),
  hops: z.array(downloadHopSchema),
  finalUrl: z.string().nullable(),
  declaredContentType: z.string().nullable(),
  declaredLength: z.number().int().nullable(),
  bytesReceived: z.number().int().min(0),
  sha256: z.string().nullable(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime().nullable(),
  durationMs: z.number().int().nullable(),
});
export type DownloadAttempt = z.infer<typeof downloadAttemptSchema>;

export const downloadRequestSchema = z.object({
  id: z.uuid(),
  source: downloadSourceSchema,
  sourceUrl: z.string(),
  trigger: downloadTriggerSchema,
  status: downloadRequestStatusSchema,
  pocArtifactId: z.uuid().nullable(),
  pocRepositoryId: z.uuid().nullable(),
  sourceRepository: z.string().nullable(),
  commitSha: z.string().nullable(),
  cveIds: z.array(cveIdSchema),
  priority: z.number().int(),
  scheduledFor: z.iso.datetime(),
  attempts: z.number().int().min(0),
  maxAttempts: z.number().int().min(1),
  errorCode: downloadErrorCodeSchema.nullable(),
  error: z.string().nullable(),
  artifactId: z.uuid().nullable(),
  requestedBy: z.string().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime().nullable(),
  version: z.number().int().min(1),
});
export type DownloadRequest = z.infer<typeof downloadRequestSchema>;

export const downloadRequestDetailSchema = downloadRequestSchema.extend({
  attemptHistory: z.array(downloadAttemptSchema),
});
export type DownloadRequestDetail = z.infer<typeof downloadRequestDetailSchema>;

// ---------------------------------------------------------------------------- artifacts

/**
 * Lifecycle of a stored artifact. Every download lands in `quarantined`; only an administrator
 * (`quarantine:manage`) can release an artifact, and only when its scan is `clean` and no linked
 * PoC artifact is judged malicious or rejected. Release is not verification.
 */
export const ARTIFACT_LIFECYCLE_STATUSES = ['quarantined', 'released', 'rejected'] as const;
export const artifactLifecycleStatusSchema = z.enum(ARTIFACT_LIFECYCLE_STATUSES);
export type ArtifactLifecycleStatus = z.infer<typeof artifactLifecycleStatusSchema>;

export const ARTIFACT_LIFECYCLE_TRANSITIONS: Readonly<
  Record<ArtifactLifecycleStatus, readonly ArtifactLifecycleStatus[]>
> = {
  quarantined: ['released', 'rejected'],
  released: ['quarantined', 'rejected'],
  rejected: ['quarantined'],
};

export function canTransitionLifecycle(
  from: ArtifactLifecycleStatus,
  to: ArtifactLifecycleStatus,
): boolean {
  return ARTIFACT_LIFECYCLE_TRANSITIONS[from].includes(to);
}

/**
 * Aggregated scan state:
 * - `pending` / `scanning`: not scanned yet;
 * - `clean`: every required scanner ran and found nothing;
 * - `suspicious`: a heuristic (YARA rule) matched;
 * - `malicious`: an antivirus signature matched;
 * - `incomplete`: a required scanner is not configured, unavailable or failed (never `clean`);
 * - `integrity-failure`: the stored object no longer matches its SHA-256.
 */
export const ARTIFACT_SCAN_STATUSES = [
  'pending',
  'scanning',
  'clean',
  'suspicious',
  'malicious',
  'incomplete',
  'integrity-failure',
] as const;
export const artifactScanStatusSchema = z.enum(ARTIFACT_SCAN_STATUSES);
export type ArtifactScanStatus = z.infer<typeof artifactScanStatusSchema>;

export const ARTIFACT_SCANNERS = ['clamav', 'yara'] as const;
export const artifactScannerSchema = z.enum(ARTIFACT_SCANNERS);
export type ArtifactScanner = z.infer<typeof artifactScannerSchema>;

export const SCAN_VERDICTS = [
  'clean',
  'suspicious',
  'malicious',
  'error',
  'not-configured',
] as const;
export const scanVerdictSchema = z.enum(SCAN_VERDICTS);
export type ScanVerdict = z.infer<typeof scanVerdictSchema>;

/**
 * File types recognised from the first bytes of the content (never from the name or the
 * declared Content-Type, which the source controls).
 */
export const DETECTED_FILE_TYPES = [
  'gzip',
  'zip',
  'tar',
  'bzip2',
  'xz',
  '7z',
  'rar',
  'pe-executable',
  'elf-executable',
  'mach-o-executable',
  'java-class',
  'pdf',
  'ole-document',
  'script',
  'text',
  'binary',
  'empty',
] as const;
export const detectedFileTypeSchema = z.enum(DETECTED_FILE_TYPES);
export type DetectedFileType = z.infer<typeof detectedFileTypeSchema>;

/** Risk indicators derived from the content type (the content is never opened or run). */
export const DOWNLOAD_RISK_INDICATORS = [
  'archive',
  'executable',
  'script',
  'macro-capable-document',
  'content-type-mismatch',
] as const;
export const downloadRiskIndicatorSchema = z.enum(DOWNLOAD_RISK_INDICATORS);
export type DownloadRiskIndicator = z.infer<typeof downloadRiskIndicatorSchema>;

export const scanFindingSchema = z.object({
  /** Antivirus signature or YARA rule name. */
  name: z.string(),
  /** YARA namespace/tags or ClamAV detail. */
  detail: z.string().nullable(),
});
export type ScanFinding = z.infer<typeof scanFindingSchema>;

export const scanResultSchema = z.object({
  id: z.uuid(),
  scanner: artifactScannerSchema,
  verdict: scanVerdictSchema,
  findings: z.array(scanFindingSchema),
  engineVersion: z.string().nullable(),
  signatureVersion: z.string().nullable(),
  error: z.string().nullable(),
  scanRunId: z.uuid(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime(),
});
export type ScanResult = z.infer<typeof scanResultSchema>;

/** Where (and why) a stored artifact was obtained. One per download that produced it. */
export const artifactProvenanceSchema = z.object({
  requestId: z.uuid(),
  source: downloadSourceSchema,
  sourceUrl: z.string(),
  finalUrl: z.string().nullable(),
  sourceRepository: z.string().nullable(),
  pocArtifactId: z.uuid().nullable(),
  commitSha: z.string().nullable(),
  cveIds: z.array(cveIdSchema),
  discoveredAt: z.iso.datetime(),
  downloadedAt: z.iso.datetime(),
});
export type ArtifactProvenance = z.infer<typeof artifactProvenanceSchema>;

export const downloadArtifactSchema = z.object({
  id: z.uuid(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  sizeBytes: z.number().int().min(0),
  /** Always `application/octet-stream` when served; this is the sniffed type. */
  mimeType: z.string(),
  detectedType: detectedFileTypeSchema,
  declaredContentType: z.string().nullable(),
  /** Untrusted name suggested by the source (metadata only; never a path or object key). */
  originalFilename: z.string().nullable(),
  storageBucket: z.string(),
  storageKey: z.string(),
  source: downloadSourceSchema,
  sourceUrl: z.string(),
  sourceRepository: z.string().nullable(),
  cveIds: z.array(cveIdSchema),
  riskIndicators: z.array(downloadRiskIndicatorSchema),
  lifecycleStatus: artifactLifecycleStatusSchema,
  scanStatus: artifactScanStatusSchema,
  /**
   * Analysts' verification from the PoC Service (`unverified` until someone reviews it). A
   * successful download or a clean scan never changes it.
   */
  verificationStatus: artifactVerificationStatusSchema,
  pocArtifactIds: z.array(z.uuid()),
  releasable: z.boolean(),
  discoveredAt: z.iso.datetime(),
  downloadedAt: z.iso.datetime(),
  lastScannedAt: z.iso.datetime().nullable(),
  releasedAt: z.iso.datetime().nullable(),
  version: z.number().int().min(1),
});
export type DownloadArtifact = z.infer<typeof downloadArtifactSchema>;

export const downloadArtifactDetailSchema = downloadArtifactSchema.extend({
  provenance: z.array(artifactProvenanceSchema),
  latestScan: z.array(scanResultSchema),
});
export type DownloadArtifactDetail = z.infer<typeof downloadArtifactDetailSchema>;

export const lifecycleEventSchema = z.object({
  id: z.uuid(),
  fromStatus: artifactLifecycleStatusSchema.nullable(),
  toStatus: artifactLifecycleStatusSchema,
  reason: z.string(),
  actorId: z.string(),
  actorUsername: z.string().nullable(),
  createdAt: z.iso.datetime(),
});
export type LifecycleEvent = z.infer<typeof lifecycleEventSchema>;

export const downloadSourceStatusSchema = z.object({
  source: downloadSourceSchema,
  name: z.string(),
  description: z.string(),
  enabled: z.boolean(),
  automatic: z.boolean(),
  allowedHosts: z.array(z.string()),
  allowedFileTypes: z.array(detectedFileTypeSchema),
  allowedContentTypes: z.array(z.string()),
  maxBytes: z.number().int(),
  termsUrl: z.string().nullable(),
});
export type DownloadSourceStatus = z.infer<typeof downloadSourceStatusSchema>;

// ---------------------------------------------------------------------------- queries

const sortOrder = z.enum(['asc', 'desc']).default('desc');
const sha256Param = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[0-9a-f]{64}$/, { message: 'must be a SHA-256 hex digest' });

export const listDownloadRequestsQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  status: listParam(downloadRequestStatusSchema, DOWNLOAD_REQUEST_STATUSES.length).optional(),
  source: downloadSourceSchema.optional(),
  trigger: downloadTriggerSchema.optional(),
  cveId: cveIdSchema.optional(),
  pocArtifactId: z.uuid().optional(),
  artifactId: z.uuid().optional(),
  createdFrom: timestampSchema.optional(),
  sort: z.enum(['createdAt', 'scheduledFor', 'finishedAt']).default('createdAt'),
  order: sortOrder,
});
export type ListDownloadRequestsQuery = z.output<typeof listDownloadRequestsQuerySchema>;

export const listDownloadArtifactsQuerySchema = z.strictObject({
  ...paginationQuerySchema.shape,
  lifecycleStatus: listParam(
    artifactLifecycleStatusSchema,
    ARTIFACT_LIFECYCLE_STATUSES.length,
  ).optional(),
  scanStatus: listParam(artifactScanStatusSchema, ARTIFACT_SCAN_STATUSES.length).optional(),
  source: downloadSourceSchema.optional(),
  cveId: cveIdSchema.optional(),
  sha256: sha256Param.optional(),
  pocArtifactId: z.uuid().optional(),
  sort: z.enum(['downloadedAt', 'sizeBytes', 'lastScannedAt']).default('downloadedAt'),
  order: sortOrder,
});
export type ListDownloadArtifactsQuery = z.output<typeof listDownloadArtifactsQuerySchema>;

// ---------------------------------------------------------------------------- write models

const reasonSchema = textSchema(2_000);

/**
 * `POST /api/v1/download-requests`: schedule a download. Either a URL that an enabled source
 * recognises, or a PoC artifact known from the PoC Service's events (downloaded from its
 * repository at that commit).
 */
export const createDownloadRequestSchema = z
  .strictObject({
    url: z.string().trim().min(8).max(2_048).optional(),
    pocArtifactId: z.uuid().optional(),
    cveIds: z.array(cveIdSchema).max(50).default([]),
    /** Not before this time (download scheduling); default now. */
    scheduledFor: timestampSchema.optional(),
    /** 1 (highest) … 10 (lowest). */
    priority: z.number().int().min(1).max(10).default(5),
    reason: reasonSchema.nullable().default(null),
  })
  .superRefine((value, ctx) => {
    if ((value.url === undefined) === (value.pocArtifactId === undefined)) {
      ctx.addIssue({
        code: 'custom',
        path: ['url'],
        message: 'exactly one of url or pocArtifactId is required',
      });
    }
  });
export type CreateDownloadRequest = z.output<typeof createDownloadRequestSchema>;

export const createDownloadResponseSchema = z.object({
  request: downloadRequestSchema,
  /** False when the same canonical URL was already requested (the existing request is returned). */
  created: z.boolean(),
});
export type CreateDownloadResponse = z.infer<typeof createDownloadResponseSchema>;

/** `POST /api/v1/download-artifacts/:id/lifecycle`. */
export const changeLifecycleRequestSchema = z.strictObject({
  status: artifactLifecycleStatusSchema,
  reason: reasonSchema,
});
export type ChangeLifecycleRequest = z.output<typeof changeLifecycleRequestSchema>;

export const rescanRequestSchema = z.strictObject({ reason: reasonSchema });
export type RescanRequest = z.output<typeof rescanRequestSchema>;
