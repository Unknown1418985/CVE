import { z } from 'zod';

import { eventActorSchema } from '../cve/events.js';
import { cveIdSchema } from '../cve/identifiers.js';
import { artifactVerificationStatusSchema } from '../poc/schemas.js';
import {
  artifactLifecycleStatusSchema,
  artifactScannerSchema,
  artifactScanStatusSchema,
  detectedFileTypeSchema,
  downloadErrorCodeSchema,
  downloadRequestStatusSchema,
  downloadRiskIndicatorSchema,
  downloadSourceSchema,
  downloadTriggerSchema,
  scanVerdictSchema,
} from './schemas.js';

/** Domain events published by the Download Service (routing key = event type). */
export const DOWNLOAD_EVENT_TYPES = {
  requestCompleted: 'download.request.completed',
  requestFailed: 'download.request.failed',
  artifactStored: 'download.artifact.stored',
  artifactScanned: 'download.artifact.scanned',
  artifactLifecycleChanged: 'download.artifact.lifecycle-changed',
} as const;
export type DownloadEventType = (typeof DOWNLOAD_EVENT_TYPES)[keyof typeof DOWNLOAD_EVENT_TYPES];

const sha256 = z.string().regex(/^[0-9a-f]{64}$/);

/** A request finished with stored (new content) or duplicate (already stored) content. */
export const downloadRequestCompletedPayloadSchema = z.object({
  requestId: z.uuid(),
  source: downloadSourceSchema,
  sourceUrl: z.string(),
  trigger: downloadTriggerSchema,
  status: z.enum(['stored', 'duplicate']),
  artifactId: z.uuid(),
  sha256,
  sizeBytes: z.number().int().min(0),
  pocArtifactId: z.uuid().nullable(),
  cveIds: z.array(cveIdSchema),
  attempt: z.number().int().min(1),
});
export type DownloadRequestCompletedPayload = z.infer<typeof downloadRequestCompletedPayloadSchema>;

export const downloadRequestFailedPayloadSchema = z.object({
  requestId: z.uuid(),
  source: downloadSourceSchema,
  sourceUrl: z.string(),
  trigger: downloadTriggerSchema,
  status: downloadRequestStatusSchema,
  errorCode: downloadErrorCodeSchema,
  error: z.string(),
  pocArtifactId: z.uuid().nullable(),
  attempt: z.number().int().min(1),
  /** True when another attempt is scheduled. */
  willRetry: z.boolean(),
});
export type DownloadRequestFailedPayload = z.infer<typeof downloadRequestFailedPayloadSchema>;

/**
 * New content was stored in the quarantine bucket. It has not been scanned or reviewed: the
 * content is untrusted and must not be released or treated as verified.
 */
export const downloadArtifactStoredPayloadSchema = z.object({
  artifactId: z.uuid(),
  requestId: z.uuid(),
  sha256,
  sizeBytes: z.number().int().min(0),
  detectedType: detectedFileTypeSchema,
  riskIndicators: z.array(downloadRiskIndicatorSchema),
  source: downloadSourceSchema,
  sourceUrl: z.string(),
  pocArtifactId: z.uuid().nullable(),
  cveIds: z.array(cveIdSchema),
  lifecycleStatus: z.literal('quarantined'),
});
export type DownloadArtifactStoredPayload = z.infer<typeof downloadArtifactStoredPayloadSchema>;

export const downloadArtifactScannedPayloadSchema = z.object({
  artifactId: z.uuid(),
  scanRunId: z.uuid(),
  sha256,
  scanStatus: artifactScanStatusSchema,
  previousScanStatus: artifactScanStatusSchema,
  scanners: z.array(
    z.object({
      scanner: artifactScannerSchema,
      verdict: scanVerdictSchema,
      findings: z.array(z.string()),
    }),
  ),
  pocArtifactIds: z.array(z.uuid()),
  lifecycleStatus: artifactLifecycleStatusSchema,
});
export type DownloadArtifactScannedPayload = z.infer<typeof downloadArtifactScannedPayloadSchema>;

export const downloadArtifactLifecycleChangedPayloadSchema = z.object({
  artifactId: z.uuid(),
  sha256,
  fromStatus: artifactLifecycleStatusSchema,
  toStatus: artifactLifecycleStatusSchema,
  reason: z.string(),
  scanStatus: artifactScanStatusSchema,
  verificationStatus: artifactVerificationStatusSchema,
  pocArtifactIds: z.array(z.uuid()),
  version: z.number().int().min(1),
  actor: eventActorSchema,
});
export type DownloadArtifactLifecycleChangedPayload = z.infer<
  typeof downloadArtifactLifecycleChangedPayloadSchema
>;
