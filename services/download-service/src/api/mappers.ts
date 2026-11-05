import type {
  ArtifactProvenance,
  DetectedFileType,
  DownloadArtifact,
  DownloadAttempt,
  DownloadErrorCode,
  DownloadHop,
  DownloadRequest,
  DownloadRiskIndicator,
  DownloadSource,
  DownloadTrigger,
  LifecycleEvent,
  ScanFinding,
  ScanResult,
} from '@cve/contracts';

import { isReleasable } from '../domain/artifact-rules.js';
import type {
  ArtifactLifecycleEvent as DbLifecycleEvent,
  ArtifactSource as DbArtifactSource,
  DownloadAttempt as DbAttempt,
  DownloadRequest as DbRequest,
  ScanResult as DbScanResult,
  StoredArtifact as DbArtifact,
} from '../generated/prisma/client.js';
import { SCAN_STATUS_TO_API, VERDICT_TO_API, VERIFICATION_TO_API } from '../persistence/enums.js';

const iso = (date: Date) => date.toISOString();
const isoOrNull = (date: Date | null) => (date === null ? null : date.toISOString());

export function toRequest(row: DbRequest): DownloadRequest {
  return {
    id: row.id,
    source: row.source as DownloadSource,
    sourceUrl: row.sourceUrl,
    trigger: row.trigger as DownloadTrigger,
    status: row.status,
    pocArtifactId: row.pocArtifactId,
    pocRepositoryId: row.pocRepositoryId,
    sourceRepository: row.sourceRepository,
    commitSha: row.commitSha,
    cveIds: row.cveIds,
    priority: row.priority,
    scheduledFor: iso(row.scheduledFor),
    attempts: row.attempts,
    maxAttempts: row.maxAttempts,
    errorCode: row.errorCode as DownloadErrorCode | null,
    error: row.error,
    artifactId: row.artifactId,
    requestedBy: row.requestedBy,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
    finishedAt: isoOrNull(row.finishedAt),
    version: row.version,
  };
}

export function toAttempt(row: DbAttempt): DownloadAttempt {
  return {
    id: row.id,
    attempt: row.attempt,
    jobId: row.jobId,
    outcome: row.outcome,
    errorCode: row.errorCode as DownloadErrorCode | null,
    error: row.error,
    retryable: row.retryable,
    httpStatus: row.httpStatus,
    hops: Array.isArray(row.hops) ? (row.hops as unknown as DownloadHop[]) : [],
    finalUrl: row.finalUrl,
    declaredContentType: row.declaredContentType,
    declaredLength: row.declaredLength === null ? null : Number(row.declaredLength),
    bytesReceived: Number(row.bytesReceived),
    sha256: row.sha256,
    startedAt: iso(row.startedAt),
    finishedAt: isoOrNull(row.finishedAt),
    durationMs: row.durationMs,
  };
}

export function toArtifact(row: DbArtifact, pocArtifactIds: readonly string[]): DownloadArtifact {
  const scanStatus = SCAN_STATUS_TO_API[row.scanStatus];
  const verificationStatus = VERIFICATION_TO_API[row.verificationStatus];
  return {
    id: row.id,
    sha256: row.sha256,
    sizeBytes: Number(row.sizeBytes),
    mimeType: row.mimeType,
    detectedType: row.detectedType as DetectedFileType,
    declaredContentType: row.declaredContentType,
    originalFilename: row.originalFilename,
    storageBucket: row.storageBucket,
    storageKey: row.storageKey,
    source: row.source as DownloadSource,
    sourceUrl: row.sourceUrl,
    sourceRepository: row.sourceRepository,
    cveIds: row.cveIds,
    riskIndicators: row.riskIndicators as DownloadRiskIndicator[],
    lifecycleStatus: row.lifecycleStatus,
    scanStatus,
    verificationStatus,
    pocArtifactIds: [...pocArtifactIds],
    releasable: isReleasable({
      lifecycleStatus: row.lifecycleStatus,
      scanStatus,
      verificationStatus,
    }),
    discoveredAt: iso(row.discoveredAt),
    downloadedAt: iso(row.downloadedAt),
    lastScannedAt: isoOrNull(row.lastScannedAt),
    releasedAt: isoOrNull(row.releasedAt),
    version: row.version,
  };
}

export function toProvenance(row: DbArtifactSource): ArtifactProvenance {
  return {
    requestId: row.requestId,
    source: row.source as DownloadSource,
    sourceUrl: row.sourceUrl,
    finalUrl: row.finalUrl,
    sourceRepository: row.sourceRepository,
    pocArtifactId: row.pocArtifactId,
    commitSha: row.commitSha,
    cveIds: row.cveIds,
    discoveredAt: iso(row.discoveredAt),
    downloadedAt: iso(row.downloadedAt),
  };
}

export function toScanResult(row: DbScanResult): ScanResult {
  return {
    id: row.id,
    scanner: row.scanner as ScanResult['scanner'],
    verdict: VERDICT_TO_API[row.verdict],
    findings: Array.isArray(row.findings) ? (row.findings as unknown as ScanFinding[]) : [],
    engineVersion: row.engineVersion,
    signatureVersion: row.signatureVersion,
    error: row.error,
    scanRunId: row.scanRunId,
    startedAt: iso(row.startedAt),
    finishedAt: iso(row.finishedAt),
  };
}

export function toLifecycleEvent(row: DbLifecycleEvent): LifecycleEvent {
  return {
    id: row.id,
    fromStatus: row.fromStatus,
    toStatus: row.toStatus,
    reason: row.reason,
    actorId: row.actorId,
    actorUsername: row.actorUsername,
    createdAt: iso(row.createdAt),
  };
}
