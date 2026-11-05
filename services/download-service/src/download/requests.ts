import type { DownloadTrigger } from '@cve/contracts';

import type { DownloadTarget } from '../domain/sources.js';
import { sha256Hex } from '../domain/naming.js';
import type { DownloadRequest } from '../generated/prisma/client.js';
import type { Tx } from '../persistence/database.js';

export interface PlanRequestInput {
  readonly target: DownloadTarget;
  readonly trigger: DownloadTrigger;
  readonly cveIds: readonly string[];
  readonly pocArtifactId: string | null;
  readonly pocRepositoryId: string | null;
  readonly priority: number;
  readonly scheduledFor: Date;
  readonly maxAttempts: number;
  readonly requestedBy: string | null;
  readonly reason: string | null;
  readonly correlationId: string | undefined;
  readonly discoveredAt: Date;
  /** Refuse without downloading (e.g. a PoC artifact far larger than the size limit). */
  readonly rejection?: { readonly errorCode: string; readonly error: string };
}

export interface PlannedRequest {
  readonly request: DownloadRequest;
  readonly created: boolean;
}

const uniqueSorted = (values: readonly string[]) => [...new Set(values)].sort();

/**
 * Creates the request for a canonical URL, or returns the existing one (one request per source
 * and URL: the same content is never downloaded twice). An existing request gains the new CVE
 * IDs and the PoC artifact link when it had none.
 */
export async function planRequest(tx: Tx, input: PlanRequestInput): Promise<PlannedRequest> {
  const urlHash = sha256Hex(input.target.url);
  const existing = await tx.downloadRequest.findUnique({
    where: { source_urlHash: { source: input.target.source, urlHash } },
  });
  if (existing !== null) {
    const cveIds = uniqueSorted([...existing.cveIds, ...input.cveIds]);
    const linkArtifact = existing.pocArtifactId === null && input.pocArtifactId !== null;
    if (cveIds.length === existing.cveIds.length && !linkArtifact) {
      return { request: existing, created: false };
    }
    const request = await tx.downloadRequest.update({
      where: { id: existing.id },
      data: {
        cveIds,
        ...(linkArtifact
          ? { pocArtifactId: input.pocArtifactId, pocRepositoryId: input.pocRepositoryId }
          : {}),
        version: { increment: 1 },
      },
    });
    return { request, created: false };
  }
  const now = new Date();
  const request = await tx.downloadRequest.create({
    data: {
      source: input.target.source,
      sourceUrl: input.target.url,
      urlHash,
      trigger: input.trigger,
      status: input.rejection === undefined ? 'pending' : 'rejected',
      pocArtifactId: input.pocArtifactId,
      pocRepositoryId: input.pocRepositoryId,
      sourceRepository: input.target.sourceRepository,
      commitSha: input.target.commitSha,
      cveIds: uniqueSorted(input.cveIds),
      priority: input.priority,
      scheduledFor: input.scheduledFor,
      maxAttempts: input.maxAttempts,
      requestedBy: input.requestedBy,
      reason: input.reason,
      correlationId: input.correlationId ?? null,
      discoveredAt: input.discoveredAt,
      ...(input.rejection === undefined
        ? {}
        : {
            errorCode: input.rejection.errorCode,
            error: input.rejection.error,
            finishedAt: now,
          }),
    },
  });
  return { request, created: true };
}
