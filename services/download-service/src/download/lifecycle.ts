import {
  DOWNLOAD_EVENT_TYPES,
  downloadArtifactLifecycleChangedPayloadSchema,
  type ArtifactLifecycleStatus,
  type DomainEventEnvelope,
} from '@cve/contracts';
import { OBJECT_STORAGE_BUCKETS } from '@cve/contracts';
import type { Logger } from '@cve/logger';

import type { ActorContext } from '../common/request-context.js';
import { combineVerification, mustRevokeRelease } from '../domain/artifact-rules.js';
import { downloadEvent } from '../events/download-events.js';
import type { Prisma, PrismaClient, StoredArtifact } from '../generated/prisma/client.js';
import { writeOutbox, type Tx } from '../persistence/database.js';
import {
  SCAN_STATUS_TO_API,
  VERIFICATION_TO_API,
  VERIFICATION_TO_DB,
} from '../persistence/enums.js';
import type { ArtifactObjectStore } from '../storage/object-store.js';

/** Locks an artifact row for a state change (`SELECT … FOR UPDATE`). */
export async function lockArtifact(tx: Tx, id: string): Promise<StoredArtifact | null> {
  const locked = await tx.$queryRaw<{ id: string }[]>`
    SELECT "id" FROM "stored_artifacts" WHERE "id" = ${id}::uuid FOR UPDATE`;
  if (locked.length === 0) return null;
  return tx.storedArtifact.findUnique({ where: { id } });
}

export interface LifecycleChange {
  /** Released copy to delete once the transaction committed (null when there is none). */
  readonly releasedKeyToDelete: { readonly artifactId: string; readonly key: string } | null;
  readonly artifact: StoredArtifact;
}

/**
 * Records a lifecycle change of a locked artifact: the row, the append-only history and the
 * outbox event. Leaving `released` schedules the released copy for deletion after commit.
 */
export async function changeLifecycle(
  tx: Tx,
  artifact: StoredArtifact,
  to: ArtifactLifecycleStatus,
  reason: string,
  context: ActorContext,
  release?: { readonly releasedKey: string },
  /** Other column changes applied in the same update (so CHECK constraints hold throughout). */
  changes: Prisma.StoredArtifactUpdateInput = {},
): Promise<LifecycleChange> {
  const now = new Date();
  const leavingRelease = artifact.lifecycleStatus === 'released' && to !== 'released';
  const updated = await tx.storedArtifact.update({
    where: { id: artifact.id },
    data: {
      ...changes,
      lifecycleStatus: to,
      ...(to === 'released' && release !== undefined
        ? {
            releasedKey: release.releasedKey,
            releasedAt: now,
            releasedBy: context.actor.username ?? context.actor.id,
          }
        : {}),
      // The key stays until the copy is deleted, so maintenance can finish a failed deletion.
      ...(leavingRelease ? { releasedAt: null, releasedBy: null } : {}),
      version: { increment: 1 },
    },
  });
  await tx.artifactLifecycleEvent.create({
    data: {
      artifactId: artifact.id,
      fromStatus: artifact.lifecycleStatus,
      toStatus: to,
      reason: reason.slice(0, 2_000),
      actorId: context.actor.id,
      actorUsername: context.actor.username,
      correlationId: context.correlationId ?? null,
    },
  });
  const pocArtifactIds = await linkedPocArtifacts(tx, artifact.id);
  const event: DomainEventEnvelope = downloadEvent(
    DOWNLOAD_EVENT_TYPES.artifactLifecycleChanged,
    downloadArtifactLifecycleChangedPayloadSchema,
    {
      artifactId: artifact.id,
      sha256: artifact.sha256,
      fromStatus: artifact.lifecycleStatus,
      toStatus: to,
      reason: reason.slice(0, 2_000),
      scanStatus: SCAN_STATUS_TO_API[updated.scanStatus],
      verificationStatus: VERIFICATION_TO_API[updated.verificationStatus],
      pocArtifactIds,
      version: updated.version,
      actor: context.actor,
    },
    context.correlationId,
  );
  await writeOutbox(tx, [event]);
  return {
    artifact: updated,
    releasedKeyToDelete:
      leavingRelease && artifact.releasedKey !== null
        ? { artifactId: artifact.id, key: artifact.releasedKey }
        : null,
  };
}

export async function linkedPocArtifacts(tx: Tx, artifactId: string): Promise<string[]> {
  const rows = await tx.artifactSource.findMany({
    where: { artifactId, pocArtifactId: { not: null } },
    select: { pocArtifactId: true },
    distinct: ['pocArtifactId'],
    orderBy: { pocArtifactId: 'asc' },
  });
  return rows.flatMap((row) => (row.pocArtifactId === null ? [] : [row.pocArtifactId]));
}

/**
 * Recomputes the combined verification of an artifact from the PoC artifact projection and
 * returns the (possibly) updated row. Revokes a release that is no longer acceptable.
 */
export async function refreshVerification(
  tx: Tx,
  artifact: StoredArtifact,
  context: ActorContext,
): Promise<LifecycleChange> {
  const pocArtifactIds = await linkedPocArtifacts(tx, artifact.id);
  const states = await tx.pocArtifactState.findMany({
    where: { pocArtifactId: { in: pocArtifactIds } },
    select: { verificationStatus: true },
  });
  const combined = combineVerification(
    states.map((state) => VERIFICATION_TO_API[state.verificationStatus]),
  );
  if (VERIFICATION_TO_DB[combined] === artifact.verificationStatus) {
    return { artifact, releasedKeyToDelete: null };
  }
  return applyStatusChange(
    tx,
    artifact,
    { verificationStatus: VERIFICATION_TO_DB[combined] },
    {},
    `a linked PoC artifact is now ${combined}`,
    context,
  );
}

/**
 * Applies a scan or verification status change to a locked artifact. When the new state no
 * longer qualifies a released artifact for release, the release is revoked in the same update:
 * the database never holds a released artifact with a blocking status.
 */
export async function applyStatusChange(
  tx: Tx,
  artifact: StoredArtifact,
  status: {
    readonly scanStatus?: StoredArtifact['scanStatus'];
    readonly verificationStatus?: StoredArtifact['verificationStatus'];
  },
  extra: Prisma.StoredArtifactUpdateInput,
  reason: string,
  context: ActorContext,
): Promise<LifecycleChange> {
  const next = {
    lifecycleStatus: artifact.lifecycleStatus,
    scanStatus: SCAN_STATUS_TO_API[status.scanStatus ?? artifact.scanStatus],
    verificationStatus: VERIFICATION_TO_API[status.verificationStatus ?? artifact.verificationStatus],
  };
  const changes: Prisma.StoredArtifactUpdateInput = { ...extra, ...status };
  if (mustRevokeRelease(next)) {
    return changeLifecycle(
      tx,
      artifact,
      'quarantined',
      `Release revoked: ${reason}`,
      context,
      undefined,
      changes,
    );
  }
  const updated = await tx.storedArtifact.update({
    where: { id: artifact.id },
    data: { ...changes, version: { increment: 1 } },
  });
  return { artifact: updated, releasedKeyToDelete: null };
}

/**
 * Deletes released copies after the change committed. The database decides what is served, so a
 * failure here only leaves an unreachable copy; its key stays recorded and maintenance retries.
 */
export async function deleteReleasedCopies(
  store: ArtifactObjectStore,
  prisma: PrismaClient,
  copies: readonly LifecycleChange['releasedKeyToDelete'][],
  logger: Logger,
): Promise<void> {
  for (const copy of copies) {
    if (copy === null) continue;
    try {
      await store.delete(OBJECT_STORAGE_BUCKETS.pocArtifacts, copy.key);
      await prisma.storedArtifact.updateMany({
        where: { id: copy.artifactId, releasedKey: copy.key, lifecycleStatus: { not: 'released' } },
        data: { releasedKey: null },
      });
    } catch (error) {
      logger.warn(
        { err: error, key: copy.key },
        'failed to delete a released copy; maintenance will retry',
      );
    }
  }
}
