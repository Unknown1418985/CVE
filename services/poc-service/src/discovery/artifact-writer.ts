import {
  artifactDiscoveredPayloadSchema,
  POC_EVENT_TYPES,
  type DomainEventEnvelope,
  type DuplicateKind,
  type RiskIndicator,
} from '@cve/contracts';

import { blobSimilarity, isBoilerplate, type SnapshotSummary } from '../domain/files.js';
import { pocEvent } from '../events/poc-events.js';
import { Prisma, type Tx } from '../persistence/database.js';

export interface DuplicateMatch {
  readonly kind: DuplicateKind;
  readonly ofArtifactId: string;
  readonly ofVerificationStatus: string;
  readonly similarity: number;
}

const MAX_NEAR_CANDIDATES = 10;

/**
 * Finds the earliest artifact of another repository with the same content. Exact duplicates
 * share the Git tree; near duplicates share most significant blobs (licences and empty files
 * excluded). Earlier snapshots of the same repository are versions, not duplicates.
 */
export async function findDuplicate(
  tx: Tx,
  input: {
    readonly repositoryId: string;
    readonly treeSha: string;
    readonly significantBlobs: ReadonlySet<string>;
    readonly threshold: number;
  },
): Promise<DuplicateMatch | null> {
  const exact = await tx.pocArtifact.findFirst({
    where: { treeSha: input.treeSha, repositoryId: { not: input.repositoryId } },
    orderBy: [{ discoveredAt: 'asc' }, { id: 'asc' }],
    select: { id: true, verificationStatus: true },
  });
  if (exact !== null) {
    return {
      kind: 'exact',
      ofArtifactId: exact.id,
      ofVerificationStatus: exact.verificationStatus,
      similarity: 1,
    };
  }
  if (input.significantBlobs.size < 2) return null;
  const blobs = [...input.significantBlobs];
  const candidates = await tx.$queryRaw<{ artifactId: string; shared: bigint }[]>`
    SELECT f."artifact_id" AS "artifactId", count(DISTINCT f."blob_sha") AS "shared"
      FROM "artifact_files" AS f
      JOIN "poc_artifacts" AS a ON a."id" = f."artifact_id"
     WHERE f."significant" AND f."blob_sha" = ANY(${blobs}::char(40)[])
       AND a."repository_id" <> ${input.repositoryId}::uuid
     GROUP BY f."artifact_id"
     ORDER BY "shared" DESC
     LIMIT ${MAX_NEAR_CANDIDATES}`;
  if (candidates.length === 0) return null;
  const sets = await tx.artifactFile.findMany({
    where: { artifactId: { in: candidates.map((c) => c.artifactId) }, significant: true },
    select: {
      artifactId: true,
      blobSha: true,
      artifact: { select: { discoveredAt: true, verificationStatus: true } },
    },
  });
  const byArtifact = new Map<string, { blobs: Set<string>; discoveredAt: Date; status: string }>();
  for (const file of sets) {
    const entry = byArtifact.get(file.artifactId) ?? {
      blobs: new Set<string>(),
      discoveredAt: file.artifact.discoveredAt,
      status: file.artifact.verificationStatus,
    };
    entry.blobs.add(file.blobSha);
    byArtifact.set(file.artifactId, entry);
  }
  let best: (DuplicateMatch & { discoveredAt: Date }) | null = null;
  for (const [artifactId, entry] of byArtifact) {
    const similarity =
      Math.round(blobSimilarity(input.significantBlobs, entry.blobs) * 1_000) / 1_000;
    if (similarity < input.threshold) continue;
    if (
      best === null ||
      similarity > best.similarity ||
      (similarity === best.similarity && entry.discoveredAt < best.discoveredAt)
    ) {
      best = {
        kind: 'near',
        ofArtifactId: artifactId,
        ofVerificationStatus: entry.status,
        similarity,
        discoveredAt: entry.discoveredAt,
      };
    }
  }
  if (best === null) return null;
  return {
    kind: best.kind,
    ofArtifactId: best.ofArtifactId,
    ofVerificationStatus: best.ofVerificationStatus,
    similarity: best.similarity,
  };
}

export interface RecordSnapshotInput {
  readonly repositoryId: string;
  readonly repositoryUrl: string;
  readonly repositoryFullName: string;
  readonly commitSha: string;
  readonly treeSha: string;
  readonly committedAt: Date | null;
  /** Null when the tree was not fetched because the repository already has an artifact for it. */
  readonly summary: SnapshotSummary | null;
  readonly nearDuplicateThreshold: number;
  readonly correlationId: string | undefined;
  readonly now: Date;
}

export interface RecordSnapshotResult {
  readonly artifactId: string | null;
  readonly created: boolean;
  readonly duplicate: DuplicateMatch | null;
  readonly events: readonly DomainEventEnvelope[];
}

/**
 * Records an observed head commit. A tree the repository already has reuses its artifact (only
 * the commit is tracked); new content becomes a new `unverified` artifact with its file listing,
 * fingerprint, risk indicators and duplicate link.
 */
export async function recordSnapshot(
  tx: Tx,
  input: RecordSnapshotInput,
): Promise<RecordSnapshotResult> {
  const existing = await tx.pocArtifact.findUnique({
    where: { repositoryId_treeSha: { repositoryId: input.repositoryId, treeSha: input.treeSha } },
    select: { id: true },
  });
  let artifactId = existing?.id ?? null;
  let duplicate: DuplicateMatch | null = null;
  const events: DomainEventEnvelope[] = [];
  if (existing === null && input.summary !== null) {
    const summary = input.summary;
    const significant = new Set(
      summary.files
        .filter((file) => !isBoilerplate({ path: file.path, sha: file.blobSha }))
        .map((file) => file.blobSha),
    );
    duplicate = await findDuplicate(tx, {
      repositoryId: input.repositoryId,
      treeSha: input.treeSha,
      significantBlobs: significant,
      threshold: input.nearDuplicateThreshold,
    });
    const risk: RiskIndicator[] = [...summary.riskIndicators];
    if (duplicate?.ofVerificationStatus === 'malicious') risk.push('duplicate-of-malicious');
    const artifact = await tx.pocArtifact.create({
      data: {
        repositoryId: input.repositoryId,
        commitSha: input.commitSha,
        treeSha: input.treeSha,
        fingerprint: summary.fingerprint,
        fileCount: summary.fileCount,
        totalBytes: BigInt(summary.totalBytes),
        listingTruncated: risk.includes('listing-truncated'),
        hasSourceCode: summary.hasSourceCode,
        riskIndicators: risk,
        duplicateKind: duplicate?.kind ?? null,
        duplicateOfId: duplicate?.ofArtifactId ?? null,
        similarity: duplicate === null ? null : new Prisma.Decimal(duplicate.similarity),
        discoveredAt: input.now,
      },
      select: { id: true },
    });
    artifactId = artifact.id;
    if (summary.files.length > 0) {
      await tx.artifactFile.createMany({
        data: summary.files.map((file) => ({
          artifactId: artifact.id,
          path: file.path,
          blobSha: file.blobSha,
          sizeBytes: file.sizeBytes,
          category: file.category,
          significant:
            significant.has(file.blobSha) && !isBoilerplate({ path: file.path, sha: file.blobSha }),
        })),
      });
    }
    const cveIds = await tx.pocAssociation.findMany({
      where: { repositoryId: input.repositoryId, reviewStatus: { not: 'rejected' } },
      select: { cveId: true },
      orderBy: { cveId: 'asc' },
    });
    events.push(
      pocEvent(
        POC_EVENT_TYPES.artifactDiscovered,
        artifactDiscoveredPayloadSchema,
        {
          artifactId: artifact.id,
          repositoryId: input.repositoryId,
          repositoryUrl: input.repositoryUrl,
          repositoryFullName: input.repositoryFullName,
          commitSha: input.commitSha,
          treeSha: input.treeSha,
          fingerprint: summary.fingerprint,
          fileCount: summary.fileCount,
          totalBytes: summary.totalBytes,
          riskIndicators: risk,
          duplicate:
            duplicate === null
              ? null
              : {
                  kind: duplicate.kind,
                  ofArtifactId: duplicate.ofArtifactId,
                  similarity: duplicate.similarity,
                },
          cveIds: cveIds.map((row) => row.cveId),
          verificationStatus: 'unverified',
        },
        input.correlationId,
      ),
    );
  }
  await tx.repositoryCommit.upsert({
    where: { repositoryId_sha: { repositoryId: input.repositoryId, sha: input.commitSha } },
    create: {
      repositoryId: input.repositoryId,
      sha: input.commitSha,
      treeSha: input.treeSha,
      committedAt: input.committedAt,
      observedAt: input.now,
      artifactId,
    },
    update: { artifactId },
  });
  return { artifactId, created: existing === null && artifactId !== null, duplicate, events };
}
