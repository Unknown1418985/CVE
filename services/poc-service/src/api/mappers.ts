import type {
  ArtifactFile,
  ArtifactVerificationStatus,
  AssociationPenalty,
  AssociationSignal,
  DiscoveryRun,
  DiscoveryRunStats,
  PocArtifact,
  PocAssociation,
  PocOwner,
  PocReference,
  PocReferenceKind,
  PocRepository,
  RiskIndicator,
} from '@cve/contracts';
import { EMPTY_DISCOVERY_RUN_STATS } from '@cve/contracts';

import type { Prisma } from '../generated/prisma/client.js';
import { decimalToNumber } from '../persistence/database.js';

const iso = (date: Date) => date.toISOString();
const isoOrNull = (date: Date | null) => (date === null ? null : date.toISOString());

export const VERIFICATION_TO_API: Readonly<Record<string, ArtifactVerificationStatus>> = {
  unverified: 'unverified',
  in_review: 'in-review',
  verified: 'verified',
  rejected: 'rejected',
  malicious: 'malicious',
};

export const VERIFICATION_TO_DB = {
  unverified: 'unverified',
  'in-review': 'in_review',
  verified: 'verified',
  rejected: 'rejected',
  malicious: 'malicious',
} as const satisfies Record<ArtifactVerificationStatus, string>;

export const REFERENCE_KIND_TO_API: Readonly<Record<string, PocReferenceKind>> = {
  github_repository: 'github-repository',
  github_gist: 'github-gist',
  exploit_db: 'exploit-db',
  packet_storm: 'packet-storm',
  other: 'other',
};

export const REFERENCE_KIND_TO_DB = {
  'github-repository': 'github_repository',
  'github-gist': 'github_gist',
  'exploit-db': 'exploit_db',
  'packet-storm': 'packet_storm',
  other: 'other',
} as const satisfies Record<PocReferenceKind, string>;

export const REPOSITORY_INCLUDE = {
  owner: true,
  commits: { orderBy: { observedAt: 'desc' }, take: 1 },
  associations: {
    where: { reviewStatus: { not: 'rejected' } },
    select: { cveId: true },
    orderBy: { confidence: 'desc' },
    take: 50,
  },
} as const satisfies Prisma.PocRepositoryInclude;

type RepositoryWithRelations = Prisma.PocRepositoryGetPayload<{
  include: typeof REPOSITORY_INCLUDE;
}>;

export function toOwner(
  row: Prisma.RepositoryOwnerGetPayload<object>,
  repositoryCount: number,
): PocOwner {
  return {
    id: row.id,
    source: 'github',
    externalId: row.externalId,
    login: row.login,
    type: row.type,
    url: row.url,
    repositoryCount,
    firstSeenAt: iso(row.firstSeenAt),
    lastSeenAt: iso(row.lastSeenAt),
  };
}

export function toRepository(row: RepositoryWithRelations): PocRepository {
  const latest = row.commits.find((commit) => commit.sha === row.latestCommitSha) ?? null;
  return {
    id: row.id,
    source: 'github',
    externalId: row.externalId,
    fullName: row.fullName,
    name: row.name,
    url: row.url,
    owner: { id: row.owner.id, login: row.owner.login, type: row.owner.type, url: row.owner.url },
    description: row.description,
    topics: row.topics,
    language: row.language,
    stars: row.stars,
    forks: row.forks,
    isFork: row.isFork,
    parentFullName: row.parentFullName,
    isArchived: row.isArchived,
    defaultBranch: row.defaultBranch,
    sizeKb: row.sizeKb,
    status: row.status,
    sourceCreatedAt: isoOrNull(row.sourceCreatedAt),
    sourcePushedAt: isoOrNull(row.sourcePushedAt),
    latestCommit:
      latest === null
        ? null
        : {
            sha: latest.sha,
            treeSha: latest.treeSha,
            committedAt: isoOrNull(latest.committedAt),
            observedAt: iso(latest.observedAt),
          },
    maxConfidence: decimalToNumber(row.maxConfidence),
    cveIds: row.associations.map((association) => association.cveId),
    discoveredBy: row.discoveredBy === 'cve-references' ? 'cve-references' : 'github',
    firstDiscoveredAt: iso(row.firstDiscoveredAt),
    lastSeenAt: iso(row.lastSeenAt),
    lastInspectedAt: isoOrNull(row.lastInspectedAt),
    version: row.version,
  };
}

export const ASSOCIATION_INCLUDE = {
  repository: { select: { fullName: true, url: true } },
} as const satisfies Prisma.PocAssociationInclude;

type AssociationWithRepository = Prisma.PocAssociationGetPayload<{
  include: typeof ASSOCIATION_INCLUDE;
}>;

export function toAssociation(row: AssociationWithRepository): PocAssociation {
  return {
    id: row.id,
    repositoryId: row.repositoryId,
    repositoryFullName: row.repository.fullName,
    repositoryUrl: row.repository.url,
    cveId: row.cveId,
    confidence: decimalToNumber(row.confidence) ?? 0,
    confidenceLevel: row.confidenceLevel,
    signals: row.signals as AssociationSignal[],
    penalties: row.penalties as AssociationPenalty[],
    scoringVersion: row.scoringVersion,
    origin: row.origin,
    reviewStatus: row.reviewStatus,
    reviewedBy: row.reviewedBy,
    reviewedAt: isoOrNull(row.reviewedAt),
    reviewNote: row.reviewNote,
    firstDiscoveredAt: iso(row.firstDiscoveredAt),
    lastEvaluatedAt: iso(row.lastEvaluatedAt),
    version: row.version,
  };
}

export const ARTIFACT_INCLUDE = {
  repository: { select: { fullName: true, url: true } },
  duplicateOf: { select: { id: true, repository: { select: { fullName: true } } } },
} as const satisfies Prisma.PocArtifactInclude;

type ArtifactWithRelations = Prisma.PocArtifactGetPayload<{ include: typeof ARTIFACT_INCLUDE }>;

export function toArtifact(row: ArtifactWithRelations): PocArtifact {
  return {
    id: row.id,
    repositoryId: row.repositoryId,
    repositoryFullName: row.repository.fullName,
    repositoryUrl: row.repository.url,
    commitSha: row.commitSha,
    treeSha: row.treeSha,
    fingerprint: row.fingerprint,
    fileCount: row.fileCount,
    totalBytes: Number(row.totalBytes),
    listingTruncated: row.listingTruncated,
    riskIndicators: row.riskIndicators as RiskIndicator[],
    duplicate:
      row.duplicateKind === null || row.duplicateOf === null
        ? null
        : {
            kind: row.duplicateKind,
            ofArtifactId: row.duplicateOf.id,
            ofRepositoryFullName: row.duplicateOf.repository.fullName,
            similarity: decimalToNumber(row.similarity) ?? 1,
          },
    verificationStatus: VERIFICATION_TO_API[row.verificationStatus] ?? 'unverified',
    verificationUpdatedAt: isoOrNull(row.verificationUpdatedAt),
    verificationUpdatedBy: row.verificationUpdatedBy,
    discoveredAt: iso(row.discoveredAt),
    version: row.version,
  };
}

export function toArtifactFile(row: Prisma.ArtifactFileGetPayload<object>): ArtifactFile {
  return {
    path: row.path,
    blobSha: row.blobSha,
    sizeBytes: row.sizeBytes,
    category: row.category as ArtifactFile['category'],
  };
}

export function toReference(row: Prisma.PocReferenceGetPayload<object>): PocReference {
  return {
    id: row.id,
    cveId: row.cveId,
    url: row.url,
    kind: REFERENCE_KIND_TO_API[row.kind] ?? 'other',
    source: row.source,
    tags: row.tags,
    repositoryId: row.repositoryId,
    firstSeenAt: iso(row.firstSeenAt),
    lastSeenAt: iso(row.lastSeenAt),
  };
}

export function toRun(row: Prisma.DiscoveryRunGetPayload<object>): DiscoveryRun {
  return {
    id: row.id,
    connector: row.connector === 'cve-references' ? 'cve-references' : 'github',
    mode: row.mode as DiscoveryRun['mode'],
    trigger: row.trigger as DiscoveryRun['trigger'],
    status: row.status,
    cveId: row.cveId,
    repositoryId: row.repositoryId,
    jobId: row.jobId,
    attempt: row.attempt,
    requestedBy: row.requestedBy,
    startedAt: iso(row.startedAt),
    finishedAt: isoOrNull(row.finishedAt),
    stats: { ...EMPTY_DISCOVERY_RUN_STATS, ...(row.stats as Partial<DiscoveryRunStats>) },
    error: row.error,
  };
}
