import { Inject, Injectable, NotFoundException } from '@nestjs/common';

import {
  type DiscoveryRun,
  type ListDiscoveryRunsQuery,
  type ListPocArtifactsQuery,
  type ListPocAssociationsQuery,
  type ListPocOwnersQuery,
  type ListPocReferencesQuery,
  type ListPocRepositoriesQuery,
  type Permission,
  type PocArtifact,
  type PocArtifactDetail,
  type PocAssociation,
  type PocConnectorStatus,
  type PocOwner,
  type PocReference,
  type PocRepository,
  type RepositoryCommit,
  type VerificationEvent,
} from '@cve/contracts';

import { CONNECTOR_TERMS } from '../connectors/catalog.js';
import type { Prisma, PrismaClient } from '../generated/prisma/client.js';
import { escapeLike, PRISMA } from '../persistence/database.js';
import {
  ARTIFACT_INCLUDE,
  ASSOCIATION_INCLUDE,
  REFERENCE_KIND_TO_DB,
  REPOSITORY_INCLUDE,
  toArtifact,
  toArtifactFile,
  toAssociation,
  toOwner,
  toReference,
  toRepository,
  toRun,
  VERIFICATION_TO_API,
  VERIFICATION_TO_DB,
} from './mappers.js';
import { CONNECTOR_INFO, type ConnectorInfo } from './tokens.js';

interface Page<T> {
  readonly items: T[];
  readonly total: number;
}

const skip = (query: { page: number; pageSize: number }) => (query.page - 1) * query.pageSize;

/**
 * Artifacts judged malicious are visible only with `quarantine:read`: ordinary users never see
 * them, even as metadata (CLAUDE.md §2.16).
 */
export function canSeeMalicious(permissions: readonly Permission[]): boolean {
  return permissions.includes('quarantine:read');
}

@Injectable()
export class PocQueryService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(CONNECTOR_INFO) private readonly connectors: readonly ConnectorInfo[],
  ) {}

  // ---------------------------------------------------------------------------- repositories

  async listRepositories(query: ListPocRepositoriesQuery): Promise<Page<PocRepository>> {
    const where: Prisma.PocRepositoryWhereInput = {
      ...(query.q === undefined
        ? {}
        : { fullNameKey: { contains: escapeLike(query.q.toLowerCase()) } }),
      ...(query.cveId === undefined
        ? {}
        : { associations: { some: { cveId: query.cveId, reviewStatus: { not: 'rejected' } } } }),
      ...(query.owner === undefined ? {} : { owner: { loginKey: query.owner.toLowerCase() } }),
      ...(query.status === undefined ? {} : { status: query.status }),
      ...(query.minConfidence === undefined ? {} : { maxConfidence: { gte: query.minConfidence } }),
      ...(query.isFork === undefined ? {} : { isFork: query.isFork }),
    };
    const sortField = query.sort;
    const orderBy: Prisma.PocRepositoryOrderByWithRelationInput[] = [
      sortField === 'maxConfidence' || sortField === 'sourcePushedAt'
        ? { [sortField]: { sort: query.order, nulls: 'last' } }
        : { [sortField]: query.order },
      { id: 'asc' },
    ];
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.pocRepository.findMany({
        where,
        include: REPOSITORY_INCLUDE,
        orderBy,
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.pocRepository.count({ where }),
    ]);
    return { items: rows.map(toRepository), total };
  }

  async getRepository(id: string): Promise<PocRepository> {
    const row = await this.prisma.pocRepository.findUnique({
      where: { id },
      include: REPOSITORY_INCLUDE,
    });
    if (row === null) throw new NotFoundException('PoC repository not found');
    return toRepository(row);
  }

  async listCommits(
    repositoryId: string,
    query: { page: number; pageSize: number },
  ): Promise<Page<RepositoryCommit>> {
    await this.getRepository(repositoryId);
    const where = { repositoryId };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.repositoryCommit.findMany({
        where,
        orderBy: [{ observedAt: 'desc' }, { id: 'asc' }],
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.repositoryCommit.count({ where }),
    ]);
    return {
      items: rows.map((row) => ({
        sha: row.sha,
        treeSha: row.treeSha,
        committedAt: row.committedAt?.toISOString() ?? null,
        observedAt: row.observedAt.toISOString(),
      })),
      total,
    };
  }

  // ---------------------------------------------------------------------------- owners

  async listOwners(query: ListPocOwnersQuery): Promise<Page<PocOwner>> {
    const where: Prisma.RepositoryOwnerWhereInput =
      query.q === undefined ? {} : { loginKey: { contains: escapeLike(query.q.toLowerCase()) } };
    const orderBy: Prisma.RepositoryOwnerOrderByWithRelationInput[] = [
      query.sort === 'repositoryCount'
        ? { repositories: { _count: query.order } }
        : query.sort === 'login'
          ? { loginKey: query.order }
          : { firstSeenAt: query.order },
      { id: 'asc' },
    ];
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.repositoryOwner.findMany({
        where,
        include: { _count: { select: { repositories: true } } },
        orderBy,
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.repositoryOwner.count({ where }),
    ]);
    return { items: rows.map((row) => toOwner(row, row._count.repositories)), total };
  }

  async getOwner(id: string): Promise<PocOwner> {
    const row = await this.prisma.repositoryOwner.findUnique({
      where: { id },
      include: { _count: { select: { repositories: true } } },
    });
    if (row === null) throw new NotFoundException('Repository owner not found');
    return toOwner(row, row._count.repositories);
  }

  // ---------------------------------------------------------------------------- associations

  async listAssociations(query: ListPocAssociationsQuery): Promise<Page<PocAssociation>> {
    const where: Prisma.PocAssociationWhereInput = {
      ...(query.cveId === undefined ? {} : { cveId: query.cveId }),
      ...(query.repositoryId === undefined ? {} : { repositoryId: query.repositoryId }),
      ...(query.reviewStatus === undefined ? {} : { reviewStatus: { in: query.reviewStatus } }),
      ...(query.confidenceLevel === undefined
        ? {}
        : { confidenceLevel: { in: query.confidenceLevel } }),
      ...(query.minConfidence === undefined ? {} : { confidence: { gte: query.minConfidence } }),
    };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.pocAssociation.findMany({
        where,
        include: ASSOCIATION_INCLUDE,
        orderBy: [{ [query.sort]: query.order }, { id: 'asc' }],
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.pocAssociation.count({ where }),
    ]);
    return { items: rows.map(toAssociation), total };
  }

  async getAssociation(id: string): Promise<PocAssociation> {
    const row = await this.prisma.pocAssociation.findUnique({
      where: { id },
      include: ASSOCIATION_INCLUDE,
    });
    if (row === null) throw new NotFoundException('PoC association not found');
    return toAssociation(row);
  }

  // ---------------------------------------------------------------------------- artifacts

  private visibility(permissions: readonly Permission[]): Prisma.PocArtifactWhereInput {
    return canSeeMalicious(permissions) ? {} : { verificationStatus: { not: 'malicious' } };
  }

  async listArtifacts(
    query: ListPocArtifactsQuery,
    permissions: readonly Permission[],
  ): Promise<Page<PocArtifact>> {
    const where: Prisma.PocArtifactWhereInput = {
      AND: [
        this.visibility(permissions),
        query.repositoryId === undefined ? {} : { repositoryId: query.repositoryId },
        query.cveId === undefined
          ? {}
          : {
              repository: {
                associations: { some: { cveId: query.cveId, reviewStatus: { not: 'rejected' } } },
              },
            },
        query.verificationStatus === undefined
          ? {}
          : {
              verificationStatus: {
                in: query.verificationStatus.map((status) => VERIFICATION_TO_DB[status]),
              },
            },
        query.duplicate === undefined
          ? {}
          : query.duplicate
            ? { duplicateOfId: { not: null } }
            : { duplicateOfId: null },
        query.fingerprint === undefined ? {} : { fingerprint: query.fingerprint },
      ],
    };
    const orderBy: Prisma.PocArtifactOrderByWithRelationInput[] = [
      query.sort === 'verificationUpdatedAt'
        ? { verificationUpdatedAt: { sort: query.order, nulls: 'last' } }
        : { discoveredAt: query.order },
      { id: 'asc' },
    ];
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.pocArtifact.findMany({
        where,
        include: ARTIFACT_INCLUDE,
        orderBy,
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.pocArtifact.count({ where }),
    ]);
    return { items: rows.map(toArtifact), total };
  }

  async getArtifact(id: string, permissions: readonly Permission[]): Promise<PocArtifactDetail> {
    const row = await this.prisma.pocArtifact.findFirst({
      where: { id, ...this.visibility(permissions) },
      include: { ...ARTIFACT_INCLUDE, files: { orderBy: { path: 'asc' } } },
    });
    if (row === null) throw new NotFoundException('PoC artifact not found');
    return { ...toArtifact(row), files: row.files.map(toArtifactFile) };
  }

  async verificationHistory(
    id: string,
    permissions: readonly Permission[],
  ): Promise<VerificationEvent[]> {
    await this.getArtifact(id, permissions);
    const rows = await this.prisma.artifactVerificationEvent.findMany({
      where: { artifactId: id },
      orderBy: [{ createdAt: 'desc' }, { id: 'asc' }],
      take: 200,
    });
    return rows.map((row) => ({
      id: row.id,
      artifactId: row.artifactId,
      fromStatus: VERIFICATION_TO_API[row.fromStatus] ?? 'unverified',
      toStatus: VERIFICATION_TO_API[row.toStatus] ?? 'unverified',
      reason: row.reason,
      actorId: row.actorId,
      actorUsername: row.actorUsername,
      createdAt: row.createdAt.toISOString(),
    }));
  }

  // ---------------------------------------------------------------------------- references

  async listReferences(query: ListPocReferencesQuery): Promise<Page<PocReference>> {
    const where: Prisma.PocReferenceWhereInput = {
      removedAt: null,
      ...(query.cveId === undefined ? {} : { cveId: query.cveId }),
      ...(query.kind === undefined
        ? {}
        : { kind: { in: query.kind.map((kind) => REFERENCE_KIND_TO_DB[kind]) } }),
    };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.pocReference.findMany({
        where,
        orderBy: [{ firstSeenAt: query.order }, { id: 'asc' }],
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.pocReference.count({ where }),
    ]);
    return { items: rows.map(toReference), total };
  }

  // ---------------------------------------------------------------------------- runs and connectors

  async listRuns(query: ListDiscoveryRunsQuery): Promise<Page<DiscoveryRun>> {
    const where: Prisma.DiscoveryRunWhereInput = {
      ...(query.connector === undefined ? {} : { connector: query.connector }),
      ...(query.mode === undefined ? {} : { mode: query.mode }),
      ...(query.status === undefined ? {} : { status: query.status }),
      ...(query.cveId === undefined ? {} : { cveId: query.cveId }),
      ...(query.startedFrom === undefined ? {} : { startedAt: { gte: query.startedFrom } }),
    };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.discoveryRun.findMany({
        where,
        orderBy: [{ startedAt: 'desc' }, { id: 'asc' }],
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.discoveryRun.count({ where }),
    ]);
    return { items: rows.map(toRun), total };
  }

  async getRun(id: string): Promise<DiscoveryRun> {
    const row = await this.prisma.discoveryRun.findUnique({ where: { id } });
    if (row === null) throw new NotFoundException('Discovery run not found');
    return toRun(row);
  }

  async listConnectors(): Promise<PocConnectorStatus[]> {
    const states = await this.prisma.connectorState.findMany();
    const statuses: PocConnectorStatus[] = [];
    for (const info of this.connectors) {
      const lastRun = await this.prisma.discoveryRun.findFirst({
        where: { connector: info.connector },
        orderBy: { startedAt: 'desc' },
        select: { startedAt: true, status: true },
      });
      const terms = CONNECTOR_TERMS[info.connector];
      const state = states.find((entry) => entry.connector === info.connector);
      statuses.push({
        connector: info.connector,
        name: terms.name,
        description: terms.description,
        approved: true,
        enabled: info.enabled,
        allowedOrigins: [...info.allowedOrigins],
        authentication: info.authentication,
        schedule: info.schedule,
        termsUrl: terms.termsUrl,
        cursor: (state?.cursor as Record<string, unknown> | undefined) ?? null,
        lastRunAt: lastRun?.startedAt.toISOString() ?? null,
        lastRunStatus: lastRun?.status ?? null,
      });
    }
    return statuses;
  }
}
