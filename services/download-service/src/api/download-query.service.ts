import { Inject, Injectable, NotFoundException } from '@nestjs/common';

import type {
  DownloadArtifact,
  DownloadArtifactDetail,
  DownloadRequest,
  DownloadRequestDetail,
  DownloadSourceStatus,
  LifecycleEvent,
  ListDownloadArtifactsQuery,
  ListDownloadRequestsQuery,
  Permission,
  ScanResult,
} from '@cve/contracts';

import { sourceStatus } from '../download/source-catalog.js';
import type { Prisma, PrismaClient, StoredArtifact } from '../generated/prisma/client.js';
import { PRISMA } from '../persistence/database.js';
import { SCAN_STATUS_TO_DB } from '../persistence/enums.js';
import {
  toArtifact,
  toAttempt,
  toLifecycleEvent,
  toProvenance,
  toRequest,
  toScanResult,
} from './mappers.js';
import { SOURCE_POLICIES, type SourcePolicy } from './tokens.js';

interface Page<T> {
  readonly items: T[];
  readonly total: number;
}

const skip = (query: { page: number; pageSize: number }) => (query.page - 1) * query.pageSize;

/**
 * Quarantined and rejected artifacts are visible only with `quarantine:read`: ordinary users see
 * released artifacts only, and get 404 for anything else (CLAUDE.md §2.16).
 */
export function canSeeQuarantine(permissions: readonly Permission[]): boolean {
  return permissions.includes('quarantine:read');
}

@Injectable()
export class DownloadQueryService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(SOURCE_POLICIES) private readonly sources: readonly SourcePolicy[],
  ) {}

  listSources(): DownloadSourceStatus[] {
    return this.sources.map(sourceStatus);
  }

  async listRequests(query: ListDownloadRequestsQuery): Promise<Page<DownloadRequest>> {
    const where: Prisma.DownloadRequestWhereInput = {
      ...(query.status === undefined ? {} : { status: { in: query.status } }),
      ...(query.source === undefined ? {} : { source: query.source }),
      ...(query.trigger === undefined ? {} : { trigger: query.trigger }),
      ...(query.cveId === undefined ? {} : { cveIds: { has: query.cveId } }),
      ...(query.pocArtifactId === undefined ? {} : { pocArtifactId: query.pocArtifactId }),
      ...(query.artifactId === undefined ? {} : { artifactId: query.artifactId }),
      ...(query.createdFrom === undefined ? {} : { createdAt: { gte: query.createdFrom } }),
    };
    const orderBy: Prisma.DownloadRequestOrderByWithRelationInput[] = [
      query.sort === 'finishedAt'
        ? { finishedAt: { sort: query.order, nulls: 'last' } }
        : { [query.sort]: query.order },
      { id: 'asc' },
    ];
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.downloadRequest.findMany({
        where,
        orderBy,
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.downloadRequest.count({ where }),
    ]);
    return { items: rows.map(toRequest), total };
  }

  async getRequest(id: string): Promise<DownloadRequestDetail> {
    const row = await this.prisma.downloadRequest.findUnique({
      where: { id },
      include: { attemptHistory: { orderBy: { attempt: 'desc' } } },
    });
    if (row === null) throw new NotFoundException('Download request not found');
    return { ...toRequest(row), attemptHistory: row.attemptHistory.map(toAttempt) };
  }

  private async pocIds(artifactIds: readonly string[]): Promise<Map<string, string[]>> {
    const rows = await this.prisma.artifactSource.findMany({
      where: { artifactId: { in: [...artifactIds] }, pocArtifactId: { not: null } },
      select: { artifactId: true, pocArtifactId: true },
      orderBy: { pocArtifactId: 'asc' },
    });
    const map = new Map<string, string[]>();
    for (const row of rows) {
      if (row.pocArtifactId === null) continue;
      const list = map.get(row.artifactId) ?? [];
      if (!list.includes(row.pocArtifactId)) list.push(row.pocArtifactId);
      map.set(row.artifactId, list);
    }
    return map;
  }

  async listArtifacts(
    query: ListDownloadArtifactsQuery,
    permissions: readonly Permission[],
  ): Promise<Page<DownloadArtifact>> {
    const visible: Prisma.StoredArtifactWhereInput = canSeeQuarantine(permissions)
      ? {}
      : { lifecycleStatus: 'released' };
    const where: Prisma.StoredArtifactWhereInput = {
      AND: [
        visible,
        query.lifecycleStatus === undefined
          ? {}
          : { lifecycleStatus: { in: query.lifecycleStatus } },
        query.scanStatus === undefined
          ? {}
          : { scanStatus: { in: query.scanStatus.map((status) => SCAN_STATUS_TO_DB[status]) } },
        query.source === undefined ? {} : { source: query.source },
        query.cveId === undefined ? {} : { cveIds: { has: query.cveId } },
        query.sha256 === undefined ? {} : { sha256: query.sha256 },
        query.pocArtifactId === undefined
          ? {}
          : { sources: { some: { pocArtifactId: query.pocArtifactId } } },
      ],
    };
    const orderBy: Prisma.StoredArtifactOrderByWithRelationInput[] = [
      query.sort === 'lastScannedAt'
        ? { lastScannedAt: { sort: query.order, nulls: 'last' } }
        : { [query.sort]: query.order },
      { id: 'asc' },
    ];
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.storedArtifact.findMany({
        where,
        orderBy,
        skip: skip(query),
        take: query.pageSize,
      }),
      this.prisma.storedArtifact.count({ where }),
    ]);
    const poc = await this.pocIds(rows.map((row) => row.id));
    return { items: rows.map((row) => toArtifact(row, poc.get(row.id) ?? [])), total };
  }

  /** The artifact row if this caller may see it; 404 otherwise (no existence leak). */
  async visibleArtifact(id: string, permissions: readonly Permission[]): Promise<StoredArtifact> {
    const row = await this.prisma.storedArtifact.findUnique({ where: { id } });
    if (row === null || (row.lifecycleStatus !== 'released' && !canSeeQuarantine(permissions))) {
      throw new NotFoundException('Artifact not found');
    }
    return row;
  }

  async getArtifact(
    id: string,
    permissions: readonly Permission[],
  ): Promise<DownloadArtifactDetail> {
    const row = await this.visibleArtifact(id, permissions);
    const [provenance, latest, poc] = await Promise.all([
      this.prisma.artifactSource.findMany({
        where: { artifactId: id },
        orderBy: { downloadedAt: 'asc' },
      }),
      this.prisma.scanResult.findFirst({
        where: { artifactId: id },
        orderBy: { finishedAt: 'desc' },
      }),
      this.pocIds([id]),
    ]);
    const latestScan =
      latest === null
        ? []
        : await this.prisma.scanResult.findMany({
            where: { scanRunId: latest.scanRunId },
            orderBy: { scanner: 'asc' },
          });
    return {
      ...toArtifact(row, poc.get(id) ?? []),
      provenance: provenance.map(toProvenance),
      latestScan: latestScan.map(toScanResult),
    };
  }

  async scanHistory(id: string, permissions: readonly Permission[]): Promise<ScanResult[]> {
    await this.visibleArtifact(id, permissions);
    const rows = await this.prisma.scanResult.findMany({
      where: { artifactId: id },
      orderBy: [{ finishedAt: 'desc' }, { scanner: 'asc' }],
      take: 200,
    });
    return rows.map(toScanResult);
  }

  async lifecycleHistory(
    id: string,
    permissions: readonly Permission[],
  ): Promise<LifecycleEvent[]> {
    await this.visibleArtifact(id, permissions);
    const rows = await this.prisma.artifactLifecycleEvent.findMany({
      where: { artifactId: id },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });
    return rows.map(toLifecycleEvent);
  }
}
