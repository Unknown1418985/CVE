import {
  EMPTY_SYNC_RUN_STATS,
  syncRunStatsSchema,
  type DomainEventEnvelope,
  type EpssScore,
  type IntelligenceSource,
  type ListSyncRunsQuery,
  type SyncRunStats,
} from '@cve/contracts';

import { Prisma, type PrismaClient } from '../generated/prisma/client.js';
import type { JsonObject } from '../sources/source-adapter.js';
import {
  MAX_STORED_ISSUES_PER_RUN,
  type EpssInsert,
  type IntelligenceRepository,
  type NewIssue,
  type NewSyncRun,
  type RecordChangeSet,
  type StoredRecordState,
  type SyncRunIssueRecord,
  type SyncRunRecord,
  type SyncStateRecord,
} from './ports.js';

type Tx = Prisma.TransactionClient;
type SyncRunRow = Prisma.SyncRunGetPayload<object>;
type SyncStateRow = Prisma.SourceSyncStateGetPayload<object>;

/** Large NVD pages write a few thousand rows; the default 5 s interactive timeout is too short. */
const TRANSACTION_OPTIONS = { maxWait: 10_000, timeout: 120_000 } as const;
const ID_CHUNK = 1_000;

function jsonObject(value: Prisma.JsonValue | null): JsonObject | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

/** Nullable JSON column value: SQL NULL for null, the JSON document otherwise. */
function nullableJson(value: unknown): Prisma.InputJsonValue | typeof Prisma.DbNull {
  if (value === null || value === undefined) return Prisma.DbNull;
  return value;
}

function json(value: unknown): Prisma.InputJsonValue {
  return value as Prisma.InputJsonValue;
}

function stats(value: Prisma.JsonValue): SyncRunStats {
  const parsed = syncRunStatsSchema.safeParse(value);
  return parsed.success ? parsed.data : { ...EMPTY_SYNC_RUN_STATS };
}

function toRun(row: SyncRunRow): SyncRunRecord {
  return {
    id: row.id,
    source: row.source as IntelligenceSource,
    trigger: row.trigger,
    status: row.status,
    jobId: row.jobId,
    attempt: row.attempt,
    requestedBy: row.requestedBy,
    resumedFromRunId: row.resumedFromRunId,
    startedAt: row.startedAt,
    heartbeatAt: row.heartbeatAt,
    finishedAt: row.finishedAt,
    cursorBefore: jsonObject(row.cursorBefore),
    cursorAfter: jsonObject(row.cursorAfter),
    checkpoint: jsonObject(row.checkpoint),
    stats: stats(row.stats),
    error: row.error,
    issueCount: row.issueCount,
  };
}

function toState(row: SyncStateRow): SyncStateRecord {
  return {
    source: row.source as IntelligenceSource,
    cursor: jsonObject(row.cursor),
    lastRunAt: row.lastRunAt,
    lastRunStatus: row.lastRunStatus,
    lastSuccessAt: row.lastSuccessAt,
    consecutiveFailures: row.consecutiveFailures,
    leaseOwner: row.leaseOwner,
    leaseExpiresAt: row.leaseExpiresAt,
  };
}

function chunks<T>(items: readonly T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < items.length; index += size)
    result.push(items.slice(index, index + size));
  return result;
}

async function writeOutbox(tx: Tx, events: readonly DomainEventEnvelope[]): Promise<void> {
  if (events.length === 0) return;
  await tx.outboxEvent.createMany({
    data: events.map((event) => ({
      eventId: event.eventId,
      eventType: event.eventType,
      envelope: json(event),
    })),
  });
}

/** Appends issues while the run has stored fewer than MAX_STORED_ISSUES_PER_RUN. */
async function writeIssues(tx: Tx, runId: string, issues: readonly NewIssue[]): Promise<void> {
  if (issues.length === 0) return;
  const stored = await tx.syncRunIssue.count({ where: { runId } });
  const room = Math.max(0, MAX_STORED_ISSUES_PER_RUN - stored);
  if (room > 0) {
    await tx.syncRunIssue.createMany({
      data: issues.slice(0, room).map((issue) => ({
        runId,
        sourceRecordId: issue.sourceRecordId?.slice(0, 128) ?? null,
        message: issue.message.slice(0, 2_000),
      })),
    });
  }
  await tx.syncRun.update({
    where: { id: runId },
    data: { issueCount: { increment: issues.length } },
  });
}

/** PostgreSQL implementation of the Intelligence Service persistence port. */
export class PrismaIntelligenceRepository implements IntelligenceRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async listSyncStates(): Promise<SyncStateRecord[]> {
    return (await this.prisma.sourceSyncState.findMany({ orderBy: { source: 'asc' } })).map(
      toState,
    );
  }

  async getSyncState(source: IntelligenceSource): Promise<SyncStateRecord | null> {
    const row = await this.prisma.sourceSyncState.findUnique({ where: { source } });
    return row === null ? null : toState(row);
  }

  async acquireLease(
    source: IntelligenceSource,
    owner: string,
    expiresAt: Date,
    now: Date,
  ): Promise<{ acquired: boolean; abandonedRunIds: string[] }> {
    return this.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<{ source: string }[]>`
        INSERT INTO "source_sync_states" ("source", "lease_owner", "lease_expires_at", "updated_at")
        VALUES (${source}, ${owner}, ${expiresAt}, ${now})
        ON CONFLICT ("source") DO UPDATE
           SET "lease_owner" = EXCLUDED."lease_owner",
               "lease_expires_at" = EXCLUDED."lease_expires_at",
               "updated_at" = EXCLUDED."updated_at"
         WHERE "source_sync_states"."lease_owner" IS NULL
            OR "source_sync_states"."lease_expires_at" IS NULL
            OR "source_sync_states"."lease_expires_at" <= ${now}
        RETURNING "source"`;
      if (rows.length === 0) return { acquired: false, abandonedRunIds: [] };
      const running = await tx.syncRun.findMany({
        where: { source, status: 'running' },
        select: { id: true },
      });
      if (running.length > 0) {
        await tx.syncRun.updateMany({
          where: { id: { in: running.map((run) => run.id) } },
          data: {
            status: 'abandoned',
            finishedAt: now,
            error: 'The worker stopped before finishing the run',
          },
        });
      }
      return { acquired: true, abandonedRunIds: running.map((run) => run.id) };
    });
  }

  async renewLease(
    source: IntelligenceSource,
    owner: string,
    expiresAt: Date,
    runId: string,
    now: Date,
  ): Promise<boolean> {
    return this.prisma.$transaction(async (tx) => {
      const lease = await tx.sourceSyncState.updateMany({
        where: { source, leaseOwner: owner },
        data: { leaseExpiresAt: expiresAt },
      });
      if (lease.count === 0) return false;
      await tx.syncRun.updateMany({
        where: { id: runId, status: 'running' },
        data: { heartbeatAt: now },
      });
      return true;
    });
  }

  async releaseLease(source: IntelligenceSource, owner: string): Promise<void> {
    await this.prisma.sourceSyncState.updateMany({
      where: { source, leaseOwner: owner },
      data: { leaseOwner: null, leaseExpiresAt: null },
    });
  }

  async createRun(run: NewSyncRun): Promise<SyncRunRecord> {
    const row = await this.prisma.syncRun.create({
      data: {
        source: run.source,
        trigger: run.trigger,
        jobId: run.jobId,
        attempt: run.attempt,
        requestedBy: run.requestedBy,
        resumedFromRunId: run.resumedFromRunId,
        startedAt: run.startedAt,
        heartbeatAt: run.startedAt,
        cursorBefore: nullableJson(run.cursorBefore),
        checkpoint: nullableJson(run.checkpoint),
        stats: json(EMPTY_SYNC_RUN_STATS),
      },
    });
    return toRun(row);
  }

  async findRun(id: string): Promise<SyncRunRecord | null> {
    const row = await this.prisma.syncRun.findUnique({ where: { id } });
    return row === null ? null : toRun(row);
  }

  async latestRun(source: IntelligenceSource): Promise<SyncRunRecord | null> {
    const row = await this.prisma.syncRun.findFirst({
      where: { source },
      orderBy: { startedAt: 'desc' },
    });
    return row === null ? null : toRun(row);
  }

  async listRuns(query: ListSyncRunsQuery): Promise<{ items: SyncRunRecord[]; total: number }> {
    const where: Prisma.SyncRunWhereInput = {
      ...(query.source === undefined ? {} : { source: query.source }),
      ...(query.status === undefined ? {} : { status: query.status }),
      ...(query.trigger === undefined ? {} : { trigger: query.trigger }),
    };
    const [rows, total] = await this.prisma.$transaction([
      this.prisma.syncRun.findMany({
        where,
        orderBy: [{ startedAt: 'desc' }, { id: 'desc' }],
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.syncRun.count({ where }),
    ]);
    return { items: rows.map(toRun), total };
  }

  async listRunIssues(runId: string, limit: number): Promise<SyncRunIssueRecord[]> {
    return this.prisma.syncRunIssue.findMany({
      where: { runId },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: limit,
      select: { sourceRecordId: true, message: true, createdAt: true },
    });
  }

  async saveProgress(
    runId: string,
    progress: {
      checkpoint: JsonObject;
      stats: SyncRunStats;
      issues: readonly NewIssue[];
      now: Date;
    },
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await tx.syncRun.update({
        where: { id: runId },
        data: {
          checkpoint: json(progress.checkpoint),
          stats: json(progress.stats),
          heartbeatAt: progress.now,
        },
      });
      await writeIssues(tx, runId, progress.issues);
    });
  }

  async completeRun(
    runId: string,
    result: {
      finishedAt: Date;
      stats: SyncRunStats;
      cursorAfter: JsonObject;
      issues: readonly NewIssue[];
      events: readonly DomainEventEnvelope[];
    },
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const run = await tx.syncRun.update({
        where: { id: runId },
        data: {
          status: 'succeeded',
          finishedAt: result.finishedAt,
          heartbeatAt: result.finishedAt,
          stats: json(result.stats),
          cursorAfter: json(result.cursorAfter),
        },
      });
      await writeIssues(tx, runId, result.issues);
      await tx.sourceSyncState.update({
        where: { source: run.source },
        data: {
          cursor: json(result.cursorAfter),
          lastRunAt: run.startedAt,
          lastRunStatus: 'succeeded',
          lastSuccessAt: result.finishedAt,
          consecutiveFailures: 0,
        },
      });
      await writeOutbox(tx, result.events);
    }, TRANSACTION_OPTIONS);
  }

  async failRun(
    runId: string,
    result: {
      status: 'failed' | 'abandoned';
      finishedAt: Date;
      stats: SyncRunStats | null;
      error: string;
      events: readonly DomainEventEnvelope[];
    },
  ): Promise<boolean> {
    return this.prisma.$transaction(async (tx) => {
      const updated = await tx.syncRun.updateMany({
        where: { id: runId, status: 'running' },
        data: {
          status: result.status,
          finishedAt: result.finishedAt,
          error: result.error.slice(0, 2_000),
          ...(result.stats === null ? {} : { stats: json(result.stats) }),
        },
      });
      if (updated.count === 0) return false;
      const run = await tx.syncRun.findUniqueOrThrow({ where: { id: runId } });
      await tx.sourceSyncState.upsert({
        where: { source: run.source },
        create: {
          source: run.source,
          lastRunAt: run.startedAt,
          lastRunStatus: result.status,
          consecutiveFailures: 1,
        },
        update: {
          lastRunAt: run.startedAt,
          lastRunStatus: result.status,
          consecutiveFailures: { increment: 1 },
        },
      });
      await writeOutbox(tx, result.events);
      return true;
    });
  }

  async findStaleRuns(before: Date): Promise<SyncRunRecord[]> {
    const rows = await this.prisma.syncRun.findMany({
      where: { status: 'running', heartbeatAt: { lt: before } },
      orderBy: { heartbeatAt: 'asc' },
      take: 100,
    });
    return rows.map(toRun);
  }

  async findRecordStates(
    source: IntelligenceSource,
    externalIds: readonly string[],
  ): Promise<Map<string, StoredRecordState>> {
    const states = new Map<string, StoredRecordState>();
    for (const ids of chunks(externalIds, ID_CHUNK)) {
      const rows = await this.prisma.sourceRecord.findMany({
        where: { source, externalId: { in: ids } },
        select: { externalId: true, contentHash: true, revision: true, removedAt: true },
      });
      for (const row of rows) states.set(row.externalId, row);
    }
    return states;
  }

  async findActiveRecordIds(source: IntelligenceSource): Promise<string[]> {
    const rows = await this.prisma.sourceRecord.findMany({
      where: { source, removedAt: null },
      select: { externalId: true },
    });
    return rows.map((row) => row.externalId);
  }

  async applyRecordChanges(changes: RecordChangeSet): Promise<void> {
    const { source, runId, observedAt } = changes;
    await this.prisma.$transaction(async (tx) => {
      const revisions: Prisma.SourceRecordRevisionCreateManyInput[] = [];
      for (const write of changes.writes) {
        const removed = write.change === 'removed';
        const record = await tx.sourceRecord.upsert({
          where: { source_externalId: { source, externalId: write.externalId } },
          create: {
            source,
            externalId: write.externalId,
            cveId: write.cveId,
            sourceUrl: write.sourceUrl,
            contentHash: write.contentHash,
            revision: write.revision,
            content: json(write.content),
            raw: nullableJson(write.raw),
            sourceModifiedAt: write.sourceModifiedAt,
            firstSeenAt: observedAt,
            lastSeenAt: observedAt,
            lastChangedAt: observedAt,
            removedAt: removed ? observedAt : null,
            lastRunId: runId,
          },
          update: removed
            ? {
                revision: write.revision,
                lastSeenAt: observedAt,
                lastChangedAt: observedAt,
                removedAt: observedAt,
                lastRunId: runId,
              }
            : {
                cveId: write.cveId,
                sourceUrl: write.sourceUrl,
                contentHash: write.contentHash,
                revision: write.revision,
                content: json(write.content),
                raw: nullableJson(write.raw),
                sourceModifiedAt: write.sourceModifiedAt,
                lastSeenAt: observedAt,
                lastChangedAt: observedAt,
                removedAt: null,
                lastRunId: runId,
              },
          select: { id: true },
        });
        revisions.push({
          recordId: record.id,
          revision: write.revision,
          contentHash: write.contentHash,
          content: json(removed ? {} : write.content),
          sourceModifiedAt: write.sourceModifiedAt,
          removed,
          observedAt,
          runId,
        });
      }
      // The (record, revision) unique key rejects a concurrent writer of the same revision.
      if (revisions.length > 0) await tx.sourceRecordRevision.createMany({ data: revisions });
      for (const ids of chunks(changes.unchanged, ID_CHUNK)) {
        await tx.sourceRecord.updateMany({
          where: { source, externalId: { in: ids } },
          data: { lastSeenAt: observedAt, lastRunId: runId },
        });
      }
      await writeOutbox(tx, changes.events);
    }, TRANSACTION_OPTIONS);
  }

  async insertEpssScores(
    insert: EpssInsert,
    buildEvents: (inserted: readonly EpssScore[]) => readonly DomainEventEnvelope[],
  ): Promise<{ inserted: number; events: number }> {
    const scoreDate = new Date(`${insert.scoreDate}T00:00:00Z`);
    return this.prisma.$transaction(async (tx) => {
      const rows = await tx.epssScore.createManyAndReturn({
        data: insert.scores.map((score) => ({
          cveId: score.cveId,
          scoreDate,
          score: new Prisma.Decimal(score.score),
          percentile: new Prisma.Decimal(score.percentile),
          modelVersion: insert.modelVersion,
          observedAt: insert.observedAt,
          runId: insert.runId,
        })),
        skipDuplicates: true,
        select: { cveId: true },
      });
      const inserted = new Set(rows.map((row) => row.cveId));
      const events = buildEvents(insert.scores.filter((score) => inserted.has(score.cveId)));
      await writeOutbox(tx, events);
      return { inserted: inserted.size, events: events.length };
    }, TRANSACTION_OPTIONS);
  }

  async purgeEpssScoresBefore(scoreDate: string): Promise<number> {
    const result = await this.prisma.epssScore.deleteMany({
      where: { scoreDate: { lt: new Date(`${scoreDate}T00:00:00Z`) } },
    });
    return result.count;
  }

  async purgePublishedOutboxBefore(cutoff: Date): Promise<number> {
    const result = await this.prisma.outboxEvent.deleteMany({
      where: { publishedAt: { not: null, lt: cutoff } },
    });
    return result.count;
  }
}
