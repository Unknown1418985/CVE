import { randomUUID } from 'node:crypto';

import {
  EMPTY_SYNC_RUN_STATS,
  type DomainEventEnvelope,
  type EpssScore,
  type IntelligenceSource,
  type ListSyncRunsQuery,
  type SyncRunStats,
} from '@cve/contracts';

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
} from '../src/persistence/ports.js';
import type { JsonObject } from '../src/sources/source-adapter.js';

interface StoredRecord extends StoredRecordState {
  readonly source: IntelligenceSource;
  readonly cveId: string | null;
  readonly content: JsonObject;
  readonly raw: unknown;
  readonly lastSeenAt: Date;
}

interface StoredRevision {
  readonly source: IntelligenceSource;
  readonly externalId: string;
  readonly revision: number;
  readonly removed: boolean;
  readonly content: JsonObject;
}

const clone = <T>(value: T): T => structuredClone(value);

/**
 * In-memory implementation of the persistence port with the same contract as PostgreSQL
 * (leases, one running run per source, atomic outbox writes, unique EPSS scores). The
 * integration suite runs the same scenarios against PostgreSQL.
 */
export class InMemoryIntelligenceRepository implements IntelligenceRepository {
  readonly states = new Map<IntelligenceSource, SyncStateRecord>();
  readonly runs = new Map<string, SyncRunRecord>();
  readonly issues = new Map<string, SyncRunIssueRecord[]>();
  readonly records = new Map<string, StoredRecord>();
  readonly revisions: StoredRevision[] = [];
  readonly epss = new Map<string, EpssScore & { scoreDate: string }>();
  readonly outbox: DomainEventEnvelope[] = [];
  /** Called before a batch write; tests throw from it to simulate a database failure. */
  beforeApply: (() => void) | undefined;

  private key(source: string, externalId: string): string {
    return `${source}|${externalId}`;
  }

  private state(source: IntelligenceSource): SyncStateRecord {
    return (
      this.states.get(source) ?? {
        source,
        cursor: null,
        lastRunAt: null,
        lastRunStatus: null,
        lastSuccessAt: null,
        consecutiveFailures: 0,
        leaseOwner: null,
        leaseExpiresAt: null,
      }
    );
  }

  eventsOfType(type: string): DomainEventEnvelope[] {
    return this.outbox.filter((event) => event.eventType === type);
  }

  listSyncStates(): Promise<SyncStateRecord[]> {
    return Promise.resolve([...this.states.values()].map(clone));
  }

  getSyncState(source: IntelligenceSource): Promise<SyncStateRecord | null> {
    const state = this.states.get(source);
    return Promise.resolve(state === undefined ? null : clone(state));
  }

  acquireLease(source: IntelligenceSource, owner: string, expiresAt: Date, now: Date) {
    const state = this.state(source);
    if (state.leaseOwner !== null && state.leaseExpiresAt !== null && state.leaseExpiresAt > now) {
      return Promise.resolve({ acquired: false, abandonedRunIds: [] });
    }
    this.states.set(source, { ...state, leaseOwner: owner, leaseExpiresAt: expiresAt });
    const abandoned: string[] = [];
    for (const run of this.runs.values()) {
      if (run.source === source && run.status === 'running') {
        this.runs.set(run.id, {
          ...run,
          status: 'abandoned',
          finishedAt: now,
          error: 'The worker stopped before finishing the run',
        });
        abandoned.push(run.id);
      }
    }
    return Promise.resolve({ acquired: true, abandonedRunIds: abandoned });
  }

  renewLease(source: IntelligenceSource, owner: string, expiresAt: Date, runId: string, now: Date) {
    const state = this.state(source);
    if (state.leaseOwner !== owner) return Promise.resolve(false);
    this.states.set(source, { ...state, leaseExpiresAt: expiresAt });
    const run = this.runs.get(runId);
    if (run?.status === 'running') this.runs.set(runId, { ...run, heartbeatAt: now });
    return Promise.resolve(true);
  }

  releaseLease(source: IntelligenceSource, owner: string): Promise<void> {
    const state = this.state(source);
    if (state.leaseOwner === owner)
      this.states.set(source, { ...state, leaseOwner: null, leaseExpiresAt: null });
    return Promise.resolve();
  }

  createRun(run: NewSyncRun): Promise<SyncRunRecord> {
    if ([...this.runs.values()].some((r) => r.source === run.source && r.status === 'running')) {
      return Promise.reject(new Error('unique violation: one running run per source'));
    }
    if (
      run.resumedFromRunId !== null &&
      [...this.runs.values()].some((r) => r.resumedFromRunId === run.resumedFromRunId)
    ) {
      return Promise.reject(new Error('unique violation: run already resumed'));
    }
    const record: SyncRunRecord = {
      ...run,
      id: randomUUID(),
      status: 'running',
      heartbeatAt: run.startedAt,
      finishedAt: null,
      cursorAfter: null,
      cursorBefore: run.cursorBefore === null ? null : clone(run.cursorBefore),
      checkpoint: run.checkpoint === null ? null : clone(run.checkpoint),
      stats: { ...EMPTY_SYNC_RUN_STATS },
      error: null,
      issueCount: 0,
    };
    this.runs.set(record.id, record);
    return Promise.resolve(clone(record));
  }

  findRun(id: string): Promise<SyncRunRecord | null> {
    const run = this.runs.get(id);
    return Promise.resolve(run === undefined ? null : clone(run));
  }

  latestRun(source: IntelligenceSource): Promise<SyncRunRecord | null> {
    const runs = [...this.runs.values()].filter((run) => run.source === source);
    const latest = runs.sort((a, b) => b.startedAt.getTime() - a.startedAt.getTime())[0];
    return Promise.resolve(latest === undefined ? null : clone(latest));
  }

  listRuns(query: ListSyncRunsQuery) {
    const all = [...this.runs.values()]
      .filter(
        (run) =>
          (query.source === undefined || run.source === query.source) &&
          (query.status === undefined || run.status === query.status) &&
          (query.trigger === undefined || run.trigger === query.trigger),
      )
      .sort((a, b) => b.startedAt.getTime() - a.startedAt.getTime());
    const start = (query.page - 1) * query.pageSize;
    return Promise.resolve({
      items: all.slice(start, start + query.pageSize).map(clone),
      total: all.length,
    });
  }

  listRunIssues(runId: string, limit: number): Promise<SyncRunIssueRecord[]> {
    return Promise.resolve((this.issues.get(runId) ?? []).slice(0, limit));
  }

  private addIssues(runId: string, issues: readonly NewIssue[]): void {
    if (issues.length === 0) return;
    const stored = this.issues.get(runId) ?? [];
    const room = Math.max(0, MAX_STORED_ISSUES_PER_RUN - stored.length);
    stored.push(...issues.slice(0, room).map((issue) => ({ ...issue, createdAt: new Date() })));
    this.issues.set(runId, stored);
    const run = this.runs.get(runId);
    if (run) this.runs.set(runId, { ...run, issueCount: run.issueCount + issues.length });
  }

  saveProgress(
    runId: string,
    progress: {
      checkpoint: JsonObject;
      stats: SyncRunStats;
      issues: readonly NewIssue[];
      now: Date;
    },
  ): Promise<void> {
    const run = this.runs.get(runId);
    if (run === undefined) return Promise.reject(new Error('run not found'));
    this.runs.set(runId, {
      ...run,
      checkpoint: clone(progress.checkpoint),
      stats: { ...progress.stats },
      heartbeatAt: progress.now,
    });
    this.addIssues(runId, progress.issues);
    return Promise.resolve();
  }

  completeRun(
    runId: string,
    result: {
      finishedAt: Date;
      stats: SyncRunStats;
      cursorAfter: JsonObject;
      issues: readonly NewIssue[];
      events: readonly DomainEventEnvelope[];
    },
  ): Promise<void> {
    const run = this.runs.get(runId);
    if (run === undefined) return Promise.reject(new Error('run not found'));
    this.runs.set(runId, {
      ...run,
      status: 'succeeded',
      finishedAt: result.finishedAt,
      heartbeatAt: result.finishedAt,
      stats: { ...result.stats },
      cursorAfter: clone(result.cursorAfter),
    });
    this.addIssues(runId, result.issues);
    const state = this.state(run.source);
    this.states.set(run.source, {
      ...state,
      cursor: clone(result.cursorAfter),
      lastRunAt: run.startedAt,
      lastRunStatus: 'succeeded',
      lastSuccessAt: result.finishedAt,
      consecutiveFailures: 0,
    });
    this.outbox.push(...result.events);
    return Promise.resolve();
  }

  failRun(
    runId: string,
    result: {
      status: 'failed' | 'abandoned';
      finishedAt: Date;
      stats: SyncRunStats | null;
      error: string;
      events: readonly DomainEventEnvelope[];
    },
  ): Promise<boolean> {
    const run = this.runs.get(runId);
    if (run?.status !== 'running') return Promise.resolve(false);
    this.runs.set(runId, {
      ...run,
      status: result.status,
      finishedAt: result.finishedAt,
      error: result.error,
      stats: result.stats === null ? run.stats : { ...result.stats },
    });
    const state = this.state(run.source);
    this.states.set(run.source, {
      ...state,
      lastRunAt: run.startedAt,
      lastRunStatus: result.status,
      consecutiveFailures: state.consecutiveFailures + 1,
    });
    this.outbox.push(...result.events);
    return Promise.resolve(true);
  }

  findStaleRuns(before: Date): Promise<SyncRunRecord[]> {
    return Promise.resolve(
      [...this.runs.values()]
        .filter((run) => run.status === 'running' && run.heartbeatAt < before)
        .map(clone),
    );
  }

  findRecordStates(source: IntelligenceSource, externalIds: readonly string[]) {
    const states = new Map<string, StoredRecordState>();
    for (const id of externalIds) {
      const record = this.records.get(this.key(source, id));
      if (record) {
        states.set(id, {
          externalId: record.externalId,
          contentHash: record.contentHash,
          revision: record.revision,
          removedAt: record.removedAt,
        });
      }
    }
    return Promise.resolve(states);
  }

  findActiveRecordIds(source: IntelligenceSource): Promise<string[]> {
    return Promise.resolve(
      [...this.records.values()]
        .filter((r) => r.source === source && r.removedAt === null)
        .map((r) => r.externalId),
    );
  }

  record(source: IntelligenceSource, externalId: string): StoredRecord | undefined {
    return this.records.get(this.key(source, externalId));
  }

  applyRecordChanges(changes: RecordChangeSet): Promise<void> {
    this.beforeApply?.();
    for (const write of changes.writes) {
      const key = this.key(changes.source, write.externalId);
      const prior = this.records.get(key);
      if ((prior?.revision ?? 0) + 1 !== write.revision) {
        return Promise.reject(new Error('unique violation: revision'));
      }
      const removed = write.change === 'removed';
      this.records.set(key, {
        source: changes.source,
        externalId: write.externalId,
        cveId: write.cveId,
        contentHash: removed && prior ? prior.contentHash : write.contentHash,
        revision: write.revision,
        content: removed && prior ? prior.content : clone(write.content),
        raw: removed && prior ? prior.raw : clone(write.raw),
        removedAt: removed ? changes.observedAt : null,
        lastSeenAt: changes.observedAt,
      });
      this.revisions.push({
        source: changes.source,
        externalId: write.externalId,
        revision: write.revision,
        removed,
        content: removed ? {} : clone(write.content),
      });
    }
    for (const id of changes.unchanged) {
      const key = this.key(changes.source, id);
      const record = this.records.get(key);
      if (record) this.records.set(key, { ...record, lastSeenAt: changes.observedAt });
    }
    this.outbox.push(...changes.events);
    return Promise.resolve();
  }

  insertEpssScores(
    insert: EpssInsert,
    buildEvents: (inserted: readonly EpssScore[]) => readonly DomainEventEnvelope[],
  ) {
    const inserted: EpssScore[] = [];
    for (const score of insert.scores) {
      const key = `${score.cveId}|${insert.scoreDate}`;
      if (this.epss.has(key)) continue;
      this.epss.set(key, { ...score, scoreDate: insert.scoreDate });
      inserted.push(score);
    }
    const events = buildEvents(inserted);
    this.outbox.push(...events);
    return Promise.resolve({ inserted: inserted.length, events: events.length });
  }

  purgeEpssScoresBefore(scoreDate: string): Promise<number> {
    let removed = 0;
    for (const [key, value] of this.epss) {
      if (value.scoreDate < scoreDate) {
        this.epss.delete(key);
        removed += 1;
      }
    }
    return Promise.resolve(removed);
  }

  purgePublishedOutboxBefore(): Promise<number> {
    return Promise.resolve(0);
  }
}
