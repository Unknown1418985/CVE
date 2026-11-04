import type {
  DomainEventEnvelope,
  EpssScore,
  IntelligenceSource,
  ListSyncRunsQuery,
  SyncRunStats,
  SyncRunStatus,
  SyncTrigger,
} from '@cve/contracts';

import type { JsonObject } from '../sources/source-adapter.js';

/** At most this many issues are stored per run; `issueCount` keeps counting. */
export const MAX_STORED_ISSUES_PER_RUN = 200;

export interface SyncStateRecord {
  readonly source: IntelligenceSource;
  readonly cursor: JsonObject | null;
  readonly lastRunAt: Date | null;
  readonly lastRunStatus: SyncRunStatus | null;
  readonly lastSuccessAt: Date | null;
  readonly consecutiveFailures: number;
  readonly leaseOwner: string | null;
  readonly leaseExpiresAt: Date | null;
}

export interface SyncRunRecord {
  readonly id: string;
  readonly source: IntelligenceSource;
  readonly trigger: SyncTrigger;
  readonly status: SyncRunStatus;
  readonly jobId: string | null;
  readonly attempt: number;
  readonly requestedBy: string | null;
  readonly resumedFromRunId: string | null;
  readonly startedAt: Date;
  readonly heartbeatAt: Date;
  readonly finishedAt: Date | null;
  readonly cursorBefore: JsonObject | null;
  readonly cursorAfter: JsonObject | null;
  readonly checkpoint: JsonObject | null;
  readonly stats: SyncRunStats;
  readonly error: string | null;
  readonly issueCount: number;
}

export interface SyncRunIssueRecord {
  readonly sourceRecordId: string | null;
  readonly message: string;
  readonly createdAt: Date;
}

export interface NewSyncRun {
  readonly source: IntelligenceSource;
  readonly trigger: SyncTrigger;
  readonly jobId: string | null;
  readonly attempt: number;
  readonly requestedBy: string | null;
  readonly resumedFromRunId: string | null;
  readonly startedAt: Date;
  readonly cursorBefore: JsonObject | null;
  readonly checkpoint: JsonObject | null;
}

export interface NewIssue {
  readonly sourceRecordId: string | null;
  readonly message: string;
}

export interface StoredRecordState {
  readonly externalId: string;
  readonly contentHash: string;
  readonly revision: number;
  readonly removedAt: Date | null;
}

export interface RecordWrite {
  readonly externalId: string;
  readonly cveId: string | null;
  readonly sourceUrl: string;
  readonly contentHash: string;
  /** Revision after this write (1 for a new record). */
  readonly revision: number;
  readonly content: JsonObject;
  readonly raw: unknown;
  readonly sourceModifiedAt: Date | null;
  /** `removed` writes a tombstone revision and sets `removedAt`. */
  readonly change: 'created' | 'updated' | 'removed';
}

/** Everything one batch changes, written atomically together with its outbox events. */
export interface RecordChangeSet {
  readonly source: IntelligenceSource;
  readonly runId: string;
  readonly observedAt: Date;
  readonly writes: readonly RecordWrite[];
  /** Items seen again with identical content: only `lastSeenAt` moves. */
  readonly unchanged: readonly string[];
  readonly events: readonly DomainEventEnvelope[];
}

export interface EpssInsert {
  readonly runId: string;
  readonly scoreDate: string;
  readonly modelVersion: string | null;
  readonly observedAt: Date;
  readonly scores: readonly EpssScore[];
}

export class LeaseLostError extends Error {
  constructor(source: string) {
    super(`The synchronisation lease of ${source} was lost`);
    this.name = 'LeaseLostError';
  }
}

/** Persistence port of the Intelligence Service (PostgreSQL in production, in-memory in tests). */
export interface IntelligenceRepository {
  listSyncStates(): Promise<SyncStateRecord[]>;
  getSyncState(source: IntelligenceSource): Promise<SyncStateRecord | null>;
  /**
   * Takes the source's lease when it is free or expired. Runs still marked `running` for the
   * source are abandoned in the same transaction: holding the lease proves they are dead.
   */
  acquireLease(
    source: IntelligenceSource,
    owner: string,
    expiresAt: Date,
    now: Date,
  ): Promise<{ acquired: boolean; abandonedRunIds: string[] }>;
  /** Extends the lease and the run heartbeat; false when another owner holds the lease. */
  renewLease(
    source: IntelligenceSource,
    owner: string,
    expiresAt: Date,
    runId: string,
    now: Date,
  ): Promise<boolean>;
  releaseLease(source: IntelligenceSource, owner: string): Promise<void>;

  createRun(run: NewSyncRun): Promise<SyncRunRecord>;
  findRun(id: string): Promise<SyncRunRecord | null>;
  latestRun(source: IntelligenceSource): Promise<SyncRunRecord | null>;
  listRuns(query: ListSyncRunsQuery): Promise<{ items: SyncRunRecord[]; total: number }>;
  listRunIssues(runId: string, limit: number): Promise<SyncRunIssueRecord[]>;
  /** Persists the position reached, the counters and new issues of a running run. */
  saveProgress(
    runId: string,
    progress: {
      checkpoint: JsonObject;
      stats: SyncRunStats;
      issues: readonly NewIssue[];
      now: Date;
    },
  ): Promise<void>;
  /** Marks the run succeeded and commits the source cursor, atomically with the events. */
  completeRun(
    runId: string,
    result: {
      finishedAt: Date;
      stats: SyncRunStats;
      cursorAfter: JsonObject;
      issues: readonly NewIssue[];
      events: readonly DomainEventEnvelope[];
    },
  ): Promise<void>;
  /** Marks a running run failed or abandoned; the cursor is left unchanged. */
  failRun(
    runId: string,
    result: {
      status: 'failed' | 'abandoned';
      finishedAt: Date;
      stats: SyncRunStats | null;
      error: string;
      events: readonly DomainEventEnvelope[];
    },
  ): Promise<boolean>;
  /** Runs still `running` whose heartbeat is older than `before` (worker crashed). */
  findStaleRuns(before: Date): Promise<SyncRunRecord[]>;

  findRecordStates(
    source: IntelligenceSource,
    externalIds: readonly string[],
  ): Promise<Map<string, StoredRecordState>>;
  /** External IDs of the source's records that are not removed. */
  findActiveRecordIds(source: IntelligenceSource): Promise<string[]>;
  applyRecordChanges(changes: RecordChangeSet): Promise<void>;

  /**
   * Inserts EPSS scores, skipping (CVE, date) pairs already stored, and writes the events built
   * from the inserted scores in the same transaction. Returns the number inserted.
   */
  insertEpssScores(
    insert: EpssInsert,
    buildEvents: (inserted: readonly EpssScore[]) => readonly DomainEventEnvelope[],
  ): Promise<{ inserted: number; events: number }>;
  purgeEpssScoresBefore(scoreDate: string): Promise<number>;
  purgePublishedOutboxBefore(cutoff: Date): Promise<number>;
}

export const INTELLIGENCE_REPOSITORY = Symbol('INTELLIGENCE_REPOSITORY');
