import {
  cveObservationRecordedPayloadSchema,
  EMPTY_SYNC_RUN_STATS,
  epssScoresPublishedPayloadSchema,
  INTELLIGENCE_EVENT_TYPES,
  kevEntryChangedPayloadSchema,
  kevEntryRemovedPayloadSchema,
  MAX_EPSS_SCORES_PER_EVENT,
  syncRunFinishedPayloadSchema,
  type DomainEventEnvelope,
  type IntelligenceSource,
  type SyncRunStats,
  type SyncTrigger,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { createDomainEvent } from '@cve/messaging';
import { isRetryable, type RequestMeter } from '@cve/source-http';
import type { z } from 'zod';

import {
  LeaseLostError,
  type IntelligenceRepository,
  type NewIssue,
  type RecordWrite,
  type SyncRunRecord,
} from '../persistence/ports.js';
import { SERVICE_NAME } from '../service.js';
import { SOURCE_TERMS } from '../sources/catalog.js';
import { contentHash } from '../sources/cve-content.js';
import type {
  CveRecordItem,
  InvalidItem,
  JsonObject,
  KevItem,
  SourceAdapter,
  SyncBatch,
} from '../sources/source-adapter.js';

export interface SyncEngineOptions {
  readonly repository: IntelligenceRepository;
  readonly adapters: ReadonlyMap<IntelligenceSource, SourceAdapter>;
  readonly logger: Logger;
  /** Identifies this worker in leases, e.g. `<hostname>:<pid>`. */
  readonly instanceId: string;
  /** Lease duration; renewed every third of it while the run is alive. Default 2 minutes. */
  readonly leaseMs?: number;
  /** A failed run younger than this is resumed from its checkpoint. Default 24 hours. */
  readonly resumeWindowMs?: number;
  /** Keep the raw upstream payloads (only where the source's terms permit). */
  readonly storeRawPayloads: boolean;
  /**
   * Refuse a CISA KEV snapshot that would remove more than this share of the stored entries
   * (and at least 10): a truncated or broken feed must not wipe the catalog. Default 0.05.
   */
  readonly maxKevRemovalRatio?: number;
  readonly now?: () => Date;
}

export interface RunRequest {
  readonly source: IntelligenceSource;
  readonly trigger: SyncTrigger;
  readonly jobId: string | null;
  /** BullMQ attempt (1 for the first). */
  readonly attempt: number;
  readonly maxAttempts: number;
  readonly requestedBy: string | null;
  /** Ignore a resumable failed run and start from the committed cursor. */
  readonly fresh: boolean;
  readonly correlationId?: string | undefined;
}

export type RunOutcome =
  | { readonly status: 'succeeded'; readonly run: SyncRunRecord }
  | { readonly status: 'skipped'; readonly reason: 'disabled' | 'locked' }
  | {
      readonly status: 'failed';
      readonly run: SyncRunRecord | null;
      readonly error: Error;
      readonly retryable: boolean;
    };

const MAX_ISSUE_LENGTH = 2_000;

function errorText(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.slice(0, MAX_ISSUE_LENGTH);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
}

interface RunState {
  readonly run: SyncRunRecord;
  readonly stats: SyncRunStats;
  readonly meter: RequestMeter;
  readonly correlationId: string | undefined;
}

/**
 * Executes synchronisation runs: takes the source lease, resumes the latest failed run from its
 * checkpoint, persists each batch (duplicate detection by content hash, revision history,
 * outbox events in the same transaction), saves the checkpoint after every batch and commits
 * the cursor only when the whole run succeeds.
 */
export class SyncEngine {
  private readonly leaseMs: number;
  private readonly resumeWindowMs: number;
  private readonly maxKevRemovalRatio: number;
  private readonly now: () => Date;

  constructor(private readonly options: SyncEngineOptions) {
    this.leaseMs = options.leaseMs ?? 2 * 60_000;
    this.resumeWindowMs = options.resumeWindowMs ?? 24 * 60 * 60_000;
    this.maxKevRemovalRatio = options.maxKevRemovalRatio ?? 0.05;
    this.now = options.now ?? (() => new Date());
  }

  isEnabled(source: IntelligenceSource): boolean {
    return this.options.adapters.has(source);
  }

  async run(request: RunRequest, signal: AbortSignal): Promise<RunOutcome> {
    const adapter = this.options.adapters.get(request.source);
    if (adapter === undefined) return { status: 'skipped', reason: 'disabled' };
    const { repository } = this.options;
    const owner = `${this.options.instanceId}:${request.jobId ?? 'direct'}`.slice(0, 200);
    const started = this.now();
    const lease = await repository.acquireLease(
      request.source,
      owner,
      new Date(started.getTime() + this.leaseMs),
      started,
    );
    if (!lease.acquired) return { status: 'skipped', reason: 'locked' };
    const logger = this.options.logger.child({ source: request.source, jobId: request.jobId });
    if (lease.abandonedRunIds.length > 0) {
      logger.warn({ runIds: lease.abandonedRunIds }, 'runs without a live worker marked abandoned');
    }

    const leaseLost = new AbortController();
    const runSignal = AbortSignal.any([signal, leaseLost.signal]);
    let state: RunState | undefined;
    let heartbeat: NodeJS.Timeout | undefined;
    try {
      const prepared = await this.prepare(adapter, request, started, logger);
      state = {
        run: prepared.run,
        stats: { ...EMPTY_SYNC_RUN_STATS },
        meter: { requests: 0 },
        correlationId: request.correlationId,
      };
      const runId = prepared.run.id;
      heartbeat = setInterval(
        () => {
          const now = this.now();
          repository
            .renewLease(request.source, owner, new Date(now.getTime() + this.leaseMs), runId, now)
            .then((renewed) => {
              if (!renewed) leaseLost.abort(new LeaseLostError(request.source));
            })
            .catch((error: unknown) => {
              logger.error({ err: error, runId }, 'failed to renew the synchronisation lease');
            });
        },
        Math.max(1_000, Math.floor(this.leaseMs / 3)),
      );
      heartbeat.unref();

      logger.info(
        { runId, trigger: request.trigger, resumedFromRunId: prepared.run.resumedFromRunId },
        'synchronisation started',
      );
      const generator = adapter.sync({
        cursor: prepared.cursor,
        checkpoint: prepared.checkpoint,
        signal: runSignal,
        logger: logger.child({ runId }),
        meter: state.meter,
        now: started,
      });
      let cursorAfter: JsonObject;
      for (;;) {
        const step = await generator.next();
        if (step.done === true) {
          cursorAfter = step.value;
          break;
        }
        const issues = await this.persist(adapter.source, step.value, state);
        state.stats.requests = state.meter.requests;
        await repository.saveProgress(runId, {
          checkpoint: step.value.checkpoint,
          stats: state.stats,
          issues,
          now: this.now(),
        });
        if (runSignal.aborted) throw runSignal.reason;
      }
      state.stats.requests = state.meter.requests;
      const finishedAt = this.now();
      const completed = {
        ...state.run,
        status: 'succeeded' as const,
        finishedAt,
        stats: state.stats,
      };
      await repository.completeRun(runId, {
        finishedAt,
        stats: state.stats,
        cursorAfter,
        issues: prepared.issues,
        events: [this.runFinishedEvent(completed, null, false, state.correlationId)],
      });
      logger.info(
        { runId, stats: state.stats, durationMs: finishedAt.getTime() - started.getTime() },
        'synchronisation succeeded',
      );
      return { status: 'succeeded', run: { ...completed, cursorAfter } };
    } catch (caught) {
      const error = asError(
        runSignal.aborted && !signal.aborted ? (runSignal.reason ?? caught) : caught,
      );
      const retryable = !(error instanceof LeaseLostError) && isRetryable(error);
      const willRetry = retryable && request.attempt < request.maxAttempts;
      if (state === undefined) {
        logger.error({ err: error }, 'synchronisation could not start');
        return { status: 'failed', run: null, error, retryable };
      }
      state.stats.requests = state.meter.requests;
      const finishedAt = this.now();
      const failed = {
        ...state.run,
        status: 'failed' as const,
        finishedAt,
        stats: state.stats,
        error: errorText(error),
      };
      try {
        await repository.failRun(state.run.id, {
          status: 'failed',
          finishedAt,
          stats: state.stats,
          error: errorText(error),
          events: [this.runFinishedEvent(failed, errorText(error), willRetry, state.correlationId)],
        });
      } catch (persistError) {
        // The run stays `running`; stale-run recovery marks it abandoned later.
        logger.error({ err: persistError, runId: state.run.id }, 'failed to record the failed run');
      }
      logger.error(
        { err: error, runId: state.run.id, stats: state.stats, willRetry },
        'synchronisation failed',
      );
      return { status: 'failed', run: failed, error, retryable };
    } finally {
      clearInterval(heartbeat);
      try {
        await repository.releaseLease(request.source, owner);
      } catch (error) {
        logger.error(
          { err: error },
          'failed to release the synchronisation lease (it will expire)',
        );
      }
    }
  }

  /** Creates the run, resuming the latest failed run's checkpoint when it is recent. */
  private async prepare(
    adapter: SourceAdapter,
    request: RunRequest,
    started: Date,
    logger: Logger,
  ): Promise<{
    run: SyncRunRecord;
    cursor: JsonObject | null;
    checkpoint: JsonObject | null;
    issues: NewIssue[];
  }> {
    const { repository } = this.options;
    const issues: NewIssue[] = [];
    const syncState = await repository.getSyncState(request.source);
    let cursor: JsonObject | null = null;
    if (syncState?.cursor != null) {
      const parsed = adapter.cursorSchema.safeParse(syncState.cursor);
      if (parsed.success) cursor = parsed.data;
      else {
        issues.push({
          sourceRecordId: null,
          message: 'The stored cursor is invalid; the run started from the initial position.',
        });
        logger.warn({ issues: parsed.error.issues }, 'stored cursor is invalid and was ignored');
      }
    }
    let checkpoint: JsonObject | null = null;
    let resumedFromRunId: string | null = null;
    if (!request.fresh) {
      const latest = await repository.latestRun(request.source);
      if (
        latest !== null &&
        (latest.status === 'failed' || latest.status === 'abandoned') &&
        latest.checkpoint !== null &&
        latest.finishedAt !== null &&
        started.getTime() - latest.finishedAt.getTime() <= this.resumeWindowMs
      ) {
        const parsed = adapter.checkpointSchema.safeParse(latest.checkpoint);
        if (parsed.success) {
          checkpoint = parsed.data;
          resumedFromRunId = latest.id;
        } else {
          logger.warn(
            { runId: latest.id },
            'checkpoint of the failed run is invalid; starting fresh',
          );
        }
      }
    }
    const run = await repository.createRun({
      source: request.source,
      trigger: request.trigger,
      jobId: request.jobId,
      attempt: request.attempt,
      requestedBy: request.requestedBy,
      resumedFromRunId,
      startedAt: started,
      cursorBefore: cursor,
      checkpoint,
    });
    return { run, cursor, checkpoint, issues };
  }

  private event(
    eventType: string,
    schema: z.ZodType,
    payload: unknown,
    correlationId: string | undefined,
  ): DomainEventEnvelope {
    // Validate against the published contract before anything reaches the outbox.
    schema.parse(payload);
    return createDomainEvent({ eventType, producer: SERVICE_NAME, payload, correlationId });
  }

  private runFinishedEvent(
    run: SyncRunRecord & { finishedAt: Date },
    error: string | null,
    willRetry: boolean,
    correlationId: string | undefined,
  ): DomainEventEnvelope {
    return this.event(
      run.status === 'succeeded'
        ? INTELLIGENCE_EVENT_TYPES.syncCompleted
        : INTELLIGENCE_EVENT_TYPES.syncFailed,
      syncRunFinishedPayloadSchema,
      {
        runId: run.id,
        source: run.source,
        trigger: run.trigger,
        status: run.status,
        startedAt: run.startedAt.toISOString(),
        finishedAt: run.finishedAt.toISOString(),
        stats: run.stats,
        resumedFromRunId: run.resumedFromRunId,
        error,
        willRetry,
      },
      correlationId,
    );
  }

  /** Builds an event for an abandoned run (stale-run recovery). */
  abandonedRunEvent(run: SyncRunRecord, finishedAt: Date): DomainEventEnvelope {
    return this.runFinishedEvent(
      { ...run, status: 'abandoned', finishedAt },
      'The worker stopped sending heartbeats',
      false,
      undefined,
    );
  }

  private invalidIssues(invalid: readonly InvalidItem[], stats: SyncRunStats): NewIssue[] {
    stats.fetched += invalid.length;
    stats.invalid += invalid.length;
    return invalid.map((item) => ({
      sourceRecordId: item.externalId,
      message: item.issue.slice(0, MAX_ISSUE_LENGTH),
    }));
  }

  private async persist(
    source: IntelligenceSource,
    batch: SyncBatch<JsonObject>,
    state: RunState,
  ): Promise<NewIssue[]> {
    switch (batch.kind) {
      case 'cve-records':
        return [
          ...this.invalidIssues(batch.invalid, state.stats),
          ...(await this.persistCveRecords(source, batch.records, state)),
        ];
      case 'kev-catalog':
        return [
          ...this.invalidIssues(batch.invalid, state.stats),
          ...(await this.persistKevCatalog(source, batch, state)),
        ];
      case 'epss-scores':
        return [
          ...this.invalidIssues(batch.invalid, state.stats),
          ...(await this.persistEpss(source, batch, state)),
        ];
      case 'notice':
        return [{ sourceRecordId: null, message: batch.issue.slice(0, MAX_ISSUE_LENGTH) }];
    }
  }

  private raw(source: IntelligenceSource, raw: unknown): unknown {
    return this.options.storeRawPayloads && SOURCE_TERMS[source].rawRetentionPermitted ? raw : null;
  }

  private async persistCveRecords(
    source: IntelligenceSource,
    items: readonly CveRecordItem[],
    state: RunState,
  ): Promise<NewIssue[]> {
    const { stats, run } = state;
    // A source can list an item twice in one response; the last occurrence wins.
    const unique = [...new Map(items.map((item) => [item.externalId, item])).values()];
    stats.fetched += items.length;
    stats.unchanged += items.length - unique.length;
    const stored = await this.options.repository.findRecordStates(
      source,
      unique.map((item) => item.externalId),
    );
    const observedAt = this.now();
    const writes: RecordWrite[] = [];
    const unchanged: string[] = [];
    const events: DomainEventEnvelope[] = [];
    const issues: NewIssue[] = [];
    const terms = SOURCE_TERMS[source];

    for (const item of unique) {
      if (item.issues.length > 0) {
        stats.invalid += 1;
        issues.push({
          sourceRecordId: item.externalId,
          message: item.issues.join('; ').slice(0, MAX_ISSUE_LENGTH),
        });
      }
      const content: JsonObject = {
        cveId: item.cveId,
        withdrawn: item.withdrawn === true,
        content: item.content,
      };
      const hash = contentHash(content);
      const prior = stored.get(item.externalId);
      const base = {
        externalId: item.externalId,
        cveId: item.cveId,
        sourceUrl: item.sourceUrl,
        contentHash: hash,
        content,
        raw: this.raw(source, item.raw),
        sourceModifiedAt: item.sourceModifiedAt,
      };
      if (item.withdrawn === true) {
        if (prior !== undefined && prior.removedAt !== null) {
          unchanged.push(item.externalId);
          stats.unchanged += 1;
        } else {
          writes.push({ ...base, revision: (prior?.revision ?? 0) + 1, change: 'removed' });
          stats.removed += 1;
        }
        continue;
      }
      if (prior?.contentHash === hash && prior.removedAt === null) {
        unchanged.push(item.externalId);
        stats.unchanged += 1;
        continue;
      }
      const change = prior === undefined ? 'created' : 'updated';
      const revision = (prior?.revision ?? 0) + 1;
      writes.push({ ...base, revision, change });
      if (change === 'created') stats.created += 1;
      else stats.updated += 1;
      if (item.cveId === null || item.content === null) continue;
      const payload = {
        source,
        sourceRecordId: item.externalId,
        sourceUrl: item.sourceUrl,
        attribution: terms.attribution,
        revision,
        contentHash: hash,
        observedAt: observedAt.toISOString(),
        sourceModifiedAt: item.sourceModifiedAt?.toISOString() ?? null,
        runId: run.id,
        cveId: item.cveId,
        change,
        content: item.content,
        truncated: [],
      };
      const check = cveObservationRecordedPayloadSchema.safeParse(payload);
      if (!check.success) {
        stats.invalid += 1;
        issues.push({
          sourceRecordId: item.externalId,
          message:
            `stored but not published: ${check.error.issues[0]?.message ?? 'invalid event'}`.slice(
              0,
              MAX_ISSUE_LENGTH,
            ),
        });
        continue;
      }
      events.push(
        createDomainEvent({
          eventType: INTELLIGENCE_EVENT_TYPES.cveObserved,
          producer: SERVICE_NAME,
          payload,
          correlationId: state.correlationId,
        }),
      );
    }
    if (writes.length > 0 || unchanged.length > 0) {
      await this.options.repository.applyRecordChanges({
        source,
        runId: run.id,
        observedAt,
        writes,
        unchanged,
        events,
      });
    }
    stats.events += events.length;
    return issues;
  }

  private async persistKevCatalog(
    source: IntelligenceSource,
    batch: Extract<SyncBatch<JsonObject>, { kind: 'kev-catalog' }>,
    state: RunState,
  ): Promise<NewIssue[]> {
    const { stats, run } = state;
    const { repository } = this.options;
    const entries = [...new Map(batch.entries.map((entry) => [entry.cveId, entry])).values()];
    stats.fetched += batch.entries.length;
    stats.unchanged += batch.entries.length - entries.length;
    const stored = await repository.findRecordStates(
      source,
      entries.map((entry) => entry.cveId),
    );
    const active = await repository.findActiveRecordIds(source);
    const present = new Set(entries.map((entry) => entry.cveId));
    const removedIds = active.filter((id) => !present.has(id));
    const allowed = Math.max(10, Math.floor(active.length * this.maxKevRemovalRatio));
    if (removedIds.length > allowed) {
      throw new KevSnapshotRejectedError(removedIds.length, active.length);
    }

    const observedAt = this.now();
    const terms = SOURCE_TERMS[source];
    const catalog = {
      catalogVersion: batch.catalog.catalogVersion,
      dateReleased: batch.catalog.dateReleased?.toISOString() ?? null,
    };
    const writes: RecordWrite[] = [];
    const unchanged: string[] = [];
    const events: DomainEventEnvelope[] = [];
    for (const entry of entries) {
      const content = kevContent(entry);
      const hash = contentHash(content);
      const prior = stored.get(entry.cveId);
      if (prior?.contentHash === hash && prior.removedAt === null) {
        unchanged.push(entry.cveId);
        stats.unchanged += 1;
        continue;
      }
      const added = prior?.removedAt !== null;
      const revision = (prior?.revision ?? 0) + 1;
      writes.push({
        externalId: entry.cveId,
        cveId: entry.cveId,
        sourceUrl: entry.sourceUrl,
        contentHash: hash,
        revision,
        content,
        raw: this.raw(source, entry.raw),
        sourceModifiedAt: batch.catalog.dateReleased,
        change: prior === undefined ? 'created' : 'updated',
      });
      if (prior === undefined) stats.created += 1;
      else stats.updated += 1;
      events.push(
        this.event(
          added ? INTELLIGENCE_EVENT_TYPES.kevAdded : INTELLIGENCE_EVENT_TYPES.kevUpdated,
          kevEntryChangedPayloadSchema,
          {
            source,
            sourceRecordId: entry.cveId,
            sourceUrl: entry.sourceUrl,
            attribution: terms.attribution,
            revision,
            contentHash: hash,
            observedAt: observedAt.toISOString(),
            sourceModifiedAt: catalog.dateReleased,
            runId: run.id,
            cveId: entry.cveId,
            catalog,
            entry: { ...entry.entry, observedAt: observedAt.toISOString() },
            vendorProject: entry.vendorProject,
            product: entry.product,
            shortDescription: entry.shortDescription,
            cweIds: [...entry.cweIds],
          },
          state.correlationId,
        ),
      );
    }
    const removedStates = await repository.findRecordStates(source, removedIds);
    for (const cveId of removedIds) {
      const prior = removedStates.get(cveId);
      if (prior === undefined) continue;
      writes.push({
        externalId: cveId,
        cveId,
        sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        contentHash: prior.contentHash,
        revision: prior.revision + 1,
        content: {},
        raw: null,
        sourceModifiedAt: batch.catalog.dateReleased,
        change: 'removed',
      });
      stats.removed += 1;
      events.push(
        this.event(
          INTELLIGENCE_EVENT_TYPES.kevRemoved,
          kevEntryRemovedPayloadSchema,
          { source, cveId, catalog, observedAt: observedAt.toISOString(), runId: run.id },
          state.correlationId,
        ),
      );
    }
    if (writes.length > 0 || unchanged.length > 0) {
      await repository.applyRecordChanges({
        source,
        runId: run.id,
        observedAt,
        writes,
        unchanged,
        events,
      });
    }
    stats.events += events.length;
    return [];
  }

  private async persistEpss(
    source: IntelligenceSource,
    batch: Extract<SyncBatch<JsonObject>, { kind: 'epss-scores' }>,
    state: RunState,
  ): Promise<NewIssue[]> {
    const { stats, run } = state;
    stats.fetched += batch.scores.length;
    if (batch.scores.length === 0) return [];
    const observedAt = this.now();
    const terms = SOURCE_TERMS[source];
    const result = await this.options.repository.insertEpssScores(
      {
        runId: run.id,
        scoreDate: batch.scoreDate,
        modelVersion: batch.modelVersion,
        observedAt,
        scores: batch.scores,
      },
      (inserted) =>
        chunk(inserted, MAX_EPSS_SCORES_PER_EVENT).map((scores) =>
          this.event(
            INTELLIGENCE_EVENT_TYPES.epssPublished,
            epssScoresPublishedPayloadSchema,
            {
              source,
              scoreDate: batch.scoreDate,
              modelVersion: batch.modelVersion,
              attribution: terms.attribution,
              observedAt: observedAt.toISOString(),
              runId: run.id,
              scores,
            },
            state.correlationId,
          ),
        ),
    );
    stats.created += result.inserted;
    stats.unchanged += batch.scores.length - result.inserted;
    stats.events += result.events;
    return [];
  }
}

export class KevSnapshotRejectedError extends Error {
  /** A broken feed does not fix itself within seconds; the next scheduled run tries again. */
  readonly retryable = false;

  constructor(removals: number, active: number) {
    super(
      `The CISA KEV catalog would remove ${removals} of ${active} stored entries; the snapshot was rejected as incomplete.`,
    );
    this.name = 'KevSnapshotRejectedError';
  }
}

function kevContent(entry: KevItem): JsonObject {
  return {
    entry: entry.entry,
    vendorProject: entry.vendorProject,
    product: entry.product,
    shortDescription: entry.shortDescription,
    cweIds: entry.cweIds,
  };
}
