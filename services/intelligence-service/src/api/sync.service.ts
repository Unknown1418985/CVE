import { ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';

import type {
  IntelligenceSource,
  ListSyncRunsQuery,
  SourceStatus,
  SyncRun,
  SyncRunDetail,
  TriggerSyncResponse,
} from '@cve/contracts';

import {
  INTELLIGENCE_REPOSITORY,
  MAX_STORED_ISSUES_PER_RUN,
  type IntelligenceRepository,
  type SyncRunRecord,
  type SyncStateRecord,
} from '../persistence/ports.js';
import { SOURCE_TERMS } from '../sources/catalog.js';
import type { RegisteredSource } from '../sources/registry.js';
import type { SyncJobQueue } from '../sync/sync-jobs.js';

export const SOURCE_REGISTRY = Symbol('SOURCE_REGISTRY');
export const SYNC_JOB_QUEUE = Symbol('SYNC_JOB_QUEUE');
export const SYNC_SETTINGS = Symbol('SYNC_SETTINGS');

export interface SyncSettings {
  readonly storeRawPayloads: boolean;
}

export interface RequestContext {
  readonly requestedBy: string;
  readonly correlationId: string | undefined;
}

export function toSyncRun(run: SyncRunRecord): SyncRun {
  return {
    id: run.id,
    source: run.source,
    trigger: run.trigger,
    status: run.status,
    jobId: run.jobId,
    attempt: run.attempt,
    requestedBy: run.requestedBy,
    resumedFromRunId: run.resumedFromRunId,
    startedAt: run.startedAt.toISOString(),
    heartbeatAt: run.heartbeatAt.toISOString(),
    finishedAt: run.finishedAt?.toISOString() ?? null,
    cursorBefore: run.cursorBefore,
    cursorAfter: run.cursorAfter,
    checkpoint: run.checkpoint,
    stats: run.stats,
    error: run.error,
    issueCount: run.issueCount,
  };
}

@Injectable()
export class SyncService {
  constructor(
    @Inject(INTELLIGENCE_REPOSITORY) private readonly repository: IntelligenceRepository,
    @Inject(SOURCE_REGISTRY)
    private readonly registry: ReadonlyMap<IntelligenceSource, RegisteredSource>,
    @Inject(SYNC_JOB_QUEUE) private readonly jobs: SyncJobQueue,
    @Inject(SYNC_SETTINGS) private readonly settings: SyncSettings,
  ) {}

  private entry(source: IntelligenceSource): RegisteredSource {
    const entry = this.registry.get(source);
    if (entry === undefined) throw new NotFoundException(`Unknown source ${source}`);
    return entry;
  }

  private status(
    source: IntelligenceSource,
    state: SyncStateRecord | undefined,
    now: Date,
  ): SourceStatus {
    const entry = this.entry(source);
    const description = entry.adapter.describe();
    const terms = SOURCE_TERMS[source];
    return {
      source,
      name: terms.name,
      description: terms.description,
      enabled: entry.enabled,
      schedule: entry.enabled ? entry.schedule : null,
      baseUrl: description.baseUrl,
      authentication: description.authentication,
      rateLimit: description.rateLimit,
      license: terms.license,
      termsUrl: terms.termsUrl,
      attribution: terms.attribution,
      storesRawPayloads: this.settings.storeRawPayloads && terms.rawRetentionPermitted,
      state: {
        running:
          state?.leaseOwner !== null &&
          state?.leaseOwner !== undefined &&
          state.leaseExpiresAt !== null &&
          state.leaseExpiresAt > now,
        lastRunAt: state?.lastRunAt?.toISOString() ?? null,
        lastRunStatus: state?.lastRunStatus ?? null,
        lastSuccessAt: state?.lastSuccessAt?.toISOString() ?? null,
        consecutiveFailures: state?.consecutiveFailures ?? 0,
        cursor: state?.cursor ?? null,
      },
    };
  }

  async listSources(): Promise<SourceStatus[]> {
    const states = new Map(
      (await this.repository.listSyncStates()).map((state) => [state.source, state]),
    );
    const now = new Date();
    return [...this.registry.keys()].map((source) => this.status(source, states.get(source), now));
  }

  async getSource(source: IntelligenceSource): Promise<SourceStatus> {
    this.entry(source);
    return this.status(
      source,
      (await this.repository.getSyncState(source)) ?? undefined,
      new Date(),
    );
  }

  async trigger(
    source: IntelligenceSource,
    options: { fresh: boolean; idempotencyKey: string | undefined },
    context: RequestContext,
  ): Promise<TriggerSyncResponse> {
    if (!this.entry(source).enabled) {
      throw new ConflictException(`The ${source} source is disabled`);
    }
    const result = await this.jobs.enqueue(
      {
        source,
        trigger: 'manual',
        requestedBy: context.requestedBy,
        fresh: options.fresh,
        ...(context.correlationId === undefined ? {} : { correlationId: context.correlationId }),
      },
      options.idempotencyKey === undefined
        ? undefined
        : `manual.${source}.${options.idempotencyKey}`,
    );
    return { source, ...result };
  }

  async listRuns(query: ListSyncRunsQuery): Promise<{ items: SyncRun[]; total: number }> {
    const { items, total } = await this.repository.listRuns(query);
    return { items: items.map(toSyncRun), total };
  }

  async getRun(runId: string): Promise<SyncRunDetail> {
    const run = await this.repository.findRun(runId);
    if (run === null) throw new NotFoundException('Synchronisation run not found');
    const issues = await this.repository.listRunIssues(runId, MAX_STORED_ISSUES_PER_RUN);
    return {
      ...toSyncRun(run),
      issues: issues.map((issue) => ({
        sourceRecordId: issue.sourceRecordId,
        message: issue.message,
        createdAt: issue.createdAt.toISOString(),
      })),
    };
  }

  /** Re-queues the source so the next run resumes the failed run from its checkpoint. */
  async retry(runId: string, context: RequestContext): Promise<TriggerSyncResponse> {
    const run = await this.repository.findRun(runId);
    if (run === null) throw new NotFoundException('Synchronisation run not found');
    if (run.status !== 'failed' && run.status !== 'abandoned') {
      throw new ConflictException(
        `Only failed or abandoned runs can be retried (run is ${run.status})`,
      );
    }
    const latest = await this.repository.latestRun(run.source);
    if (latest?.id !== run.id) {
      throw new ConflictException('A later run of this source exists; retry the latest run');
    }
    if (!this.entry(run.source).enabled) {
      throw new ConflictException(`The ${run.source} source is disabled`);
    }
    const result = await this.jobs.enqueue(
      {
        source: run.source,
        trigger: 'manual',
        requestedBy: context.requestedBy,
        fresh: false,
        ...(context.correlationId === undefined ? {} : { correlationId: context.correlationId }),
      },
      `retry.${run.id}`,
    );
    return { source: run.source, ...result };
  }
}
