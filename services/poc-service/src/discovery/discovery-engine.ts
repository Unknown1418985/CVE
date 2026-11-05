import {
  discoveryRunFinishedPayloadSchema,
  EMPTY_DISCOVERY_RUN_STATS,
  POC_EVENT_TYPES,
  repositoryUpdatedPayloadSchema,
  type DiscoveryMode,
  type DiscoveryRunStats,
  type DiscoveryTrigger,
  type DomainEventEnvelope,
  type PocConnector,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { isRetryable, type RequestMeter } from '@cve/source-http';

import { isUnavailable, type GithubConnector } from '../connectors/github/github-connector.js';
import type { MappedRepository, RepositoryMetadata } from '../connectors/github/github-mapping.js';
import { summarizeTree } from '../domain/files.js';
import { nextScanDelayMs } from '../domain/scan-policy.js';
import { pocEvent, SYSTEM_ACTOR } from '../events/poc-events.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import { decimalToNumber, toJson, TX_OPTIONS, writeOutbox } from '../persistence/database.js';
import { recordSnapshot } from './artifact-writer.js';
import { rescoreRepository, type ScoringSettings } from './association-scorer.js';
import {
  markRepositoryUnavailable,
  REPOSITORY_SELECT,
  repositorySnapshot,
  upsertRepository,
} from './repository-writer.js';

export interface DiscoveryRequest {
  readonly connector: PocConnector;
  readonly mode: DiscoveryMode;
  readonly trigger: DiscoveryTrigger;
  readonly cveId?: string | undefined;
  readonly repositoryId?: string | undefined;
  /** `owner/name` of a repository known only from a reference. */
  readonly fullName?: string | undefined;
  readonly requestedBy: string | null;
  readonly correlationId?: string | undefined;
  readonly jobId: string | null;
  readonly attempt: number;
  readonly maxAttempts: number;
}

export type RunOutcome =
  | { readonly status: 'succeeded'; readonly runId: string; readonly stats: DiscoveryRunStats }
  | {
      readonly status: 'failed';
      readonly runId: string;
      readonly error: Error;
      readonly retryable: boolean;
    };

/** Queues repository inspections (BullMQ in production). */
export interface InspectionQueue {
  enqueueInspection(input: {
    repositoryId: string;
    dedupeKey: string;
    correlationId: string | undefined;
  }): Promise<boolean>;
}

export interface DiscoverySettings extends ScoringSettings {
  readonly maxFilesPerArtifact: number;
  readonly nearDuplicateThreshold: number;
  readonly recentWindowMs: number;
  readonly recentInitialLookbackMs: number;
  readonly recentMaxWindows: number;
}

export interface DiscoveryEngineOptions {
  readonly prisma: PrismaClient;
  readonly github: GithubConnector | null;
  readonly inspections: InspectionQueue;
  readonly settings: DiscoverySettings;
  readonly logger: Logger;
  readonly now?: () => Date;
}

/** Thrown for runs that cannot succeed by retrying (disabled connector, unknown repository). */
export class NonRetryableDiscoveryError extends Error {
  readonly retryable = false;
  constructor(message: string) {
    super(message);
    this.name = 'NonRetryableDiscoveryError';
  }
}

/** The newest window of the recent sweep stays open this long (GitHub indexes with a delay). */
const RECENT_SETTLE_MS = 5 * 60_000;
const MIN_RECENT_WINDOW_MS = 60_000;

interface RunState {
  readonly runId: string;
  readonly stats: DiscoveryRunStats & RequestMeter;
  readonly correlationId: string | undefined;
  readonly signal: AbortSignal;
  readonly connector: PocConnector;
}

type MutableStats = { -readonly [K in keyof DiscoveryRunStats]: number } & RequestMeter;

/**
 * Runs discovery jobs. Every network call happens outside database transactions; every write
 * of one repository (metadata, associations, artifacts and their outbox events) is one
 * transaction. Nothing fetched is executed: the connector returns metadata only.
 */
export class DiscoveryEngine {
  private readonly now: () => Date;

  constructor(private readonly options: DiscoveryEngineOptions) {
    this.now = options.now ?? (() => new Date());
  }

  private get logger() {
    return this.options.logger;
  }

  private github(): GithubConnector {
    if (this.options.github === null) {
      throw new NonRetryableDiscoveryError('The github connector is not enabled');
    }
    return this.options.github;
  }

  async run(request: DiscoveryRequest, signal: AbortSignal): Promise<RunOutcome> {
    const stats: MutableStats = { ...EMPTY_DISCOVERY_RUN_STATS, requests: 0 };
    const run = await this.options.prisma.discoveryRun.create({
      data: {
        connector: request.connector,
        mode: request.mode,
        trigger: request.trigger,
        cveId: request.cveId ?? null,
        repositoryId: request.repositoryId ?? null,
        jobId: request.jobId,
        attempt: request.attempt,
        requestedBy: request.requestedBy,
        correlationId: request.correlationId ?? null,
        startedAt: this.now(),
        stats: toJson(stats),
      },
      select: { id: true, startedAt: true },
    });
    const state: RunState = {
      runId: run.id,
      stats,
      correlationId: request.correlationId,
      signal,
      connector: request.connector,
    };
    const log = this.logger.child({
      runId: run.id,
      mode: request.mode,
      connector: request.connector,
    });
    try {
      switch (request.mode) {
        case 'cve':
          if (request.cveId === undefined)
            throw new NonRetryableDiscoveryError('cveId is required');
          await this.discoverCve(request.cveId, state);
          break;
        case 'recent':
          await this.discoverRecent(state);
          break;
        case 'repository':
          await this.discoverRepository(request, state);
          break;
      }
      await this.finish(run, request, 'succeeded', stats, null, false);
      log.info({ stats }, 'discovery run succeeded');
      return { status: 'succeeded', runId: run.id, stats };
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error));
      const retryable = !signal.aborted && isRetryable(failure);
      const willRetry = retryable && request.attempt < request.maxAttempts;
      await this.finish(run, request, 'failed', stats, failure.message, willRetry).catch(
        (finishError: unknown) => {
          log.error({ err: finishError }, 'failed to record the failed discovery run');
        },
      );
      log.warn({ err: failure, stats, willRetry }, 'discovery run failed');
      return { status: 'failed', runId: run.id, error: failure, retryable };
    }
  }

  private async finish(
    run: { id: string; startedAt: Date },
    request: DiscoveryRequest,
    status: 'succeeded' | 'failed',
    stats: MutableStats,
    error: string | null,
    willRetry: boolean,
  ): Promise<void> {
    const finishedAt = this.now();
    const { requests, ...counters } = stats;
    const finalStats: DiscoveryRunStats = { ...counters, requests };
    await this.options.prisma.$transaction(async (tx) => {
      await tx.discoveryRun.update({
        where: { id: run.id },
        data: {
          status,
          finishedAt,
          stats: toJson(finalStats),
          error: error?.slice(0, 2_000) ?? null,
        },
      });
      await writeOutbox(tx, [
        pocEvent(
          status === 'succeeded'
            ? POC_EVENT_TYPES.discoveryRunCompleted
            : POC_EVENT_TYPES.discoveryRunFailed,
          discoveryRunFinishedPayloadSchema,
          {
            runId: run.id,
            connector: request.connector,
            mode: request.mode,
            trigger: request.trigger,
            status,
            cveId: request.cveId ?? null,
            repositoryId: request.repositoryId ?? null,
            startedAt: run.startedAt.toISOString(),
            finishedAt: finishedAt.toISOString(),
            stats: finalStats,
            error: error?.slice(0, 2_000) ?? null,
            willRetry,
          },
          request.correlationId,
        ),
      ]);
    });
  }

  // ---------------------------------------------------------------------------- modes

  private async discoverCve(cveId: string, state: RunState): Promise<void> {
    const github = this.github();
    for await (const page of github.searchCve(cveId, {
      signal: state.signal,
      meter: state.stats,
    })) {
      if (page.incomplete) this.logger.info({ cveId }, 'GitHub reported incomplete search results');
      await this.processPage(page.repositories, state, new Set([cveId]));
    }
    await this.markScanned(cveId);
  }

  /** Records a completed scan of a tracked CVE and schedules the next one. */
  private async markScanned(cveId: string): Promise<void> {
    const tracked = await this.options.prisma.trackedCve.findUnique({ where: { cveId } });
    if (tracked === null) return;
    const now = this.now();
    const delay = nextScanDelayMs(
      {
        inKev: tracked.inKev,
        epssScore: decimalToNumber(tracked.epssScore),
        publishedAt: tracked.publishedAt,
      },
      now,
    );
    await this.options.prisma.trackedCve.update({
      where: { cveId },
      data: {
        lastScannedAt: now,
        scanCount: { increment: 1 },
        nextScanAt: tracked.deletedAt === null ? new Date(now.getTime() + delay) : null,
      },
    });
  }

  private async discoverRecent(state: RunState): Promise<void> {
    const github = this.github();
    const { settings } = this.options;
    const stored = await this.options.prisma.connectorState.findUnique({
      where: { connector: 'github' },
    });
    const cursor = stored?.cursor as { pushedSince?: unknown } | undefined;
    let from =
      typeof cursor?.pushedSince === 'string' && !Number.isNaN(Date.parse(cursor.pushedSince))
        ? new Date(cursor.pushedSince)
        : new Date(this.now().getTime() - settings.recentInitialLookbackMs);
    let windowMs = settings.recentWindowMs;
    for (let windows = 0; windows < settings.recentMaxWindows;) {
      const limit = this.now().getTime() - RECENT_SETTLE_MS;
      if (from.getTime() >= limit) break;
      const to = new Date(Math.min(from.getTime() + windowMs, limit));
      let url: string | null = github.searchUrl(github.recentQuery(from, to), 'updated');
      const first = await github.searchPage(url, { signal: state.signal, meter: state.stats });
      if (first.totalCount > 1_000 && to.getTime() - from.getTime() > MIN_RECENT_WINDOW_MS) {
        // GitHub serves at most 1 000 results per query: narrow the window and try again.
        windowMs = Math.max(MIN_RECENT_WINDOW_MS, Math.floor((to.getTime() - from.getTime()) / 2));
        continue;
      }
      await this.processPage(first.repositories, state, new Set());
      url = first.nextUrl;
      while (url !== null) {
        const page = await github.searchPage(url, { signal: state.signal, meter: state.stats });
        await this.processPage(page.repositories, state, new Set());
        url = page.nextUrl;
      }
      from = to;
      windows += 1;
      windowMs = settings.recentWindowMs;
      await this.options.prisma.connectorState.upsert({
        where: { connector: 'github' },
        create: { connector: 'github', cursor: { pushedSince: from.toISOString() } },
        update: { cursor: { pushedSince: from.toISOString() } },
      });
    }
  }

  private async discoverRepository(request: DiscoveryRequest, state: RunState): Promise<void> {
    const github = this.github();
    const options = { signal: state.signal, meter: state.stats };
    let repositoryId = request.repositoryId;
    if (repositoryId === undefined) {
      const [owner, name, ...rest] = (request.fullName ?? '').split('/');
      if (owner === undefined || name === undefined || rest.length > 0) {
        throw new NonRetryableDiscoveryError('repositoryId or fullName (owner/name) is required');
      }
      let mapped: MappedRepository;
      try {
        mapped = await github.repositoryByName(owner, name, options);
      } catch (error) {
        if (isUnavailable(error)) {
          await this.markReferencesResolved(`${owner}/${name}`.toLowerCase());
          this.logger.info(
            { fullName: request.fullName },
            'referenced repository is not available',
          );
          return;
        }
        throw error;
      }
      if (!mapped.ok) {
        state.stats.invalid += 1;
        this.logger.warn(
          { externalId: mapped.externalId, issue: mapped.issue },
          'repository refused',
        );
        return;
      }
      repositoryId = await this.storeCandidate(mapped.repository, state, new Set());
    }
    await this.inspect(repositoryId, state);
  }

  private async markReferencesResolved(repositoryKey: string): Promise<void> {
    await this.options.prisma.pocReference.updateMany({
      where: { repositoryKey, repositoryId: null },
      data: { resolveQueuedAt: this.now() },
    });
  }

  // ---------------------------------------------------------------------------- candidates

  private async processPage(
    repositories: readonly MappedRepository[],
    state: RunState,
    searched: ReadonlySet<string>,
  ): Promise<void> {
    state.stats.candidates += repositories.length;
    for (const mapped of repositories) {
      if (state.signal.aborted)
        throw state.signal.reason instanceof Error ? state.signal.reason : new Error('aborted');
      if (!mapped.ok) {
        state.stats.invalid += 1;
        this.logger.debug(
          { externalId: mapped.externalId, issue: mapped.issue },
          'search result refused',
        );
        continue;
      }
      await this.storeCandidate(mapped.repository, state, searched);
    }
  }

  /** Stores one validated repository, rescores it and queues an inspection when needed. */
  private async storeCandidate(
    meta: RepositoryMetadata,
    state: RunState,
    searched: ReadonlySet<string>,
  ): Promise<string> {
    const now = this.now();
    const result = await this.options.prisma.$transaction(async (tx) => {
      const upserted = await upsertRepository(tx, meta, {
        connector: state.connector,
        runId: state.runId,
        correlationId: state.correlationId,
        now,
      });
      // Link references that point to this repository by name.
      await tx.pocReference.updateMany({
        where: { repositoryKey: meta.fullName.toLowerCase(), repositoryId: null },
        data: { repositoryId: upserted.repositoryId },
      });
      const scored = await rescoreRepository(
        tx,
        upserted.repositoryId,
        this.options.settings,
        { actor: SYSTEM_ACTOR, correlationId: state.correlationId, now },
        searched,
      );
      await writeOutbox(tx, [...upserted.events, ...scored.events]);
      return { upserted, scored };
    }, TX_OPTIONS);
    const { stats } = state;
    if (result.upserted.outcome === 'created') stats.repositoriesCreated += 1;
    else if (result.upserted.outcome === 'updated') stats.repositoriesUpdated += 1;
    else stats.unchanged += 1;
    stats.associationsCreated += result.scored.created;
    stats.associationsUpdated += result.scored.updated;
    stats.associationsDiscarded += result.scored.discarded;
    if (result.upserted.inspectionNeeded) {
      await this.queueInspection(result.upserted.repositoryId, meta, state);
    }
    return result.upserted.repositoryId;
  }

  private async queueInspection(
    repositoryId: string,
    meta: RepositoryMetadata,
    state: RunState,
  ): Promise<void> {
    try {
      const queued = await this.options.inspections.enqueueInspection({
        repositoryId,
        dedupeKey: String(meta.sourcePushedAt?.getTime() ?? 0),
        correlationId: state.correlationId,
      });
      if (queued) state.stats.inspectionsQueued += 1;
    } catch (error) {
      // `inspection_due_at` is set: the maintenance job queues it again.
      this.logger.error({ err: error, repositoryId }, 'failed to queue a repository inspection');
    }
  }

  // ---------------------------------------------------------------------------- inspection

  /**
   * Refreshes a repository's metadata and records its head commit and file listing. The tree is
   * fetched only for a commit whose tree the repository does not have yet.
   */
  private async inspect(repositoryId: string, state: RunState): Promise<void> {
    const github = this.github();
    const options = { signal: state.signal, meter: state.stats };
    const repo = await this.options.prisma.pocRepository.findUnique({
      where: { id: repositoryId },
      select: { externalId: true, latestCommitSha: true, latestArtifactId: true, status: true },
    });
    if (repo === null)
      throw new NonRetryableDiscoveryError(`Repository ${repositoryId} does not exist`);

    let mapped: MappedRepository;
    try {
      mapped = await github.repository(repo.externalId, options);
    } catch (error) {
      if (!isUnavailable(error)) throw error;
      const now = this.now();
      await this.options.prisma.$transaction(async (tx) => {
        await writeOutbox(
          tx,
          await markRepositoryUnavailable(tx, repositoryId, {
            runId: state.runId,
            correlationId: state.correlationId,
            now,
          }),
        );
      });
      state.stats.repositoriesUpdated += 1;
      return;
    }
    if (!mapped.ok) {
      state.stats.invalid += 1;
      throw new NonRetryableDiscoveryError(
        `GitHub returned an unusable repository: ${mapped.issue}`,
      );
    }
    const meta = mapped.repository;
    const head =
      meta.defaultBranch === null
        ? ({ kind: 'empty' } as const)
        : await github.headCommit(meta.fullName, meta.defaultBranch, options);

    let summary = null;
    if (head.kind === 'commit') {
      const known = await this.options.prisma.pocArtifact.findUnique({
        where: { repositoryId_treeSha: { repositoryId, treeSha: head.treeSha } },
        select: { id: true },
      });
      if (known === null) {
        const tree = await github.tree(meta.fullName, head.treeSha, options);
        summary = summarizeTree(tree.entries, {
          truncated: tree.truncated,
          maxFiles: this.options.settings.maxFilesPerArtifact,
        });
      }
    }

    const now = this.now();
    await this.options.prisma.$transaction(async (tx) => {
      const events: DomainEventEnvelope[] = [];
      const upserted = await upsertRepository(tx, meta, {
        connector: state.connector,
        runId: state.runId,
        correlationId: state.correlationId,
        now,
      });
      events.push(...upserted.events);
      const inspected = {
        lastInspectedAt: now,
        inspectedPushedAt: meta.sourcePushedAt,
        inspectionDueAt: null,
      };
      if (head.kind === 'empty') {
        await tx.pocRepository.update({
          where: { id: repositoryId },
          data: { ...inspected, isEmpty: true },
        });
      } else if (head.sha === repo.latestCommitSha && repo.latestArtifactId !== null) {
        await tx.pocRepository.update({ where: { id: repositoryId }, data: inspected });
      } else {
        const recorded = await recordSnapshot(tx, {
          repositoryId,
          repositoryUrl: meta.url,
          repositoryFullName: meta.fullName,
          commitSha: head.sha,
          treeSha: head.treeSha,
          committedAt: head.committedAt,
          summary,
          nearDuplicateThreshold: this.options.settings.nearDuplicateThreshold,
          correlationId: state.correlationId,
          now,
        });
        events.push(...recorded.events);
        if (recorded.created) state.stats.artifactsCreated += 1;
        if (recorded.duplicate !== null) state.stats.duplicatesDetected += 1;
        const row = await tx.pocRepository.update({
          where: { id: repositoryId },
          data: {
            ...inspected,
            isEmpty: false,
            latestCommitSha: head.sha,
            latestArtifactId: recorded.artifactId,
            version: { increment: 1 },
          },
          select: REPOSITORY_SELECT,
        });
        events.push(
          pocEvent(
            POC_EVENT_TYPES.repositoryUpdated,
            repositoryUpdatedPayloadSchema,
            { ...repositorySnapshot(row), changedFields: ['commit'], runId: state.runId },
            state.correlationId,
          ),
        );
      }
      const scored = await rescoreRepository(tx, repositoryId, this.options.settings, {
        actor: SYSTEM_ACTOR,
        correlationId: state.correlationId,
        now,
      });
      state.stats.associationsCreated += scored.created;
      state.stats.associationsUpdated += scored.updated;
      state.stats.associationsDiscarded += scored.discarded;
      events.push(...scored.events);
      await writeOutbox(tx, events);
    }, TX_OPTIONS);
  }
}
