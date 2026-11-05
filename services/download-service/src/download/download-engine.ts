import { randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';

import {
  DOWNLOAD_EVENT_TYPES,
  downloadArtifactStoredPayloadSchema,
  downloadRequestCompletedPayloadSchema,
  downloadRequestFailedPayloadSchema,
  OBJECT_STORAGE_BUCKETS,
  type DomainEventEnvelope,
  type DownloadErrorCode,
  type DownloadSource,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';

import { detectFileType, FILE_TYPE_MIME, riskIndicators } from '../domain/file-type.js';
import {
  filenameFromContentDisposition,
  filenameFromUrl,
  quarantineKey,
} from '../domain/naming.js';
import type { SourcePolicy } from '../domain/sources.js';
import { downloadEvent, systemContext } from '../events/download-events.js';
import type { DownloadRequest, PrismaClient } from '../generated/prisma/client.js';
import {
  isUniqueViolation,
  toJson,
  TX_OPTIONS,
  writeOutbox,
  type Tx,
} from '../persistence/database.js';
import type { ArtifactObjectStore } from '../storage/object-store.js';
import { DownloadError } from './errors.js';
import { refreshVerification, deleteReleasedCopies, type LifecycleChange } from './lifecycle.js';
import type { FetchResult, SafeFetcher } from './safe-fetcher.js';
import { fetchPolicyFor } from './source-catalog.js';

export interface ScanQueue {
  enqueueScan(artifactId: string, reason: string): Promise<boolean>;
}

export interface DownloadEngineOptions {
  readonly prisma: PrismaClient;
  readonly fetcher: SafeFetcher;
  readonly store: ArtifactObjectStore;
  readonly sources: readonly SourcePolicy[];
  readonly scans: ScanQueue;
  readonly stagingDir: string;
  readonly totalTimeoutMs: number;
  readonly logger: Logger;
}

export interface DownloadJobContext {
  readonly jobId: string;
  /** BullMQ attempt of this job (1 for the first). */
  readonly attempt: number;
  readonly maxAttempts: number;
}

export type DownloadOutcome =
  | { readonly status: 'skipped'; readonly reason: string }
  | { readonly status: 'stored' | 'duplicate'; readonly artifactId: string }
  | {
      readonly status: 'failed' | 'rejected' | 'retry';
      readonly error: DownloadError;
    };

const truncate = (value: string, max = 2_000) => (value.length > max ? value.slice(0, max) : value);

/**
 * Runs one download request: claims it, fetches the canonical URL through the SSRF-safe
 * fetcher into a private staging file, validates the detected file type, detects duplicates by
 * SHA-256, uploads new content to the quarantine bucket under a generated key and records the
 * attempt, the artifact and its provenance with their outbox events in one transaction.
 *
 * A stored artifact is quarantined and unscanned; a successful download never makes it
 * verified or released.
 */
export class DownloadEngine {
  constructor(private readonly options: DownloadEngineOptions) {}

  private policy(source: string): SourcePolicy | undefined {
    return this.options.sources.find((policy) => policy.source === source);
  }

  /** Marks the request as downloading; null when another worker has it or it is finished. */
  private async claim(
    requestId: string,
    context: DownloadJobContext,
  ): Promise<DownloadRequest | null> {
    const leaseUntil = new Date(Date.now() + this.options.totalTimeoutMs + 60_000);
    const [claimed] = await this.options.prisma.$queryRaw<{ id: string }[]>`
      UPDATE "download_requests"
         SET "status" = 'downloading', "attempts" = "attempts" + 1, "lease_until" = ${leaseUntil},
             "job_id" = ${context.jobId}, "version" = "version" + 1, "updated_at" = now()
       WHERE "id" = ${requestId}::uuid
         AND ("status" = 'pending'
              OR ("status" = 'downloading' AND "lease_until" < now()))
   RETURNING "id"`;
    if (claimed === undefined) return null;
    return this.options.prisma.downloadRequest.findUniqueOrThrow({ where: { id: requestId } });
  }

  async run(
    requestId: string,
    context: DownloadJobContext,
    signal: AbortSignal,
  ): Promise<DownloadOutcome> {
    const { prisma, logger } = this.options;
    const request = await this.claim(requestId, context);
    if (request === null) {
      return {
        status: 'skipped',
        reason: 'the request is not pending (finished, cancelled or running elsewhere)',
      };
    }
    const attempt = await prisma.downloadAttempt.create({
      data: { requestId, attempt: request.attempts, jobId: context.jobId, hops: [] },
    });
    const log = logger.child({ requestId, attempt: request.attempts, source: request.source });
    const started = Date.now();
    const policy = this.policy(request.source);
    await mkdir(this.options.stagingDir, { recursive: true, mode: 0o700 });
    const staging = join(this.options.stagingDir, `${randomUUID()}.part`);
    try {
      if (!policy?.enabled) {
        throw new DownloadError(
          'source-disabled',
          `The source ${request.source} is not enabled`,
          false,
        );
      }
      const result = await this.options.fetcher.fetchToFile(
        request.sourceUrl,
        fetchPolicyFor(policy),
        staging,
        signal,
      );
      const detected = detectFileType(result.head, result.bytes);
      if (!policy.allowedFileTypes.includes(detected)) {
        throw new DownloadError(
          'file-type-not-allowed',
          `The content is ${detected}; ${request.source} only accepts ${policy.allowedFileTypes.join(', ')}`,
          false,
          { hops: result.hops, httpStatus: result.httpStatus, bytesReceived: result.bytes },
        );
      }
      const outcome = await this.store(
        request,
        attempt.id,
        result,
        detected,
        staging,
        started,
        log,
      );
      log.info(
        { status: outcome.status, artifactId: outcome.artifactId, bytes: result.bytes },
        'download finished',
      );
      return outcome;
    } catch (error) {
      const failure =
        error instanceof DownloadError
          ? error
          : new DownloadError(
              'storage-failure',
              `Storing the download failed: ${String(error instanceof Error ? error.message : error)}`,
              true,
              {},
              { cause: error },
            );
      const willRetry = failure.retryable && context.attempt < context.maxAttempts;
      await this.recordFailure(request, attempt.id, failure, willRetry, started);
      log.warn({ err: failure, code: failure.code, willRetry }, 'download attempt failed');
      if (willRetry) return { status: 'retry', error: failure };
      return { status: failure.outcome === 'rejected' ? 'rejected' : 'failed', error: failure };
    } finally {
      await rm(staging, { force: true });
    }
  }

  private async store(
    request: DownloadRequest,
    attemptId: string,
    result: FetchResult,
    detected: ReturnType<typeof detectFileType>,
    staging: string,
    started: number,
    log: Logger,
  ): Promise<{ status: 'stored' | 'duplicate'; artifactId: string }> {
    const { prisma, store } = this.options;
    const now = new Date();
    const existing = await prisma.storedArtifact.findUnique({ where: { sha256: result.sha256 } });
    if (existing !== null) {
      return this.recordDuplicate(request, attemptId, result, existing.id, started, now);
    }
    const artifactId = randomUUID();
    const key = quarantineKey(artifactId, now);
    // Network I/O happens outside the transaction; the database row only exists once the
    // object is stored and its checksum verified by the object store.
    await store.putFile({
      bucket: OBJECT_STORAGE_BUCKETS.pocQuarantine,
      key,
      path: staging,
      sizeBytes: result.bytes,
      sha256: result.sha256,
      metadata: { 'artifact-id': artifactId, 'request-id': request.id, source: request.source },
    });
    const declaredContentType = result.declaredContentType?.slice(0, 255) ?? null;
    const indicators = riskIndicators(detected, declaredContentType);
    const originalFilename =
      filenameFromContentDisposition(result.contentDisposition) ?? filenameFromUrl(result.finalUrl);
    try {
      await prisma.$transaction(async (tx) => {
        await tx.storedArtifact.create({
          data: {
            id: artifactId,
            sha256: result.sha256,
            sizeBytes: BigInt(result.bytes),
            mimeType: FILE_TYPE_MIME[detected],
            detectedType: detected,
            declaredContentType,
            originalFilename,
            storageBucket: OBJECT_STORAGE_BUCKETS.pocQuarantine,
            storageKey: key,
            source: request.source,
            sourceUrl: request.sourceUrl,
            sourceRepository: request.sourceRepository,
            cveIds: request.cveIds,
            riskIndicators: indicators,
            lifecycleStatus: 'quarantined',
            scanStatus: 'pending',
            discoveredAt: request.discoveredAt,
            downloadedAt: now,
          },
        });
        await tx.artifactLifecycleEvent.create({
          data: {
            artifactId,
            fromStatus: null,
            toStatus: 'quarantined',
            reason: 'Downloaded; untrusted until scanned and reviewed',
            actorId: 'download-service',
            correlationId: request.correlationId,
          },
        });
        // A new artifact is quarantined: linking it can never revoke a release.
        await this.linkSource(tx, request, artifactId, result, now);
        await this.finishRequest(
          tx,
          request,
          attemptId,
          result,
          'stored',
          artifactId,
          started,
          now,
        );
        await writeOutbox(tx, [
          downloadEvent(
            DOWNLOAD_EVENT_TYPES.artifactStored,
            downloadArtifactStoredPayloadSchema,
            {
              artifactId,
              requestId: request.id,
              sha256: result.sha256,
              sizeBytes: result.bytes,
              detectedType: detected,
              riskIndicators: indicators,
              source: request.source as DownloadSource,
              sourceUrl: request.sourceUrl,
              pocArtifactId: request.pocArtifactId,
              cveIds: request.cveIds,
              lifecycleStatus: 'quarantined',
            },
            request.correlationId ?? undefined,
          ),
          this.completedEvent(request, 'stored', artifactId, result),
        ]);
      }, TX_OPTIONS);
    } catch (error) {
      // Another worker stored the same content first: keep its artifact, drop this object.
      if (!isUniqueViolation(error)) {
        await this.deleteOrphan(key, log);
        throw error;
      }
      await this.deleteOrphan(key, log);
      const winner = await prisma.storedArtifact.findUniqueOrThrow({
        where: { sha256: result.sha256 },
      });
      return this.recordDuplicate(request, attemptId, result, winner.id, started, now);
    }
    await this.options.scans.enqueueScan(artifactId, 'downloaded').catch((error: unknown) => {
      // The scheduler re-queues unscanned artifacts; a Redis outage only delays the scan.
      log.warn({ err: error, artifactId }, 'failed to queue the scan; the scheduler will retry');
    });
    return { status: 'stored', artifactId };
  }

  private async deleteOrphan(key: string, log: Logger): Promise<void> {
    try {
      await this.options.store.delete(OBJECT_STORAGE_BUCKETS.pocQuarantine, key);
    } catch (error) {
      log.error({ err: error, key }, 'failed to delete an orphaned quarantine object');
    }
  }

  private async recordDuplicate(
    request: DownloadRequest,
    attemptId: string,
    result: FetchResult,
    artifactId: string,
    started: number,
    now: Date,
  ): Promise<{ status: 'duplicate'; artifactId: string }> {
    const change = await this.options.prisma.$transaction(async (tx) => {
      const artifact = await tx.storedArtifact.findUniqueOrThrow({ where: { id: artifactId } });
      const cveIds = [...new Set([...artifact.cveIds, ...request.cveIds])].sort();
      if (cveIds.length !== artifact.cveIds.length) {
        await tx.storedArtifact.update({
          where: { id: artifactId },
          data: { cveIds, version: { increment: 1 } },
        });
      }
      const linked = await this.linkSource(tx, request, artifactId, result, now);
      await this.finishRequest(
        tx,
        request,
        attemptId,
        result,
        'duplicate',
        artifactId,
        started,
        now,
      );
      await writeOutbox(tx, [this.completedEvent(request, 'duplicate', artifactId, result)]);
      return linked;
    }, TX_OPTIONS);
    await deleteReleasedCopies(
      this.options.store,
      this.options.prisma,
      [change?.releasedKeyToDelete ?? null],
      this.options.logger,
    );
    return { status: 'duplicate', artifactId };
  }

  /** Provenance row; a new PoC link can change the combined verification. */
  private async linkSource(
    tx: Tx,
    request: DownloadRequest,
    artifactId: string,
    result: FetchResult,
    now: Date,
  ): Promise<LifecycleChange | null> {
    await tx.artifactSource.create({
      data: {
        artifactId,
        requestId: request.id,
        source: request.source,
        sourceUrl: request.sourceUrl,
        finalUrl: result.finalUrl,
        sourceRepository: request.sourceRepository,
        pocArtifactId: request.pocArtifactId,
        commitSha: request.commitSha,
        cveIds: request.cveIds,
        discoveredAt: request.discoveredAt,
        downloadedAt: now,
      },
    });
    if (request.pocArtifactId === null) return null;
    const artifact = await tx.storedArtifact.findUniqueOrThrow({ where: { id: artifactId } });
    return refreshVerification(tx, artifact, systemContext(request.correlationId ?? undefined));
  }

  private async finishRequest(
    tx: Tx,
    request: DownloadRequest,
    attemptId: string,
    result: FetchResult,
    status: 'stored' | 'duplicate',
    artifactId: string,
    started: number,
    now: Date,
  ): Promise<void> {
    await tx.downloadAttempt.update({
      where: { id: attemptId },
      data: {
        outcome: 'succeeded',
        httpStatus: result.httpStatus,
        hops: toJson(result.hops),
        finalUrl: result.finalUrl,
        declaredContentType: result.declaredContentType?.slice(0, 255) ?? null,
        declaredLength: result.declaredLength === null ? null : BigInt(result.declaredLength),
        bytesReceived: BigInt(result.bytes),
        sha256: result.sha256,
        finishedAt: now,
        durationMs: Date.now() - started,
      },
    });
    await tx.downloadRequest.update({
      where: { id: request.id },
      data: {
        status,
        artifactId,
        errorCode: null,
        error: null,
        leaseUntil: null,
        finishedAt: now,
        version: { increment: 1 },
      },
    });
  }

  private completedEvent(
    request: DownloadRequest,
    status: 'stored' | 'duplicate',
    artifactId: string,
    result: FetchResult,
  ): DomainEventEnvelope {
    return downloadEvent(
      DOWNLOAD_EVENT_TYPES.requestCompleted,
      downloadRequestCompletedPayloadSchema,
      {
        requestId: request.id,
        source: request.source as DownloadSource,
        sourceUrl: request.sourceUrl,
        trigger: request.trigger as 'event' | 'manual',
        status,
        artifactId,
        sha256: result.sha256,
        sizeBytes: result.bytes,
        pocArtifactId: request.pocArtifactId,
        cveIds: request.cveIds,
        attempt: request.attempts,
      },
      request.correlationId ?? undefined,
    );
  }

  private async recordFailure(
    request: DownloadRequest,
    attemptId: string,
    failure: DownloadError,
    willRetry: boolean,
    started: number,
  ): Promise<void> {
    const now = new Date();
    const status = willRetry ? 'pending' : failure.outcome;
    const code: DownloadErrorCode = failure.code;
    await this.options.prisma.$transaction(async (tx) => {
      await tx.downloadAttempt.update({
        where: { id: attemptId },
        data: {
          outcome: failure.outcome,
          errorCode: code,
          error: truncate(failure.message),
          retryable: failure.retryable,
          httpStatus: failure.httpStatus,
          hops: toJson(failure.hops),
          finalUrl: failure.hops.at(-1)?.url ?? null,
          bytesReceived: BigInt(failure.bytesReceived),
          finishedAt: now,
          durationMs: Date.now() - started,
        },
      });
      await tx.downloadRequest.update({
        where: { id: request.id },
        data: {
          status,
          errorCode: code,
          error: truncate(failure.message),
          leaseUntil: null,
          ...(willRetry ? {} : { finishedAt: now, queuedAt: null }),
          version: { increment: 1 },
        },
      });
      await writeOutbox(tx, [
        downloadEvent(
          DOWNLOAD_EVENT_TYPES.requestFailed,
          downloadRequestFailedPayloadSchema,
          {
            requestId: request.id,
            source: request.source as DownloadSource,
            sourceUrl: request.sourceUrl,
            trigger: request.trigger as 'event' | 'manual',
            status,
            errorCode: code,
            error: truncate(failure.message),
            pocArtifactId: request.pocArtifactId,
            attempt: request.attempts,
            willRetry,
          },
          request.correlationId ?? undefined,
        ),
      ]);
    }, TX_OPTIONS);
  }
}
