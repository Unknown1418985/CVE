import type { Readable } from 'node:stream';

import {
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
  UnprocessableEntityException,
} from '@nestjs/common';

import {
  OBJECT_STORAGE_BUCKETS,
  type ChangeLifecycleRequest,
  type CreateDownloadRequest,
  type CreateDownloadResponse,
  type DownloadArtifact,
  type DownloadRequest,
  type Permission,
  type RescanRequest,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';

import { APP_LOGGER } from '../common/lifecycle.js';
import { checkPrecondition, type Precondition } from '../common/http.js';
import type { ActorContext } from '../common/request-context.js';
import { checkLifecycleChange } from '../domain/artifact-rules.js';
import { releasedKey } from '../domain/naming.js';
import { githubArchiveTarget, resolveUserUrl, type DownloadTarget } from '../domain/sources.js';
import {
  changeLifecycle,
  deleteReleasedCopies,
  linkedPocArtifacts,
  lockArtifact,
} from '../download/lifecycle.js';
import { planRequest } from '../download/requests.js';
import type { PrismaClient, StoredArtifact } from '../generated/prisma/client.js';
import { isUniqueViolation, PRISMA, TX_OPTIONS } from '../persistence/database.js';
import { SCAN_STATUS_TO_API, VERIFICATION_TO_API } from '../persistence/enums.js';
import { DownloadQueryService } from './download-query.service.js';
import { toArtifact, toRequest } from './mappers.js';
import {
  DOWNLOAD_JOBS,
  DOWNLOAD_SETTINGS,
  OBJECT_STORE,
  SOURCE_POLICIES,
  type ArtifactObjectStore,
  type DownloadJobQueue,
  type DownloadSettings,
  type SourcePolicy,
} from './tokens.js';

const actorName = (context: ActorContext) => context.actor.username ?? context.actor.id;

const stateOf = (row: StoredArtifact) => ({
  lifecycleStatus: row.lifecycleStatus,
  scanStatus: SCAN_STATUS_TO_API[row.scanStatus],
  verificationStatus: VERIFICATION_TO_API[row.verificationStatus],
});

@Injectable()
export class DownloadCommandService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(DOWNLOAD_JOBS) private readonly jobs: DownloadJobQueue | null,
    @Inject(SOURCE_POLICIES) private readonly sources: readonly SourcePolicy[],
    @Inject(OBJECT_STORE) private readonly store: ArtifactObjectStore,
    @Inject(DOWNLOAD_SETTINGS) private readonly settings: DownloadSettings,
    @Inject(APP_LOGGER) private readonly logger: Logger,
    private readonly queries: DownloadQueryService,
  ) {}

  private async target(input: CreateDownloadRequest): Promise<{
    target: DownloadTarget;
    pocArtifactId: string | null;
    pocRepositoryId: string | null;
    cveIds: string[];
  }> {
    if (input.url !== undefined) {
      const target = resolveUserUrl(this.sources, input.url);
      if (target === null) {
        throw new UnprocessableEntityException({
          message: 'The URL does not belong to an enabled download source',
          details: [
            {
              path: 'url',
              message:
                'use an https URL of an enabled source (GitHub archives must name a full commit SHA)',
            },
          ],
        });
      }
      return { target, pocArtifactId: null, pocRepositoryId: null, cveIds: [] };
    }
    const pocArtifactId = input.pocArtifactId ?? '';
    const state = await this.prisma.pocArtifactState.findUnique({ where: { pocArtifactId } });
    if (state === null)
      throw new NotFoundException('PoC artifact not known to the Download Service');
    const policy = this.sources.find((candidate) => candidate.source === 'github-archive');
    if (!policy?.enabled) {
      throw new UnprocessableEntityException({
        message: 'The github-archive source is not enabled',
      });
    }
    const target =
      state.repositoryFullName === null
        ? null
        : githubArchiveTarget(policy, state.repositoryFullName, state.commitSha);
    if (target === null) {
      throw new UnprocessableEntityException({
        message: 'The PoC artifact has no downloadable repository',
      });
    }
    return { target, pocArtifactId, pocRepositoryId: state.repositoryId, cveIds: state.cveIds };
  }

  async createRequest(
    context: ActorContext,
    input: CreateDownloadRequest,
  ): Promise<CreateDownloadResponse> {
    const resolved = await this.target(input);
    const now = new Date();
    const plan = () =>
      this.prisma.$transaction(
        (tx) =>
          planRequest(tx, {
            target: resolved.target,
            trigger: 'manual',
            cveIds: [...resolved.cveIds, ...input.cveIds],
            pocArtifactId: resolved.pocArtifactId,
            pocRepositoryId: resolved.pocRepositoryId,
            priority: input.priority,
            scheduledFor: input.scheduledFor ?? now,
            maxAttempts: this.settings.maxAttempts,
            requestedBy: actorName(context),
            reason: input.reason,
            correlationId: context.correlationId,
            discoveredAt: now,
          }),
        TX_OPTIONS,
      );
    let planned;
    try {
      planned = await plan();
    } catch (error) {
      // A concurrent request for the same URL won the insert: return that one.
      if (!isUniqueViolation(error)) throw error;
      planned = await plan();
    }
    if (planned.created) await this.queue(planned.request.id);
    return { request: toRequest(planned.request), created: planned.created };
  }

  private async queue(requestId: string): Promise<void> {
    if (this.jobs === null) return;
    try {
      await this.jobs.queueRequest(requestId);
    } catch (error) {
      this.logger.warn(
        { err: error, requestId },
        'failed to queue a download; the scheduler will retry',
      );
    }
  }

  /** Retries a failed, rejected or cancelled request from scratch. */
  async retryRequest(
    context: ActorContext,
    id: string,
    precondition: Precondition,
  ): Promise<DownloadRequest> {
    const request = await this.prisma.$transaction(async (tx) => {
      const current = await tx.downloadRequest.findUnique({ where: { id } });
      if (current === null) throw new NotFoundException('Download request not found');
      checkPrecondition(precondition, current.version);
      if (!['failed', 'rejected', 'cancelled'].includes(current.status)) {
        throw new ConflictException({
          message: `A ${current.status} request cannot be retried`,
          details: [
            {
              path: 'status',
              message: 'only failed, rejected or cancelled requests can be retried',
            },
          ],
        });
      }
      return tx.downloadRequest.update({
        where: { id },
        data: {
          status: 'pending',
          scheduledFor: new Date(),
          queuedAt: null,
          jobId: null,
          errorCode: null,
          error: null,
          finishedAt: null,
          requestedBy: actorName(context),
          version: { increment: 1 },
        },
      });
    }, TX_OPTIONS);
    await this.queue(id);
    return toRequest(request);
  }

  async cancelRequest(
    context: ActorContext,
    id: string,
    precondition: Precondition,
  ): Promise<DownloadRequest> {
    return this.prisma.$transaction(async (tx) => {
      const current = await tx.downloadRequest.findUnique({ where: { id } });
      if (current === null) throw new NotFoundException('Download request not found');
      checkPrecondition(precondition, current.version);
      if (current.status !== 'pending') {
        throw new ConflictException({
          message: `A ${current.status} request cannot be cancelled`,
          details: [{ path: 'status', message: 'only pending requests can be cancelled' }],
        });
      }
      const updated = await tx.downloadRequest.update({
        where: { id },
        data: {
          status: 'cancelled',
          finishedAt: new Date(),
          error: `Cancelled by ${actorName(context)}`,
          version: { increment: 1 },
        },
      });
      return toRequest(updated);
    }, TX_OPTIONS);
  }

  async rescan(id: string, input: RescanRequest): Promise<{ queued: boolean }> {
    const artifact = await this.prisma.storedArtifact.findUnique({ where: { id } });
    if (artifact === null) throw new NotFoundException('Artifact not found');
    if (this.jobs === null)
      throw new ServiceUnavailableException('Scanning is not available on this replica');
    return { queued: await this.jobs.enqueueScan(id, `manual: ${input.reason}`.slice(0, 200)) };
  }

  private refuse(message: string): ConflictException {
    return new ConflictException({ message, details: [{ path: 'status', message }] });
  }

  /**
   * Releases, rejects or re-quarantines an artifact. Releasing copies the object into the
   * released bucket first (outside the transaction), then re-checks the artifact under a lock:
   * if anything changed meanwhile, the copy is deleted and the release refused.
   */
  async changeLifecycle(
    context: ActorContext,
    id: string,
    input: ChangeLifecycleRequest,
    precondition: Precondition,
  ): Promise<DownloadArtifact> {
    const current = await this.prisma.storedArtifact.findUnique({ where: { id } });
    if (current === null) throw new NotFoundException('Artifact not found');
    checkPrecondition(precondition, current.version);
    const refusal = checkLifecycleChange(stateOf(current), input.status);
    if (refusal !== null) throw this.refuse(refusal);

    let copiedKey: string | null = null;
    if (input.status === 'released') {
      copiedKey = releasedKey(id);
      await this.store.copy({
        fromBucket: current.storageBucket,
        fromKey: current.storageKey,
        toBucket: OBJECT_STORAGE_BUCKETS.pocArtifacts,
        toKey: copiedKey,
      });
    }
    try {
      const change = await this.prisma.$transaction(async (tx) => {
        const locked = await lockArtifact(tx, id);
        if (locked === null) throw new NotFoundException('Artifact not found');
        if (locked.version !== current.version) {
          throw this.refuse('The artifact changed while the request was processed; try again');
        }
        const again = checkLifecycleChange(stateOf(locked), input.status);
        if (again !== null) throw this.refuse(again);
        return changeLifecycle(
          tx,
          locked,
          input.status,
          input.reason,
          context,
          copiedKey === null ? undefined : { releasedKey: copiedKey },
        );
      }, TX_OPTIONS);
      await deleteReleasedCopies(
        this.store,
        this.prisma,
        [change.releasedKeyToDelete],
        this.logger,
      );
      const poc = await this.prisma.$transaction((tx) => linkedPocArtifacts(tx, id));
      return toArtifact(change.artifact, poc);
    } catch (error) {
      if (copiedKey !== null) {
        await this.store
          .delete(OBJECT_STORAGE_BUCKETS.pocArtifacts, copiedKey)
          .catch((cleanup: unknown) => {
            this.logger.warn(
              { err: cleanup, artifactId: id },
              'failed to delete an unused released copy',
            );
          });
      }
      throw error;
    }
  }

  /**
   * Opens the released copy for download. Only released, clean artifacts are served; the
   * quarantine bucket is never read on behalf of a user.
   */
  async openContent(
    id: string,
    permissions: readonly Permission[],
    signal: AbortSignal,
  ): Promise<{ artifact: StoredArtifact; body: Readable }> {
    const artifact = await this.queries.visibleArtifact(id, permissions);
    if (
      artifact.lifecycleStatus !== 'released' ||
      artifact.scanStatus !== 'clean' ||
      artifact.releasedKey === null
    ) {
      throw this.refuse('Only released artifacts with a clean scan can be downloaded');
    }
    const body = await this.store.getStream(
      OBJECT_STORAGE_BUCKETS.pocArtifacts,
      artifact.releasedKey,
      signal,
    );
    return { artifact, body };
  }
}
