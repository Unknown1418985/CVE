import {
  artifactDiscoveredPayloadSchema,
  artifactVerificationChangedPayloadSchema,
  POC_EVENT_TYPES,
  referenceDiscoveredPayloadSchema,
  type ArtifactDiscoveredPayload,
  type ArtifactVerificationChangedPayload,
  type ReferenceDiscoveredPayload,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';
import type { DomainEvent, EventSubscription } from '@cve/messaging';

import {
  exploitDbIdFromReference,
  exploitDbTarget,
  githubArchiveTarget,
  type SourcePolicy,
} from '../domain/sources.js';
import type { DownloadJobQueue } from '../download/download-jobs.js';
import {
  deleteReleasedCopies,
  refreshVerification,
  type LifecycleChange,
} from '../download/lifecycle.js';
import { planRequest } from '../download/requests.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import { claimEvent, TX_OPTIONS } from '../persistence/database.js';
import { VERIFICATION_TO_DB } from '../persistence/enums.js';
import type { ArtifactObjectStore } from '../storage/object-store.js';
import { systemContext } from './download-events.js';

export const POC_ARTIFACT_CONSUMER = 'poc-artifact-downloads';
export const POC_VERIFICATION_CONSUMER = 'poc-artifact-verification';
export const POC_REFERENCE_CONSUMER = 'poc-reference-downloads';

export interface PocEventHandlerOptions {
  readonly prisma: PrismaClient;
  readonly jobs: DownloadJobQueue | null;
  readonly store: ArtifactObjectStore;
  readonly sources: readonly SourcePolicy[];
  readonly maxAttempts: number;
  /** A PoC artifact whose listing exceeds `maxBytes × ratio` is rejected without downloading. */
  readonly maxExpectedRatio: number;
  readonly logger: Logger;
}

/**
 * Turns PoC Service events into downloads and keeps the verification projection current:
 * - `poc.artifact.discovered`: schedule the repository archive at that commit;
 * - `poc.artifact.verification-changed`: update the combined verification of stored artifacts
 *   (a malicious or rejected judgement revokes a release);
 * - `poc.reference.discovered` (Exploit-DB): schedule the raw exploit file.
 *
 * Every handler claims the event in its own transaction (inbox), so redelivery is a no-op.
 */
export class PocEventHandlers {
  constructor(private readonly options: PocEventHandlerOptions) {}

  private policy(source: SourcePolicy['source']): SourcePolicy | undefined {
    return this.options.sources.find((policy) => policy.source === source);
  }

  private async queue(requestId: string | null): Promise<void> {
    if (requestId === null || this.options.jobs === null) return;
    try {
      await this.options.jobs.queueRequest(requestId);
    } catch (error) {
      // The scheduler sweep picks the request up; Redis outages only delay it.
      this.options.logger.warn({ err: error, requestId }, 'failed to queue a download');
    }
  }

  async artifactDiscovered(event: DomainEvent<ArtifactDiscoveredPayload>): Promise<void> {
    const payload = event.payload;
    const policy = this.policy('github-archive');
    const requestId = await this.options.prisma.$transaction(async (tx) => {
      if (!(await claimEvent(tx, POC_ARTIFACT_CONSUMER, event.eventId))) return null;
      const occurredAt = new Date(event.occurredAt);
      const existing = await tx.pocArtifactState.findUnique({
        where: { pocArtifactId: payload.artifactId },
      });
      if (existing === null) {
        await tx.pocArtifactState.create({
          data: {
            pocArtifactId: payload.artifactId,
            repositoryId: payload.repositoryId,
            repositoryFullName: payload.repositoryFullName,
            commitSha: payload.commitSha,
            cveIds: payload.cveIds,
            totalBytes: BigInt(payload.totalBytes),
            verificationStatus: VERIFICATION_TO_DB[payload.verificationStatus],
            eventOccurredAt: occurredAt,
          },
        });
      }
      if (policy === undefined || !policy.enabled || !policy.automatic) return null;
      const target = githubArchiveTarget(policy, payload.repositoryFullName, payload.commitSha);
      if (target === null) {
        this.options.logger.warn(
          { artifactId: payload.artifactId },
          'PoC artifact has no valid repository name or commit',
        );
        return null;
      }
      const expectedLimit = policy.maxBytes * this.options.maxExpectedRatio;
      const planned = await planRequest(tx, {
        target,
        trigger: 'event',
        cveIds: payload.cveIds,
        pocArtifactId: payload.artifactId,
        pocRepositoryId: payload.repositoryId,
        priority: payload.verificationStatus === 'malicious' ? 9 : 5,
        scheduledFor: new Date(),
        maxAttempts: this.options.maxAttempts,
        requestedBy: null,
        reason: 'poc.artifact.discovered',
        correlationId: event.correlationId,
        discoveredAt: occurredAt,
        ...(payload.totalBytes > expectedLimit
          ? {
              rejection: {
                errorCode: 'size-limit-exceeded',
                error: `The repository listing has ${String(payload.totalBytes)} bytes, more than ${String(this.options.maxExpectedRatio)}× the download limit`,
              },
            }
          : {}),
      });
      return planned.created && planned.request.status === 'pending' ? planned.request.id : null;
    }, TX_OPTIONS);
    await this.queue(requestId);
  }

  async verificationChanged(event: DomainEvent<ArtifactVerificationChangedPayload>): Promise<void> {
    const payload = event.payload;
    const changes: LifecycleChange[] = [];
    await this.options.prisma.$transaction(async (tx) => {
      if (!(await claimEvent(tx, POC_VERIFICATION_CONSUMER, event.eventId))) return;
      const existing = await tx.pocArtifactState.findUnique({
        where: { pocArtifactId: payload.artifactId },
      });
      // Events can arrive out of order: an older decision never overwrites a newer one.
      if (existing !== null && existing.verificationVersion >= payload.version) return;
      const status = VERIFICATION_TO_DB[payload.toStatus];
      await tx.pocArtifactState.upsert({
        where: { pocArtifactId: payload.artifactId },
        create: {
          pocArtifactId: payload.artifactId,
          repositoryId: payload.repositoryId,
          commitSha: payload.commitSha,
          cveIds: [],
          verificationStatus: status,
          verificationVersion: payload.version,
          eventOccurredAt: new Date(event.occurredAt),
        },
        update: {
          verificationStatus: status,
          verificationVersion: payload.version,
          eventOccurredAt: new Date(event.occurredAt),
        },
      });
      const linked = await tx.artifactSource.findMany({
        where: { pocArtifactId: payload.artifactId },
        select: { artifactId: true },
        distinct: ['artifactId'],
      });
      for (const { artifactId } of linked) {
        const locked = await tx.$queryRaw<{ id: string }[]>`
          SELECT "id" FROM "stored_artifacts" WHERE "id" = ${artifactId}::uuid FOR UPDATE`;
        if (locked.length === 0) continue;
        const artifact = await tx.storedArtifact.findUniqueOrThrow({ where: { id: artifactId } });
        changes.push(await refreshVerification(tx, artifact, systemContext(event.correlationId)));
      }
    }, TX_OPTIONS);
    await deleteReleasedCopies(
      this.options.store,
      this.options.prisma,
      changes.map((change) => change.releasedKeyToDelete),
      this.options.logger,
    );
  }

  async referenceDiscovered(event: DomainEvent<ReferenceDiscoveredPayload>): Promise<void> {
    const payload = event.payload;
    const policy = this.policy('exploit-db');
    if (
      payload.kind !== 'exploit-db' ||
      policy === undefined ||
      !policy.enabled ||
      !policy.automatic
    )
      return;
    const exploitId = exploitDbIdFromReference(policy, payload.url);
    const target = exploitId === null ? null : exploitDbTarget(policy, exploitId);
    const requestId = await this.options.prisma.$transaction(async (tx) => {
      if (!(await claimEvent(tx, POC_REFERENCE_CONSUMER, event.eventId))) return null;
      if (target === null) {
        this.options.logger.info({ url: payload.url }, 'Exploit-DB reference without an entry ID');
        return null;
      }
      const planned = await planRequest(tx, {
        target,
        trigger: 'event',
        cveIds: [payload.cveId],
        pocArtifactId: null,
        pocRepositoryId: null,
        priority: 5,
        scheduledFor: new Date(),
        maxAttempts: this.options.maxAttempts,
        requestedBy: null,
        reason: 'poc.reference.discovered',
        correlationId: event.correlationId,
        discoveredAt: new Date(event.occurredAt),
      });
      return planned.created ? planned.request.id : null;
    }, TX_OPTIONS);
    await this.queue(requestId);
  }
}

/** Event subscriptions; payloads are validated against the PoC Service's published contracts. */
export function downloadSubscriptions(
  handlers: PocEventHandlers,
): [
  EventSubscription<ArtifactDiscoveredPayload>,
  EventSubscription<ArtifactVerificationChangedPayload>,
  EventSubscription<ReferenceDiscoveredPayload>,
] {
  return [
    {
      consumer: POC_ARTIFACT_CONSUMER,
      eventTypes: [POC_EVENT_TYPES.artifactDiscovered],
      payloadSchema: artifactDiscoveredPayloadSchema,
      prefetch: 8,
      handle: (event) => handlers.artifactDiscovered(event),
    },
    {
      consumer: POC_VERIFICATION_CONSUMER,
      eventTypes: [POC_EVENT_TYPES.artifactVerificationChanged],
      payloadSchema: artifactVerificationChangedPayloadSchema,
      handle: (event) => handlers.verificationChanged(event),
    },
    {
      consumer: POC_REFERENCE_CONSUMER,
      eventTypes: [POC_EVENT_TYPES.referenceDiscovered],
      payloadSchema: referenceDiscoveredPayloadSchema,
      prefetch: 8,
      handle: (event) => handlers.referenceDiscovered(event),
    },
  ];
}
