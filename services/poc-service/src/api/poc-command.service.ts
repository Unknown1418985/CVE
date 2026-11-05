import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';

import {
  artifactVerificationChangedPayloadSchema,
  artifactVerificationStatusSchema,
  POC_EVENT_TYPES,
  type ChangeVerificationRequest,
  type CreateAssociationRequest,
  type Permission,
  type PocArtifact,
  type PocAssociation,
  type ReviewAssociationRequest,
  type TriggerDiscoveryRequest,
  type TriggerDiscoveryResponse,
} from '@cve/contracts';

import { checkPrecondition, type Precondition } from '../common/http.js';
import type { ActorContext } from '../common/request-context.js';
import {
  associationEvent,
  refreshMaxConfidence,
  rescoreRepository,
  type ScoringSettings,
} from '../discovery/association-scorer.js';
import type { DiscoveryJobQueue } from '../discovery/discovery-jobs.js';
import { checkVerificationTransition } from '../domain/verification.js';
import { pocEvent } from '../events/poc-events.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import {
  decimalToNumber,
  isUniqueViolation,
  PRISMA,
  TX_OPTIONS,
  writeOutbox,
} from '../persistence/database.js';
import {
  ARTIFACT_INCLUDE,
  ASSOCIATION_INCLUDE,
  toArtifact,
  toAssociation,
  VERIFICATION_TO_DB,
} from './mappers.js';
import { canSeeMalicious } from './poc-query.service.js';
import { CONNECTOR_INFO, DISCOVERY_JOBS, SCORING_SETTINGS, type ConnectorInfo } from './tokens.js';

const actorName = (context: ActorContext) => context.actor.username ?? context.actor.id;

@Injectable()
export class PocCommandService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(DISCOVERY_JOBS) private readonly jobs: DiscoveryJobQueue | null,
    @Inject(CONNECTOR_INFO) private readonly connectors: readonly ConnectorInfo[],
    @Inject(SCORING_SETTINGS) private readonly scoring: ScoringSettings,
  ) {}

  /** Confirms or rejects an association. The score is kept; the decision is the analyst's. */
  async reviewAssociation(
    context: ActorContext,
    id: string,
    input: ReviewAssociationRequest,
    precondition: Precondition,
  ): Promise<PocAssociation> {
    return this.prisma.$transaction(async (tx) => {
      const [locked] = await tx.$queryRaw<{ version: number }[]>`
        SELECT "version" FROM "poc_cve_associations" WHERE "id" = ${id}::uuid FOR UPDATE`;
      if (locked === undefined) throw new NotFoundException('PoC association not found');
      checkPrecondition(precondition, locked.version);
      const current = await tx.pocAssociation.findUniqueOrThrow({ where: { id } });
      if (current.reviewStatus === input.reviewStatus && current.reviewNote === input.note) {
        return toAssociation(
          await tx.pocAssociation.findUniqueOrThrow({
            where: { id },
            include: ASSOCIATION_INCLUDE,
          }),
        );
      }
      const row = await tx.pocAssociation.update({
        where: { id },
        data: {
          reviewStatus: input.reviewStatus,
          reviewNote: input.note,
          reviewedBy: actorName(context),
          reviewedAt: new Date(),
          version: { increment: 1 },
        },
        include: ASSOCIATION_INCLUDE,
      });
      await refreshMaxConfidence(tx, row.repositoryId);
      const confidence = decimalToNumber(row.confidence) ?? 0;
      await writeOutbox(tx, [
        associationEvent(
          POC_EVENT_TYPES.associationReviewed,
          row,
          row.repository.url,
          {
            confidence,
            level: row.confidenceLevel,
            signals: row.signals as never,
            scoringVersion: row.scoringVersion,
          },
          confidence,
          context,
        ),
      ]);
      return toAssociation(row);
    }, TX_OPTIONS);
  }

  /** Associates a known repository with a CVE by hand; it is confirmed and scored like others. */
  async createAssociation(
    context: ActorContext,
    input: CreateAssociationRequest,
  ): Promise<PocAssociation> {
    try {
      return await this.prisma.$transaction(async (tx) => {
        const repository = await tx.pocRepository.findUnique({
          where: { id: input.repositoryId },
          select: { id: true },
        });
        if (repository === null) throw new NotFoundException('PoC repository not found');
        const existing = await tx.pocAssociation.findUnique({
          where: { repositoryId_cveId: { repositoryId: input.repositoryId, cveId: input.cveId } },
          select: { id: true },
        });
        if (existing !== null) {
          throw new ConflictException({
            message:
              'The repository is already associated with this CVE; review the existing association',
            details: [{ path: 'cveId', message: `association ${existing.id} exists` }],
          });
        }
        const now = new Date();
        const created = await tx.pocAssociation.create({
          data: {
            repositoryId: input.repositoryId,
            cveId: input.cveId,
            confidence: 0,
            confidenceLevel: 'low',
            signals: [],
            penalties: [],
            scoringVersion: 1,
            origin: 'manual',
            manual: true,
            reviewStatus: 'confirmed',
            reviewedBy: actorName(context),
            reviewedAt: now,
            reviewNote: input.note,
            firstDiscoveredAt: now,
          },
          select: { id: true },
        });
        // Scores the new pair together with the repository's other evidence.
        const scored = await rescoreRepository(tx, input.repositoryId, this.scoring, {
          actor: context.actor,
          correlationId: context.correlationId,
          now,
        });
        const row = await tx.pocAssociation.findUniqueOrThrow({
          where: { id: created.id },
          include: ASSOCIATION_INCLUDE,
        });
        const confidence = decimalToNumber(row.confidence) ?? 0;
        await writeOutbox(tx, [
          ...scored.events.filter(
            (event) => (event.payload as { associationId?: string }).associationId !== row.id,
          ),
          associationEvent(
            POC_EVENT_TYPES.associationDiscovered,
            row,
            row.repository.url,
            {
              confidence,
              level: row.confidenceLevel,
              signals: row.signals as never,
              scoringVersion: row.scoringVersion,
            },
            null,
            context,
          ),
        ]);
        return toAssociation(row);
      }, TX_OPTIONS);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ConflictException('The repository is already associated with this CVE');
      }
      throw error;
    }
  }

  /** Moves an artifact through its verification states (append-only history). */
  async changeVerification(
    context: ActorContext,
    permissions: readonly Permission[],
    id: string,
    input: ChangeVerificationRequest,
    precondition: Precondition,
  ): Promise<PocArtifact> {
    return this.prisma.$transaction(async (tx) => {
      const [locked] = await tx.$queryRaw<{ version: number; status: string }[]>`
        SELECT "version", "verification_status"::text AS "status" FROM "poc_artifacts"
         WHERE "id" = ${id}::uuid FOR UPDATE`;
      if (
        locked === undefined ||
        (locked.status === 'malicious' && !canSeeMalicious(permissions))
      ) {
        throw new NotFoundException('PoC artifact not found');
      }
      checkPrecondition(precondition, locked.version);
      // Raw SQL returns the database labels (`in-review`), which are the API values; anything
      // else is a schema drift and must not be read as `unverified`.
      const from = artifactVerificationStatusSchema.parse(locked.status);
      const check = checkVerificationTransition(from, input.status, permissions);
      if (!check.ok) {
        if (check.reason === 'forbidden') {
          throw new ForbiddenException(
            from === 'malicious'
              ? 'Leaving the malicious state requires the quarantine:manage permission'
              : 'Changing the verification status requires the poc:manage permission',
          );
        }
        throw new ConflictException({
          message:
            check.reason === 'same-status'
              ? `The artifact is already ${from}`
              : `An artifact cannot move from ${from} to ${input.status}`,
          details: [
            { path: 'status', message: `transition ${from} → ${input.status} is not allowed` },
          ],
        });
      }
      const now = new Date();
      const row = await tx.pocArtifact.update({
        where: { id },
        data: {
          verificationStatus: VERIFICATION_TO_DB[input.status],
          verificationUpdatedAt: now,
          verificationUpdatedBy: actorName(context),
          version: { increment: 1 },
        },
        include: ARTIFACT_INCLUDE,
      });
      await tx.artifactVerificationEvent.create({
        data: {
          artifactId: id,
          fromStatus: VERIFICATION_TO_DB[from],
          toStatus: VERIFICATION_TO_DB[input.status],
          reason: input.reason,
          actorId: context.actor.id,
          actorUsername: context.actor.username,
          correlationId: context.correlationId ?? null,
          createdAt: now,
        },
      });
      await writeOutbox(tx, [
        pocEvent(
          POC_EVENT_TYPES.artifactVerificationChanged,
          artifactVerificationChangedPayloadSchema,
          {
            artifactId: id,
            repositoryId: row.repositoryId,
            commitSha: row.commitSha,
            fromStatus: from,
            toStatus: input.status,
            reason: input.reason,
            version: row.version,
            actor: context.actor,
          },
          context.correlationId,
        ),
      ]);
      return toArtifact(row);
    }, TX_OPTIONS);
  }

  /** Queues a discovery job; the idempotency key makes retries of the request safe. */
  async triggerDiscovery(
    context: ActorContext,
    input: TriggerDiscoveryRequest,
    idempotencyKey: string | undefined,
  ): Promise<TriggerDiscoveryResponse> {
    const connector = this.connectors.find((info) => info.connector === input.connector);
    if (!connector?.enabled) {
      throw new ConflictException(`The ${input.connector} connector is not enabled`);
    }
    if (this.jobs === null)
      throw new ServiceUnavailableException('Discovery jobs are not available');
    if (input.mode === 'repository') {
      const repository = await this.prisma.pocRepository.findUnique({
        where: { id: input.repositoryId },
        select: { id: true },
      });
      if (repository === null) throw new NotFoundException('PoC repository not found');
    }
    const requestedBy = actorName(context);
    const base = {
      connector: input.connector,
      trigger: 'manual' as const,
      requestedBy,
      ...(context.correlationId === undefined ? {} : { correlationId: context.correlationId }),
    };
    const payload =
      input.mode === 'cve'
        ? { ...base, mode: 'cve' as const, cveId: input.cveId }
        : input.mode === 'repository'
          ? { ...base, mode: 'repository' as const, repositoryId: input.repositoryId }
          : { ...base, mode: 'recent' as const };
    return this.jobs.enqueueDiscovery(
      payload,
      idempotencyKey === undefined
        ? undefined
        : `manual.${context.actor.id.slice(0, 40)}.${idempotencyKey}`.replace(
            /[^A-Za-z0-9._-]/g,
            '-',
          ),
    );
  }
}
