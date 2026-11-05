import { createHash } from 'node:crypto';

import {
  POC_EVENT_TYPES,
  referenceDiscoveredPayloadSchema,
  type CveObservationRecordedPayload,
  type DomainEventEnvelope,
  type PocReferenceKind,
} from '@cve/contracts';
import type { Logger } from '@cve/logger';
import type { DomainEvent } from '@cve/messaging';

import { rescoreRepository, type ScoringSettings } from '../discovery/association-scorer.js';
import { hashedJobId, type DiscoveryJobQueue } from '../discovery/discovery-jobs.js';
import { classifyReference } from '../domain/references.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import { claimEvent, TX_OPTIONS, writeOutbox } from '../persistence/database.js';
import { pocEvent, SYSTEM_ACTOR } from './poc-events.js';

export const REFERENCE_CONSUMER = 'cve-observation-references';

export type ReferenceOutcome =
  | { readonly kind: 'duplicate' }
  | { readonly kind: 'stale' }
  | {
      readonly kind: 'applied';
      readonly created: number;
      readonly removed: number;
      readonly lookups: number;
    };

const KIND_TO_DB: Readonly<
  Record<
    PocReferenceKind,
    'github_repository' | 'github_gist' | 'exploit_db' | 'packet_storm' | 'other'
  >
> = {
  'github-repository': 'github_repository',
  'github-gist': 'github_gist',
  'exploit-db': 'exploit_db',
  'packet-storm': 'packet_storm',
  other: 'other',
};

const urlHash = (url: string) => createHash('sha256').update(url).digest('hex');

/**
 * Turns `intelligence.cve-observation.recorded` events into public PoC references. Each source
 * item owns the references it lists: a newer revision replaces the set (missing references are
 * marked removed, never deleted) and older or repeated revisions are ignored. References to
 * known repositories rescore them; unknown GitHub repositories are looked up by a job.
 */
export class ReferenceCollector {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly jobs: DiscoveryJobQueue | null,
    private readonly scoring: ScoringSettings,
    private readonly logger: Logger,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async apply(event: DomainEvent<CveObservationRecordedPayload>): Promise<ReferenceOutcome> {
    const payload = event.payload;
    const now = this.clock();
    const result = await this.prisma.$transaction(async (tx) => {
      if (!(await claimEvent(tx, REFERENCE_CONSUMER, event.eventId)))
        return { kind: 'duplicate' } as const;
      const cursor = await tx.$queryRaw<{ revision: number }[]>`
        INSERT INTO "observation_cursors" ("id", "source", "source_record_id", "cve_id", "revision", "applied_at")
        VALUES (gen_random_uuid(), ${payload.source}, ${payload.sourceRecordId}, ${payload.cveId},
                ${payload.revision}, now())
        ON CONFLICT ("source", "source_record_id") DO UPDATE
           SET "revision" = EXCLUDED."revision", "cve_id" = EXCLUDED."cve_id", "applied_at" = now()
         WHERE "observation_cursors"."revision" < EXCLUDED."revision"
        RETURNING "revision"`;
      if (cursor.length === 0) return { kind: 'stale' } as const;

      const source = payload.source;
      const wanted = new Map<
        string,
        { url: string; tags: string[]; kind: PocReferenceKind; repositoryKey: string | null }
      >();
      for (const reference of payload.content.references) {
        const classified = classifyReference(reference.url, reference.tags);
        if (classified === null) continue;
        wanted.set(urlHash(reference.url), {
          url: reference.url,
          tags: [...reference.tags],
          kind: classified.kind,
          repositoryKey: classified.repository?.fullName.toLowerCase() ?? null,
        });
      }
      const stored = await tx.pocReference.findMany({ where: { cveId: payload.cveId, source } });
      const storedByHash = new Map(stored.map((row) => [row.urlHash, row]));
      const removed = stored.filter((row) => row.removedAt === null && !wanted.has(row.urlHash));
      if (removed.length > 0) {
        await tx.pocReference.updateMany({
          where: { id: { in: removed.map((row) => row.id) } },
          data: { removedAt: now },
        });
      }
      const events: DomainEventEnvelope[] = [];
      const affectedRepositories = new Set<string>(
        removed.flatMap((row) => (row.repositoryId === null ? [] : [row.repositoryId])),
      );
      const lookups = new Set<string>();
      let created = 0;
      for (const [hash, reference] of wanted) {
        const known =
          reference.repositoryKey === null
            ? null
            : await tx.pocRepository.findFirst({
                where: { fullNameKey: reference.repositoryKey },
                select: { id: true },
              });
        const existing = storedByHash.get(hash);
        const fields = {
          url: reference.url,
          kind: KIND_TO_DB[reference.kind],
          tags: reference.tags,
          repositoryKey: reference.repositoryKey,
          repositoryId: known?.id ?? existing?.repositoryId ?? null,
          removedAt: null,
          lastSeenAt: now,
        };
        if (existing === undefined) {
          const row = await tx.pocReference.create({
            data: { cveId: payload.cveId, source, urlHash: hash, firstSeenAt: now, ...fields },
          });
          created += 1;
          events.push(
            pocEvent(
              POC_EVENT_TYPES.referenceDiscovered,
              referenceDiscoveredPayloadSchema,
              {
                referenceId: row.id,
                cveId: payload.cveId,
                url: row.url,
                kind: reference.kind,
                source,
                tags: row.tags,
                repositoryId: row.repositoryId,
              },
              event.correlationId,
            ),
          );
        } else {
          await tx.pocReference.update({ where: { id: existing.id }, data: fields });
        }
        if (fields.repositoryId !== null) affectedRepositories.add(fields.repositoryId);
        else if (reference.repositoryKey !== null) lookups.add(reference.repositoryKey);
      }
      for (const repositoryId of affectedRepositories) {
        const scored = await rescoreRepository(tx, repositoryId, this.scoring, {
          actor: SYSTEM_ACTOR,
          correlationId: event.correlationId,
          now,
        });
        events.push(...scored.events);
      }
      if (lookups.size > 0 && this.jobs !== null) {
        await tx.pocReference.updateMany({
          where: { repositoryKey: { in: [...lookups] }, repositoryId: null },
          data: { resolveQueuedAt: now },
        });
      }
      await writeOutbox(tx, events);
      return { kind: 'applied', created, removed: removed.length, lookups: [...lookups] } as const;
    }, TX_OPTIONS);

    if (result.kind !== 'applied') return result;
    // Best effort after the commit: unresolved references are re-queued by the maintenance job.
    for (const fullName of result.lookups) {
      try {
        await this.jobs?.enqueueDiscovery(
          {
            connector: 'github',
            mode: 'repository',
            trigger: 'event',
            fullName,
            ...(event.correlationId === undefined ? {} : { correlationId: event.correlationId }),
          },
          hashedJobId('reference', `${fullName}:${now.toISOString().slice(0, 10)}`),
        );
      } catch (error) {
        this.logger.error(
          { err: error, fullName },
          'failed to queue a referenced repository lookup',
        );
      }
    }
    this.logger.debug(
      {
        eventId: event.eventId,
        cveId: payload.cveId,
        created: result.created,
        removed: result.removed,
      },
      'cve observation references processed',
    );
    return {
      kind: 'applied',
      created: result.created,
      removed: result.removed,
      lookups: result.lookups.length,
    };
  }
}
