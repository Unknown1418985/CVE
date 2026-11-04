import { Inject, Injectable } from '@nestjs/common';

import type { CveObservationRecordedPayload, VersionRangeInput } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import type { DomainEvent } from '@cve/messaging';

import { APP_LOGGER } from '../common/lifecycle.js';
import { systemContext } from '../events/asset-events.js';
import type { PrismaClient } from '../generated/prisma/client.js';
import { outboxRows, PRISMA, TX_OPTIONS, type Tx } from '../persistence/database.js';
import {
  applyAssociationSet,
  canonicalRanges,
  type DesiredAssociation,
} from './association-writer.js';
import { ProductResolver } from './product-resolver.js';

export type ObservationOutcome =
  | { readonly kind: 'duplicate' }
  | { readonly kind: 'stale'; readonly storedRevision: number }
  | {
      readonly kind: 'applied';
      readonly changes: number;
      readonly products: number;
      readonly skipped: number;
    };

export const OBSERVATION_CONSUMER = 'cve-observation-products';

/**
 * Turns `intelligence.cve-observation.recorded` events into CVE-to-product associations. Each
 * source item (source + sourceRecordId) owns its set of associations; a newer revision replaces
 * the set and older or repeated revisions are ignored, so redelivery and reordering are safe.
 */
@Injectable()
export class ObservationApplier {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(APP_LOGGER) private readonly logger: Logger,
  ) {}

  async apply(event: DomainEvent<CveObservationRecordedPayload>): Promise<ObservationOutcome> {
    const payload = event.payload;
    const context = systemContext(event.correlationId);
    const outcome = await this.prisma.$transaction(async (tx): Promise<ObservationOutcome> => {
      if (!(await claimEvent(tx, OBSERVATION_CONSUMER, event.eventId)))
        return { kind: 'duplicate' };

      const observedAt = new Date(payload.observedAt);
      const cursor = await tx.$queryRaw<{ revision: number; applied: boolean }[]>`
        INSERT INTO "observation_cursors"
               ("id", "source", "source_record_id", "cve_id", "revision", "content_hash",
                "observed_at", "applied_at")
        VALUES (gen_random_uuid(), ${payload.source}, ${payload.sourceRecordId}, ${payload.cveId},
                ${payload.revision}, ${payload.contentHash}, ${observedAt}, now())
        ON CONFLICT ("source", "source_record_id") DO UPDATE
           SET "revision" = EXCLUDED."revision", "cve_id" = EXCLUDED."cve_id",
               "content_hash" = EXCLUDED."content_hash", "observed_at" = EXCLUDED."observed_at",
               "applied_at" = now()
         WHERE "observation_cursors"."revision" < EXCLUDED."revision"
     RETURNING "revision", true AS "applied"`;
      if (cursor.length === 0) {
        const stored = await tx.observationCursor.findUniqueOrThrow({
          where: {
            source_sourceRecordId: {
              source: payload.source,
              sourceRecordId: payload.sourceRecordId,
            },
          },
        });
        return { kind: 'stale', storedRevision: stored.revision };
      }

      const resolver = new ProductResolver(tx, payload.source, context);
      const rangesByProduct = new Map<string, VersionRangeInput[]>();
      let skipped = 0;
      for (const entry of payload.content.affectedProducts) {
        const resolution = await resolver.resolve(entry);
        if (resolution.kind === 'skipped') {
          skipped += 1;
          continue;
        }
        const ranges = rangesByProduct.get(resolution.productId) ?? [];
        ranges.push({
          status: entry.status,
          ...(entry.cpe === undefined ? {} : { cpe: entry.cpe.toLowerCase() }),
          ...(entry.version === undefined ? {} : { version: entry.version }),
          ...(entry.versionStartIncluding === undefined
            ? {}
            : { versionStartIncluding: entry.versionStartIncluding }),
          ...(entry.versionStartExcluding === undefined
            ? {}
            : { versionStartExcluding: entry.versionStartExcluding }),
          ...(entry.versionEndIncluding === undefined
            ? {}
            : { versionEndIncluding: entry.versionEndIncluding }),
          ...(entry.versionEndExcluding === undefined
            ? {}
            : { versionEndExcluding: entry.versionEndExcluding }),
        });
        rangesByProduct.set(resolution.productId, ranges);
      }
      const desired: DesiredAssociation[] = [...rangesByProduct.entries()].map(
        ([productId, ranges]) => ({
          cveId: payload.cveId,
          productId,
          ranges: canonicalRanges(ranges),
        }),
      );

      const { changes, events } = await applyAssociationSet(
        tx,
        {
          source: payload.source,
          sourceRecordId: payload.sourceRecordId,
          origin: 'observation',
          sourceUrl: payload.sourceUrl,
          attribution: payload.attribution,
          scope: {},
          desired,
          seenAt: observedAt,
        },
        context,
      );
      const outbox = [...resolver.events, ...events];
      if (outbox.length > 0) await tx.outboxEvent.createMany({ data: outboxRows(outbox) });
      return { kind: 'applied', changes: changes.length, products: desired.length, skipped };
    }, TX_OPTIONS);

    this.logger.info(
      {
        eventId: event.eventId,
        cveId: payload.cveId,
        source: payload.source,
        sourceRecordId: payload.sourceRecordId,
        revision: payload.revision,
        ...outcome,
      },
      'cve observation processed',
    );
    return outcome;
  }
}

/**
 * Inbox: records that `consumer` handled `eventId`, in the caller's transaction. Returns false
 * when it was already recorded (a redelivery), so the handler can skip it.
 */
export async function claimEvent(tx: Tx, consumer: string, eventId: string): Promise<boolean> {
  const rows = await tx.$queryRaw<{ id: string }[]>`
    INSERT INTO "processed_events" ("id", "consumer", "event_id", "processed_at")
    VALUES (gen_random_uuid(), ${consumer}, ${eventId}::uuid, now())
    ON CONFLICT ("consumer", "event_id") DO NOTHING
 RETURNING "id"`;
  return rows.length > 0;
}
