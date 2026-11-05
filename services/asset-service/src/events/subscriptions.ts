import {
  CVE_EVENT_TYPES,
  cveObservationRecordedPayloadSchema,
  cveRecordCreatedPayloadSchema,
  cveRecordDeletedPayloadSchema,
  cveRecordUpdatedPayloadSchema,
  INTELLIGENCE_EVENT_TYPES,
  type CveObservationRecordedPayload,
} from '@cve/contracts';
import type { EventSubscription } from '@cve/messaging';
import { z } from 'zod';

import {
  OBSERVATION_CONSUMER,
  type ObservationApplier,
} from '../associations/observation-applier.js';
import { CVE_FACTS_CONSUMER, type CveFactsProjector } from './cve-facts.projector.js';

/** `updated` first: it is the most specific shape, and object schemas strip unknown keys. */
const cveRecordPayloadSchema = z.union([
  cveRecordUpdatedPayloadSchema,
  cveRecordCreatedPayloadSchema,
  cveRecordDeletedPayloadSchema,
]);

/**
 * Event subscriptions of the Asset Service. Both handlers are idempotent (inbox table written in
 * the same transaction) and order-aware, so at-least-once delivery and retries are safe.
 */
export function assetSubscriptions(handlers: {
  readonly observations: ObservationApplier;
  readonly facts: CveFactsProjector;
}): [
  EventSubscription<CveObservationRecordedPayload>,
  EventSubscription<z.infer<typeof cveRecordPayloadSchema>>,
] {
  return [
    {
      consumer: OBSERVATION_CONSUMER,
      eventTypes: [INTELLIGENCE_EVENT_TYPES.cveObserved],
      payloadSchema: cveObservationRecordedPayloadSchema,
      // Observations can carry up to 2,000 products; keep few in flight.
      prefetch: 4,
      handle: async (event) => {
        await handlers.observations.apply(event);
      },
    },
    {
      consumer: CVE_FACTS_CONSUMER,
      eventTypes: [CVE_EVENT_TYPES.created, CVE_EVENT_TYPES.updated, CVE_EVENT_TYPES.deleted],
      payloadSchema: cveRecordPayloadSchema,
      handle: async (event) => {
        await handlers.facts.apply(event);
      },
    },
  ];
}
