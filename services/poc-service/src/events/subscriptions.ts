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

import { CVE_TRACKER_CONSUMER, type CveTracker } from './cve-tracker.js';
import { REFERENCE_CONSUMER, type ReferenceCollector } from './reference-collector.js';

/** `updated` first: it is the most specific shape, and object schemas strip unknown keys. */
const cveRecordPayloadSchema = z.union([
  cveRecordUpdatedPayloadSchema,
  cveRecordCreatedPayloadSchema,
  cveRecordDeletedPayloadSchema,
]);

/**
 * Event subscriptions of the PoC Service. Both handlers are idempotent (inbox table written in
 * the same transaction) and order-aware, so at-least-once delivery and retries are safe.
 */
export function pocSubscriptions(handlers: {
  readonly tracker: CveTracker;
  readonly references: ReferenceCollector;
}): [
  EventSubscription<z.infer<typeof cveRecordPayloadSchema>>,
  EventSubscription<CveObservationRecordedPayload>,
] {
  return [
    {
      consumer: CVE_TRACKER_CONSUMER,
      eventTypes: [CVE_EVENT_TYPES.created, CVE_EVENT_TYPES.updated, CVE_EVENT_TYPES.deleted],
      payloadSchema: cveRecordPayloadSchema,
      handle: async (event) => {
        await handlers.tracker.apply(event);
      },
    },
    {
      consumer: REFERENCE_CONSUMER,
      eventTypes: [INTELLIGENCE_EVENT_TYPES.cveObserved],
      payloadSchema: cveObservationRecordedPayloadSchema,
      prefetch: 8,
      handle: async (event) => {
        await handlers.references.apply(event);
      },
    },
  ];
}
