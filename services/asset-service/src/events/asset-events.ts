import type { z } from 'zod';

import type { DomainEventEnvelope, EventActor } from '@cve/contracts';
import { createDomainEvent } from '@cve/messaging';

import type { ActorContext } from '../common/request-context.js';
import { SERVICE_NAME } from '../service.js';

/** Actor of changes the service makes on its own, e.g. products discovered from CVE data. */
export const SYSTEM_ACTOR: EventActor = { type: 'service', id: SERVICE_NAME, username: null };

export function systemContext(correlationId: string | undefined): ActorContext {
  return { actor: SYSTEM_ACTOR, correlationId };
}

/** Builds an outbox event after validating the payload against its published contract. */
export function assetEvent<T extends z.ZodType>(
  eventType: string,
  schema: T,
  payload: z.input<T>,
  context: ActorContext,
): DomainEventEnvelope {
  return createDomainEvent({
    eventType,
    producer: SERVICE_NAME,
    payload: schema.parse(payload),
    correlationId: context.correlationId,
  });
}
