import { z } from 'zod';

import { SERVICE_NAMES } from './services.js';

/**
 * Envelope for every domain event published on RabbitMQ.
 * Payload schemas are defined per event type by the owning service.
 */
export const domainEventEnvelopeSchema = z.object({
  eventId: z.uuid(),
  eventType: z.string().regex(/^[a-z]+(?:-[a-z]+)*\.[a-z]+(?:-[a-z]+)*\.[a-z]+(?:-[a-z]+)*$/, {
    message: 'eventType must follow "<domain>.<entity>.<action>" in kebab-case',
  }),
  eventVersion: z.number().int().min(1),
  occurredAt: z.iso.datetime(),
  producer: z.enum(SERVICE_NAMES),
  correlationId: z.string().min(1).optional(),
  payload: z.unknown(),
});

export type DomainEventEnvelope = z.infer<typeof domainEventEnvelopeSchema>;

/** Builds a typed envelope schema for a specific payload. */
export function domainEventSchema<T extends z.ZodType>(payload: T) {
  return domainEventEnvelopeSchema.extend({ payload });
}
