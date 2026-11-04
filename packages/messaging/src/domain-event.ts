import { randomUUID } from 'node:crypto';

import {
  domainEventEnvelopeSchema,
  type DomainEventEnvelope,
  type ServiceName,
} from '@cve/contracts';

/** A domain event whose payload has been validated against a specific schema. */
export type DomainEvent<TPayload> = Omit<DomainEventEnvelope, 'payload'> & {
  readonly payload: TPayload;
};

export interface CreateDomainEventInput<TPayload> {
  readonly eventType: string;
  readonly eventVersion?: number;
  readonly producer: ServiceName;
  readonly payload: TPayload;
  readonly correlationId?: string | undefined;
  /** Override for deterministic tests and outbox replays. */
  readonly eventId?: string;
  readonly occurredAt?: Date;
}

/** Builds and validates a domain event envelope. Throws when the envelope is invalid. */
export function createDomainEvent<TPayload>(
  input: CreateDomainEventInput<TPayload>,
): DomainEvent<TPayload> {
  const envelope = {
    eventId: input.eventId ?? randomUUID(),
    eventType: input.eventType,
    eventVersion: input.eventVersion ?? 1,
    occurredAt: (input.occurredAt ?? new Date()).toISOString(),
    producer: input.producer,
    ...(input.correlationId === undefined ? {} : { correlationId: input.correlationId }),
    payload: input.payload,
  };
  domainEventEnvelopeSchema.parse(envelope);
  return envelope;
}
