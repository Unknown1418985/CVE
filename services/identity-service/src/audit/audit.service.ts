import { Inject, Injectable } from '@nestjs/common';

import { createDomainEvent } from '@cve/messaging';
import type { AuditOutcome } from '@cve/contracts';

import type { ActorContext } from '../common/request-context.js';
import { AUDIT_REPOSITORY, type AuditRepository } from '../persistence/ports.js';
import { SERVICE_NAME } from '../service.js';

export interface AuditActionInput {
  readonly action: string;
  readonly outcome?: AuditOutcome;
  readonly resourceType?: string;
  readonly resourceId?: string;
  readonly details?: Readonly<Record<string, unknown>>;
  /** Domain events written atomically with the audit entry (transactional outbox). */
  readonly events?: readonly { eventType: string; payload: unknown }[];
}

/** Records what authenticated users did through the Identity Service. */
@Injectable()
export class AuditService {
  constructor(@Inject(AUDIT_REPOSITORY) private readonly repository: AuditRepository) {}

  async record(context: ActorContext, input: AuditActionInput): Promise<void> {
    const { principal } = context;
    const events = (input.events ?? []).map((event) =>
      createDomainEvent({
        eventType: event.eventType,
        producer: SERVICE_NAME,
        payload: event.payload,
        ...(context.correlationId === undefined ? {} : { correlationId: context.correlationId }),
      }),
    );
    await this.repository.append(
      {
        occurredAt: new Date(),
        source: SERVICE_NAME,
        action: input.action,
        outcome: input.outcome ?? 'success',
        actorType: 'user',
        actorId: principal.subject,
        actorUsername: principal.username,
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        correlationId: context.correlationId,
        details: input.details,
      },
      events,
    );
  }
}
