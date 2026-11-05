import type { Request } from 'express';

import type { AuthenticatedPrincipal } from '@cve/auth';
import type { EventActor } from '@cve/contracts';
import { getCorrelationId } from '@cve/shared';

/** Who made a change, carried into domain events and logs. */
export interface ActorContext {
  readonly actor: EventActor;
  readonly correlationId: string | undefined;
}

/** Keycloak names service-account users `service-account-<client>`. */
export function eventActor(principal: AuthenticatedPrincipal): EventActor {
  return {
    type: principal.username.startsWith('service-account-') ? 'service' : 'user',
    id: principal.subject,
    username: principal.username,
  };
}

export function actorContext(req: Request, principal: AuthenticatedPrincipal): ActorContext {
  return { actor: eventActor(principal), correlationId: getCorrelationId(req) };
}
