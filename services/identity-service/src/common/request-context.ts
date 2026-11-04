import type { Request } from 'express';

import type { AuthenticatedPrincipal } from '@cve/auth';
import { getCorrelationId } from '@cve/shared';

/** Who did something, from where. Attached to audit entries and domain events. */
export interface ActorContext {
  readonly principal: AuthenticatedPrincipal;
  readonly ipAddress: string | undefined;
  readonly userAgent: string | undefined;
  readonly correlationId: string | undefined;
}

export function actorContext(req: Request, principal: AuthenticatedPrincipal): ActorContext {
  const userAgent = req.headers['user-agent'];
  return {
    principal,
    // `trust proxy` is limited to private networks, so this is the gateway-forwarded client IP.
    ipAddress: req.ip,
    userAgent: typeof userAgent === 'string' ? userAgent.slice(0, 512) : undefined,
    correlationId: getCorrelationId(req),
  };
}
