import type { Request } from 'express';

import type { AuthenticatedPrincipal } from '@cve/auth';
import { getCorrelationId } from '@cve/shared';

import type { RequestContext } from './sync.service.js';

export function requestContext(req: Request, principal: AuthenticatedPrincipal): RequestContext {
  return {
    requestedBy: `${principal.username} (${principal.subject})`.slice(0, 200),
    correlationId: getCorrelationId(req),
  };
}
