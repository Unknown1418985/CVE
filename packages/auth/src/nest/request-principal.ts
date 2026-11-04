import type { Request } from 'express';

import type { AuthenticatedPrincipal } from '../principal.js';

const principals = new WeakMap<Request, AuthenticatedPrincipal>();

export function setRequestPrincipal(req: Request, principal: AuthenticatedPrincipal): void {
  principals.set(req, principal);
}

/** The principal attached by the authentication guard, if the request carried a valid token. */
export function getRequestPrincipal(req: Request): AuthenticatedPrincipal | undefined {
  return principals.get(req);
}
