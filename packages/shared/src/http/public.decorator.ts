import { SetMetadata } from '@nestjs/common';

/** Metadata key read by the authentication guard in `@cve/auth`. */
export const PUBLIC_ROUTE_METADATA = 'cve:public-route';

/**
 * Marks a controller or handler as reachable without a bearer token. Every other route is
 * private by default once the authentication guard is registered globally.
 */
export const Public = (): MethodDecorator & ClassDecorator =>
  SetMetadata(PUBLIC_ROUTE_METADATA, true);
