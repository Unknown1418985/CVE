import {
  createParamDecorator,
  SetMetadata,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';

import type { Permission, Role } from '@cve/contracts';

import type { AuthenticatedPrincipal } from '../principal.js';
import { REQUIRED_PERMISSIONS_METADATA, REQUIRED_ROLES_METADATA } from './auth.constants.js';
import { getRequestPrincipal } from './request-principal.js';

/** The caller must hold **all** listed permissions. Handler metadata adds to class metadata. */
export const RequirePermissions = (
  ...permissions: [Permission, ...Permission[]]
): MethodDecorator & ClassDecorator => SetMetadata(REQUIRED_PERMISSIONS_METADATA, permissions);

/** The caller must hold **at least one** of the listed roles. Prefer permissions where possible. */
export const RequireRoles = (...roles: [Role, ...Role[]]): MethodDecorator & ClassDecorator =>
  SetMetadata(REQUIRED_ROLES_METADATA, roles);

/** Injects the authenticated principal; throws 401 if the route is reached without one. */
export const CurrentPrincipal = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AuthenticatedPrincipal => {
    const principal = getRequestPrincipal(context.switchToHttp().getRequest<Request>());
    if (!principal) throw new UnauthorizedException('Authentication required');
    return principal;
  },
);

/** Injects the principal when present (for public routes that adapt to the caller). */
export const OptionalPrincipal = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AuthenticatedPrincipal | undefined =>
    getRequestPrincipal(context.switchToHttp().getRequest<Request>()),
);
