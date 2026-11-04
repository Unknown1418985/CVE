import {
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';

import type { Permission, Role } from '@cve/contracts';
import { getCorrelationId, PUBLIC_ROUTE_METADATA } from '@cve/shared';

import { hasAnyRole } from '../principal.js';
import {
  AUTH_OPTIONS,
  REQUIRED_PERMISSIONS_METADATA,
  REQUIRED_ROLES_METADATA,
} from './auth.constants.js';
import type { AuthModuleOptions } from './auth.options.js';
import { getRequestPrincipal } from './request-principal.js';

/**
 * Global guard enforcing `@RequirePermissions` (all of) and `@RequireRoles` (any of), with class
 * and handler requirements combined. Runs after {@link AuthenticationGuard}.
 */
@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(AUTH_OPTIONS) private readonly options: AuthModuleOptions,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const targets = [context.getClass(), context.getHandler()];
    const permissions = [
      ...new Set(
        targets.flatMap(
          (target) =>
            this.reflector.get<Permission[] | undefined>(REQUIRED_PERMISSIONS_METADATA, target) ??
            [],
        ),
      ),
    ];
    const roles = [
      ...new Set(
        targets.flatMap(
          (target) => this.reflector.get<Role[] | undefined>(REQUIRED_ROLES_METADATA, target) ?? [],
        ),
      ),
    ];
    const isPublic =
      this.reflector.getAllAndOverride<boolean | undefined>(PUBLIC_ROUTE_METADATA, targets) ===
      true;
    if (isPublic && permissions.length === 0 && roles.length === 0) return true;

    const req = context.switchToHttp().getRequest<Request>();
    const principal = getRequestPrincipal(req);
    if (!principal) throw new UnauthorizedException('Authentication required');

    const missing = permissions.filter((p) => !principal.permissions.includes(p));
    const roleOk = roles.length === 0 || hasAnyRole(principal, roles);
    if (missing.length === 0 && roleOk) return true;

    this.options.logger.warn(
      {
        audit: true,
        subject: principal.subject,
        missingPermissions: missing,
        requiredRoles: roles,
        correlationId: getCorrelationId(req),
        method: req.method,
        path: req.path,
      },
      'access denied',
    );
    try {
      Promise.resolve(
        this.options.listener?.onAccessDenied?.({
          request: req,
          principal,
          missingPermissions: missing,
          requiredRoles: roleOk ? [] : roles,
        }),
      ).catch((error: unknown) => {
        this.options.logger.error({ err: error }, 'auth event listener failed');
      });
    } catch (error) {
      this.options.logger.error({ err: error }, 'auth event listener failed');
    }
    throw new ForbiddenException('Insufficient permissions');
  }
}
