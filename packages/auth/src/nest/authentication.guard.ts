import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  ServiceUnavailableException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';

import { getCorrelationId, PUBLIC_ROUTE_METADATA } from '@cve/shared';

import { AuthenticationError, IdentityProviderUnavailableError } from '../errors.js';
import { extractBearerToken } from '../token-verifier.js';
import { AUTH_OPTIONS } from './auth.constants.js';
import type { AuthModuleOptions } from './auth.options.js';
import { setRequestPrincipal } from './request-principal.js';

const AUTHENTICATION_REALM = 'cve-platform';

/**
 * Global guard: every route requires a valid Keycloak access token unless marked `@Public()`.
 * On public routes a valid token is still attached so handlers can adapt to the caller.
 */
@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(AUTH_OPTIONS) private readonly options: AuthModuleOptions,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') return false;
    const http = context.switchToHttp();
    const req = http.getRequest<Request>();
    const res = http.getResponse<Response>();
    const isPublic =
      this.reflector.getAllAndOverride<boolean | undefined>(PUBLIC_ROUTE_METADATA, [
        context.getHandler(),
        context.getClass(),
      ]) === true;

    if (isPublic && req.headers.authorization === undefined) return true;

    try {
      const token = extractBearerToken(req.headers.authorization);
      const principal = await this.options.verifier.verify(token);
      await this.options.sessionChecker?.assertActive(token, principal);
      setRequestPrincipal(req, principal);
      return true;
    } catch (error) {
      if (isPublic) return true;
      if (error instanceof AuthenticationError) {
        this.options.logger.warn(
          {
            audit: true,
            reason: error.reason,
            correlationId: getCorrelationId(req),
            method: req.method,
            path: req.path,
            ip: req.ip,
          },
          'authentication failed',
        );
        this.notify(() =>
          this.options.listener?.onAuthenticationFailed?.({ request: req, reason: error.reason }),
        );
        const challenge =
          error.reason === 'missing-token'
            ? `Bearer realm="${AUTHENTICATION_REALM}"`
            : `Bearer realm="${AUTHENTICATION_REALM}", error="invalid_token"`;
        res.setHeader('WWW-Authenticate', challenge);
        throw new HttpException(
          error.reason === 'missing-token' ? 'Authentication required' : error.message,
          HttpStatus.UNAUTHORIZED,
        );
      }
      if (error instanceof IdentityProviderUnavailableError) {
        this.options.logger.error(
          { err: error, correlationId: getCorrelationId(req) },
          'identity provider unavailable during authentication',
        );
        throw new ServiceUnavailableException('Authentication is temporarily unavailable');
      }
      throw error;
    }
  }

  private notify(call: () => unknown): void {
    try {
      Promise.resolve(call()).catch((error: unknown) => {
        this.options.logger.error({ err: error }, 'auth event listener failed');
      });
    } catch (error) {
      this.options.logger.error({ err: error }, 'auth event listener failed');
    }
  }
}
