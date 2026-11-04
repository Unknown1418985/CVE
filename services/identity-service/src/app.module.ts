import { Module, type DynamicModule } from '@nestjs/common';

import { authGuards, AuthModule, type AuthEventListener, type TokenVerifier } from '@cve/auth';
import type { Logger } from '@cve/logger';
import { getCorrelationId, HealthModule, type HealthIndicator } from '@cve/shared';

import { AuditController } from './audit/audit.controller.js';
import { AuditService } from './audit/audit.service.js';
import {
  APP_LOGGER,
  MANAGED_RESOURCES,
  ResourceLifecycle,
  type ManagedResource,
} from './common/lifecycle.js';
import type { Env } from './config/env.js';
import { IDENTITY_OPTIONS, type IdentityOptions } from './identity.options.js';
import { IDENTITY_PROVIDER, type IdentityProvider } from './keycloak/identity-provider.js';
import {
  AUDIT_REPOSITORY,
  PROFILE_REPOSITORY,
  type AuditRepository,
  type ProfileRepository,
} from './persistence/ports.js';
import { ProfileController } from './profile/profile.controller.js';
import { ProfileService } from './profile/profile.service.js';
import { RolesController } from './roles/roles.controller.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';
import { SessionsController } from './sessions/sessions.controller.js';
import { SessionsService } from './sessions/sessions.service.js';
import { UsersController } from './users/users.controller.js';
import { UsersService } from './users/users.service.js';

/** Everything the module needs from the outside world; tests substitute in-memory fakes. */
export interface IdentityDependencies {
  readonly logger: Logger;
  readonly verifier: TokenVerifier;
  readonly identityProvider: IdentityProvider;
  readonly auditRepository: AuditRepository;
  readonly profileRepository: ProfileRepository;
  readonly healthIndicators: readonly HealthIndicator[];
  readonly resources?: readonly ManagedResource[];
}

/** Writes authorization denials to the audit log; authentication failures are only logged. */
function auditListener(repository: AuditRepository, logger: Logger): AuthEventListener {
  return {
    onAccessDenied: async ({ request, principal, missingPermissions, requiredRoles }) => {
      await repository
        .append({
          occurredAt: new Date(),
          source: SERVICE_NAME,
          action: 'identity.access.denied',
          outcome: 'denied',
          actorType: 'user',
          actorId: principal.subject,
          actorUsername: principal.username,
          resourceType: 'endpoint',
          resourceId:
            `${request.method} ${request.route ? String((request.route as { path: unknown }).path) : request.path}`.slice(
              0,
              128,
            ),
          ipAddress: request.ip,
          correlationId: getCorrelationId(request),
          details: { missingPermissions, requiredRoles },
        })
        .catch((error: unknown) => {
          logger.error({ err: error }, 'failed to audit access denial');
        });
    },
  };
}

@Module({})
export class AppModule {
  static register(env: Env, deps: IdentityDependencies): DynamicModule {
    const options: IdentityOptions = {
      realm: env.KEYCLOAK_REALM,
      keycloakPublicUrl: env.KEYCLOAK_PUBLIC_URL,
      webClientId: env.KEYCLOAK_WEB_CLIENT_ID,
      accountRedirectUri: env.ACCOUNT_REDIRECT_URI,
    };
    return {
      module: AppModule,
      imports: [
        AuthModule.forRoot({
          verifier: deps.verifier,
          logger: deps.logger,
          listener: auditListener(deps.auditRepository, deps.logger),
        }),
        HealthModule.forRoot({
          service: SERVICE_NAME,
          version: SERVICE_VERSION,
          timeoutMs: env.HEALTH_CHECK_TIMEOUT_MS,
          indicators: deps.healthIndicators,
        }),
      ],
      controllers: [
        ProfileController,
        SessionsController,
        UsersController,
        RolesController,
        AuditController,
      ],
      providers: [
        ...authGuards(),
        { provide: APP_LOGGER, useValue: deps.logger },
        { provide: MANAGED_RESOURCES, useValue: deps.resources ?? [] },
        { provide: IDENTITY_OPTIONS, useValue: options },
        { provide: IDENTITY_PROVIDER, useValue: deps.identityProvider },
        { provide: AUDIT_REPOSITORY, useValue: deps.auditRepository },
        { provide: PROFILE_REPOSITORY, useValue: deps.profileRepository },
        ResourceLifecycle,
        AuditService,
        ProfileService,
        SessionsService,
        UsersService,
      ],
    };
  }
}
