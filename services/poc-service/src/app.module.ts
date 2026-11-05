import { Module, type DynamicModule } from '@nestjs/common';

import { authGuards, AuthModule, type TokenVerifier } from '@cve/auth';
import type { Logger } from '@cve/logger';
import { HealthModule, type HealthIndicator } from '@cve/shared';

import {
  PocArtifactsController,
  PocAssociationsController,
  PocDiscoveryController,
  PocOwnersController,
  PocReferencesController,
  PocRepositoriesController,
} from './api/controllers.js';
import { PocCommandService } from './api/poc-command.service.js';
import { PocQueryService } from './api/poc-query.service.js';
import {
  CONNECTOR_INFO,
  DISCOVERY_JOBS,
  SCORING_SETTINGS,
  type ConnectorInfo,
} from './api/tokens.js';
import {
  APP_LOGGER,
  MANAGED_RESOURCES,
  ResourceLifecycle,
  type ManagedResource,
} from './common/lifecycle.js';
import type { Env } from './config/env.js';
import type { ScoringSettings } from './discovery/association-scorer.js';
import type { DiscoveryJobQueue } from './discovery/discovery-jobs.js';
import type { PrismaClient } from './generated/prisma/client.js';
import { PRISMA } from './persistence/database.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';

/** Everything the module needs from the outside world; tests substitute their own. */
export interface PocServiceDependencies {
  readonly logger: Logger;
  readonly verifier: TokenVerifier;
  readonly prisma: PrismaClient;
  readonly healthIndicators: readonly HealthIndicator[];
  /** Null when Redis is not wired (tests): triggering discovery answers 503. */
  readonly jobs: DiscoveryJobQueue | null;
  readonly connectors: readonly ConnectorInfo[];
  readonly scoring: ScoringSettings;
  readonly resources?: readonly ManagedResource[];
}

/**
 * Root module of the PoC Service. Every route requires a valid Keycloak access token (zero
 * trust: the gateway's check is repeated here) and the permissions declared per route.
 */
@Module({})
export class AppModule {
  static register(env: Env, deps: PocServiceDependencies): DynamicModule {
    return {
      module: AppModule,
      imports: [
        AuthModule.forRoot({ verifier: deps.verifier, logger: deps.logger }),
        HealthModule.forRoot({
          service: SERVICE_NAME,
          version: SERVICE_VERSION,
          timeoutMs: env.HEALTH_CHECK_TIMEOUT_MS,
          indicators: deps.healthIndicators,
        }),
      ],
      controllers: [
        PocRepositoriesController,
        PocOwnersController,
        PocAssociationsController,
        PocArtifactsController,
        PocReferencesController,
        PocDiscoveryController,
      ],
      providers: [
        ...authGuards(),
        { provide: APP_LOGGER, useValue: deps.logger },
        { provide: MANAGED_RESOURCES, useValue: deps.resources ?? [] },
        { provide: PRISMA, useValue: deps.prisma },
        { provide: DISCOVERY_JOBS, useValue: deps.jobs },
        { provide: CONNECTOR_INFO, useValue: deps.connectors },
        { provide: SCORING_SETTINGS, useValue: deps.scoring },
        ResourceLifecycle,
        PocQueryService,
        PocCommandService,
      ],
    };
  }
}
