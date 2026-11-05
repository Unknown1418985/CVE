import { Module, type DynamicModule } from '@nestjs/common';

import { authGuards, AuthModule, type TokenVerifier } from '@cve/auth';
import type { Logger } from '@cve/logger';
import { HealthModule, type HealthIndicator } from '@cve/shared';

import {
  DownloadArtifactsController,
  DownloadRequestsController,
  DownloadSourcesController,
} from './api/controllers.js';
import { DownloadCommandService } from './api/download-command.service.js';
import { DownloadQueryService } from './api/download-query.service.js';
import {
  DOWNLOAD_JOBS,
  DOWNLOAD_SETTINGS,
  OBJECT_STORE,
  SOURCE_POLICIES,
  type DownloadSettings,
} from './api/tokens.js';
import {
  APP_LOGGER,
  MANAGED_RESOURCES,
  ResourceLifecycle,
  type ManagedResource,
} from './common/lifecycle.js';
import type { Env } from './config/env.js';
import type { SourcePolicy } from './domain/sources.js';
import type { DownloadJobQueue } from './download/download-jobs.js';
import type { PrismaClient } from './generated/prisma/client.js';
import { PRISMA } from './persistence/database.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';
import type { ArtifactObjectStore } from './storage/object-store.js';

/** Everything the module needs from the outside world; tests substitute their own. */
export interface DownloadServiceDependencies {
  readonly logger: Logger;
  readonly verifier: TokenVerifier;
  readonly prisma: PrismaClient;
  readonly healthIndicators: readonly HealthIndicator[];
  /** Null when Redis is not wired (tests): requests wait for the scheduler, rescans answer 503. */
  readonly jobs: DownloadJobQueue | null;
  readonly store: ArtifactObjectStore;
  readonly sources: readonly SourcePolicy[];
  readonly settings: DownloadSettings;
  readonly resources?: readonly ManagedResource[];
}

/**
 * Root module of the Download Service. Every route requires a valid Keycloak access token (the
 * gateway's check is repeated here) and the permissions declared per route.
 */
@Module({})
export class AppModule {
  static register(env: Env, deps: DownloadServiceDependencies): DynamicModule {
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
        DownloadSourcesController,
        DownloadRequestsController,
        DownloadArtifactsController,
      ],
      providers: [
        ...authGuards(),
        { provide: APP_LOGGER, useValue: deps.logger },
        { provide: MANAGED_RESOURCES, useValue: deps.resources ?? [] },
        { provide: PRISMA, useValue: deps.prisma },
        { provide: DOWNLOAD_JOBS, useValue: deps.jobs },
        { provide: OBJECT_STORE, useValue: deps.store },
        { provide: SOURCE_POLICIES, useValue: deps.sources },
        { provide: DOWNLOAD_SETTINGS, useValue: deps.settings },
        ResourceLifecycle,
        DownloadQueryService,
        DownloadCommandService,
      ],
    };
  }
}
