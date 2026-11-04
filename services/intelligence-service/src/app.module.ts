import { Module, type DynamicModule } from '@nestjs/common';

import { authGuards, AuthModule, type TokenVerifier } from '@cve/auth';
import type { IntelligenceSource } from '@cve/contracts';
import type { Logger } from '@cve/logger';
import { HealthModule, type HealthIndicator } from '@cve/shared';

import { SourcesController, SyncRunsController } from './api/sources.controller.js';
import { SOURCE_REGISTRY, SYNC_JOB_QUEUE, SYNC_SETTINGS, SyncService } from './api/sync.service.js';
import {
  APP_LOGGER,
  MANAGED_RESOURCES,
  ResourceLifecycle,
  type ManagedResource,
} from './common/lifecycle.js';
import type { Env } from './config/env.js';
import { INTELLIGENCE_REPOSITORY, type IntelligenceRepository } from './persistence/ports.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';
import type { RegisteredSource } from './sources/registry.js';
import type { SyncJobQueue } from './sync/sync-jobs.js';

/** Everything the module needs from the outside world; tests substitute in-memory fakes. */
export interface IntelligenceDependencies {
  readonly logger: Logger;
  readonly verifier: TokenVerifier;
  readonly repository: IntelligenceRepository;
  readonly registry: ReadonlyMap<IntelligenceSource, RegisteredSource>;
  readonly jobs: SyncJobQueue;
  readonly healthIndicators: readonly HealthIndicator[];
  readonly resources?: readonly ManagedResource[];
}

/**
 * Root module of the Intelligence Service: the data-source API (sources, synchronisation
 * history, manual runs and retries). Synchronisation itself runs in BullMQ workers started as
 * managed resources. Every route requires a Keycloak access token and `data-source:*`.
 */
@Module({})
export class AppModule {
  static register(env: Env, deps: IntelligenceDependencies): DynamicModule {
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
      controllers: [SourcesController, SyncRunsController],
      providers: [
        ...authGuards(),
        { provide: APP_LOGGER, useValue: deps.logger },
        { provide: MANAGED_RESOURCES, useValue: deps.resources ?? [] },
        { provide: INTELLIGENCE_REPOSITORY, useValue: deps.repository },
        { provide: SOURCE_REGISTRY, useValue: deps.registry },
        { provide: SYNC_JOB_QUEUE, useValue: deps.jobs },
        { provide: SYNC_SETTINGS, useValue: { storeRawPayloads: env.STORE_RAW_PAYLOADS } },
        ResourceLifecycle,
        SyncService,
      ],
    };
  }
}
