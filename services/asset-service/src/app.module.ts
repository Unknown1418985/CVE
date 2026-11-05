import { Module, type DynamicModule } from '@nestjs/common';

import { authGuards, AuthModule, type TokenVerifier } from '@cve/auth';
import type { Logger } from '@cve/logger';
import { HealthModule, type HealthIndicator } from '@cve/shared';

import { VendorAnalyticsService } from './analytics/vendor-analytics.service.js';
import { AssociationsService } from './associations/associations.service.js';
import { CveAssociationsController } from './associations/cve-associations.controller.js';
import { ProductsController } from './catalog/products.controller.js';
import { ProductsService } from './catalog/products.service.js';
import { VendorsController } from './catalog/vendors.controller.js';
import { VendorsService } from './catalog/vendors.service.js';
import {
  APP_LOGGER,
  MANAGED_RESOURCES,
  ResourceLifecycle,
  type ManagedResource,
} from './common/lifecycle.js';
import type { Env } from './config/env.js';
import type { PrismaClient } from './generated/prisma/client.js';
import { PRISMA } from './persistence/database.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';

/** Everything the module needs from the outside world; tests substitute their own. */
export interface AssetServiceDependencies {
  readonly logger: Logger;
  readonly verifier: TokenVerifier;
  readonly prisma: PrismaClient;
  readonly healthIndicators: readonly HealthIndicator[];
  readonly resources?: readonly ManagedResource[];
}

/**
 * Root module of the Asset Service. Every route requires a valid Keycloak access token (zero
 * trust: the gateway's check is repeated here) and the permissions declared per route.
 */
@Module({})
export class AppModule {
  static register(env: Env, deps: AssetServiceDependencies): DynamicModule {
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
      controllers: [VendorsController, ProductsController, CveAssociationsController],
      providers: [
        ...authGuards(),
        { provide: APP_LOGGER, useValue: deps.logger },
        { provide: MANAGED_RESOURCES, useValue: deps.resources ?? [] },
        { provide: PRISMA, useValue: deps.prisma },
        ResourceLifecycle,
        VendorsService,
        ProductsService,
        AssociationsService,
        VendorAnalyticsService,
      ],
    };
  }
}
