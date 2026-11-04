import { Module, type DynamicModule } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

import { HealthModule } from '@cve/shared';

import { serviceRegistryFromEnv, type Env } from './config/env.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';
import type { HttpFetch } from './services-health/services-health.constants.js';
import { ServicesHealthModule } from './services-health/services-health.module.js';

export interface AppModuleOverrides {
  readonly fetch?: HttpFetch;
}

/** Root module of the API Gateway. Request routing to services is added with each feature. */
@Module({})
export class AppModule {
  static register(env: Env, overrides: AppModuleOverrides = {}): DynamicModule {
    return {
      module: AppModule,
      imports: [
        ThrottlerModule.forRoot({
          throttlers: [{ ttl: env.RATE_LIMIT_TTL_MS, limit: env.RATE_LIMIT_MAX }],
        }),
        HealthModule.forRoot({
          service: SERVICE_NAME,
          version: SERVICE_VERSION,
          timeoutMs: env.HEALTH_CHECK_TIMEOUT_MS,
          indicators: [],
        }),
        ServicesHealthModule.register({
          registry: serviceRegistryFromEnv(env),
          timeoutMs: env.HEALTH_CHECK_TIMEOUT_MS,
          ...(overrides.fetch ? { fetch: overrides.fetch } : {}),
        }),
      ],
      providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
    };
  }
}
