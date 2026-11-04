import { Module, type DynamicModule } from '@nestjs/common';

import { createTcpHealthIndicator, HealthModule } from '@cve/shared';

import type { Env } from './config/env.js';
import { SERVICE_NAME, SERVICE_VERSION } from './service.js';

/**
 * Root module of the Reporting Service.
 * Domain modules are registered here as they are implemented in later phases.
 */
@Module({})
export class AppModule {
  static register(env: Env): DynamicModule {
    return {
      module: AppModule,
      imports: [
        HealthModule.forRoot({
          service: SERVICE_NAME,
          version: SERVICE_VERSION,
          timeoutMs: env.HEALTH_CHECK_TIMEOUT_MS,
          indicators: [
            createTcpHealthIndicator('postgres', env.DATABASE_URL),
            createTcpHealthIndicator('rabbitmq', env.RABBITMQ_URL),
            createTcpHealthIndicator('redis', env.REDIS_URL),
          ],
        }),
      ],
    };
  }
}
