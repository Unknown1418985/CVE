import { Module, type DynamicModule } from '@nestjs/common';

import { HEALTH_MODULE_OPTIONS } from './health.constants.js';
import { HealthController } from './health.controller.js';
import { HealthService } from './health.service.js';
import type { HealthModuleOptions } from './health.types.js';

@Module({})
export class HealthModule {
  static forRoot(options: HealthModuleOptions): DynamicModule {
    return {
      module: HealthModule,
      controllers: [HealthController],
      providers: [{ provide: HEALTH_MODULE_OPTIONS, useValue: options }, HealthService],
      exports: [HealthService],
    };
  }
}
