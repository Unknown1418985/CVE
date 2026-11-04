import { Module, type DynamicModule } from '@nestjs/common';

import type { ServiceRegistry } from '../config/env.js';
import {
  HTTP_FETCH,
  SERVICE_REGISTRY,
  SERVICES_HEALTH_TIMEOUT_MS,
  type HttpFetch,
} from './services-health.constants.js';
import { ServicesHealthController } from './services-health.controller.js';
import { ServicesHealthService } from './services-health.service.js';

export interface ServicesHealthModuleOptions {
  readonly registry: ServiceRegistry;
  readonly timeoutMs: number;
  /** Injectable for tests; defaults to the global `fetch`. */
  readonly fetch?: HttpFetch;
}

@Module({})
export class ServicesHealthModule {
  static register(options: ServicesHealthModuleOptions): DynamicModule {
    return {
      module: ServicesHealthModule,
      controllers: [ServicesHealthController],
      providers: [
        { provide: SERVICE_REGISTRY, useValue: options.registry },
        { provide: SERVICES_HEALTH_TIMEOUT_MS, useValue: options.timeoutMs },
        { provide: HTTP_FETCH, useValue: options.fetch ?? globalThis.fetch.bind(globalThis) },
        ServicesHealthService,
      ],
    };
  }
}
