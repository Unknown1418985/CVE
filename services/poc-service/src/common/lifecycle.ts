import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';

import type { Logger } from '@cve/logger';

/** A background component (connection, relay, worker) started with the app and stopped with it. */
export interface ManagedResource {
  readonly name: string;
  start?(): Promise<void>;
  stop(): Promise<void>;
}

export const MANAGED_RESOURCES = Symbol('MANAGED_RESOURCES');
export const APP_LOGGER = Symbol('APP_LOGGER');

@Injectable()
export class ResourceLifecycle implements OnApplicationBootstrap, OnApplicationShutdown {
  constructor(
    @Inject(MANAGED_RESOURCES) private readonly resources: readonly ManagedResource[],
    @Inject(APP_LOGGER) private readonly logger: Logger,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    for (const resource of this.resources) {
      await resource.start?.();
      this.logger.debug({ resource: resource.name }, 'resource started');
    }
  }

  async onApplicationShutdown(): Promise<void> {
    // Stop in reverse order: workers before the connections they use.
    for (const resource of [...this.resources].reverse()) {
      try {
        await resource.stop();
      } catch (error) {
        this.logger.error({ err: error, resource: resource.name }, 'failed to stop resource');
      }
    }
  }
}
