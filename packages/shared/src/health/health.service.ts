import { Inject, Injectable, type OnModuleDestroy } from '@nestjs/common';

import { aggregateHealthStatus, type DependencyCheck, type HealthReport } from '@cve/contracts';

import { HEALTH_MODULE_OPTIONS } from './health.constants.js';
import type { HealthModuleOptions } from './health.types.js';

/** Check reported by readiness once the process has started shutting down. */
export const SHUTDOWN_CHECK_NAME = 'shutdown';

@Injectable()
export class HealthService implements OnModuleDestroy {
  private readonly startedAt = Date.now();
  private shuttingDown = false;

  constructor(@Inject(HEALTH_MODULE_OPTIONS) private readonly options: HealthModuleOptions) {}

  /** Liveness: the process is running and able to serve requests. */
  liveness(): HealthReport {
    return this.report([]);
  }

  /**
   * Readiness: all registered dependencies are checked concurrently. Once shutdown has begun the
   * service reports `down` so load balancers and orchestrators stop routing new work to it while
   * in-flight requests finish.
   */
  async readiness(): Promise<HealthReport> {
    if (this.shuttingDown) {
      return this.report([
        { name: SHUTDOWN_CHECK_NAME, status: 'down', message: 'service is shutting down' },
      ]);
    }
    const checks = await Promise.all(
      this.options.indicators.map(async (indicator): Promise<DependencyCheck> => {
        try {
          const result = await indicator.check(this.options.timeoutMs);
          if (result.status === 'down' && !indicator.critical) {
            return { ...result, status: 'degraded' };
          }
          return result;
        } catch (error) {
          return {
            name: indicator.name,
            status: indicator.critical ? 'down' : 'degraded',
            message: error instanceof Error ? error.message : 'health check failed',
          };
        }
      }),
    );
    return this.report(checks);
  }

  /** Marks the service as draining; readiness fails from now on. */
  markShuttingDown(): void {
    this.shuttingDown = true;
  }

  get isShuttingDown(): boolean {
    return this.shuttingDown;
  }

  onModuleDestroy(): void {
    this.markShuttingDown();
  }

  private report(checks: DependencyCheck[]): HealthReport {
    return {
      service: this.options.service,
      version: this.options.version,
      status: aggregateHealthStatus(checks.map((check) => check.status)),
      uptimeSeconds: Math.round((Date.now() - this.startedAt) / 1000),
      timestamp: new Date().toISOString(),
      checks,
    };
  }
}
