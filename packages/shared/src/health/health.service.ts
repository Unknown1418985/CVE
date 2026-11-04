import { Inject, Injectable } from '@nestjs/common';

import { aggregateHealthStatus, type DependencyCheck, type HealthReport } from '@cve/contracts';

import { HEALTH_MODULE_OPTIONS } from './health.constants.js';
import type { HealthModuleOptions } from './health.types.js';

@Injectable()
export class HealthService {
  private readonly startedAt = Date.now();

  constructor(@Inject(HEALTH_MODULE_OPTIONS) private readonly options: HealthModuleOptions) {}

  /** Liveness: the process is running and able to serve requests. */
  liveness(): HealthReport {
    return this.report([]);
  }

  /** Readiness: all registered dependencies are checked concurrently. */
  async readiness(): Promise<HealthReport> {
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
