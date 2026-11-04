import { Inject, Injectable } from '@nestjs/common';

import {
  aggregateHealthStatus,
  API_PREFIX,
  BACKEND_SERVICE_NAMES,
  healthReportSchema,
  type BackendServiceName,
  type PlatformHealth,
  type ServiceHealthSummary,
} from '@cve/contracts';

import type { ServiceRegistry } from '../config/env.js';
import {
  HTTP_FETCH,
  SERVICE_REGISTRY,
  SERVICES_HEALTH_TIMEOUT_MS,
  type HttpFetch,
} from './services-health.constants.js';

@Injectable()
export class ServicesHealthService {
  constructor(
    @Inject(SERVICE_REGISTRY) private readonly registry: ServiceRegistry,
    @Inject(HTTP_FETCH) private readonly fetchFn: HttpFetch,
    @Inject(SERVICES_HEALTH_TIMEOUT_MS) private readonly timeoutMs: number,
  ) {}

  /** Queries every backend service's readiness endpoint concurrently. */
  async check(): Promise<PlatformHealth> {
    const services = await Promise.all(
      BACKEND_SERVICE_NAMES.map((service) => this.checkService(service)),
    );
    return {
      status: aggregateHealthStatus(services.map((service) => service.status)),
      timestamp: new Date().toISOString(),
      services,
    };
  }

  private async checkService(service: BackendServiceName): Promise<ServiceHealthSummary> {
    const url = `${this.registry[service]}/${API_PREFIX}/health/ready`;
    const started = performance.now();
    const elapsed = () => Math.round(performance.now() - started);
    try {
      const response = await this.fetchFn(url, {
        method: 'GET',
        headers: { accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      const body: unknown = await response.json();
      const parsed = healthReportSchema.safeParse(
        typeof body === 'object' && body !== null ? (body as { data?: unknown }).data : undefined,
      );
      if (!parsed.success) {
        return {
          service,
          status: 'down',
          latencyMs: elapsed(),
          message: `invalid health response (HTTP ${response.status})`,
        };
      }
      return { service, status: parsed.data.status, latencyMs: elapsed(), report: parsed.data };
    } catch (error) {
      const message =
        error instanceof Error && error.name === 'TimeoutError'
          ? `timed out after ${this.timeoutMs}ms`
          : `unreachable: ${error instanceof Error ? error.message : 'unknown error'}`;
      return { service, status: 'down', latencyMs: elapsed(), message };
    }
  }
}
