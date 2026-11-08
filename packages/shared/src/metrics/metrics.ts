import { createServer, type Server } from 'node:http';

import type { Logger } from '@cve/logger';
import type { NextFunction, Request, Response } from 'express';
import { Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

import type { HealthReport } from '@cve/contracts';
import { platformRegistry, setPlatformDefaultLabels } from '@cve/metrics';

/** Prometheus registry and standard instruments for one service process. */
export interface ServiceMetrics {
  readonly registry: Registry;
  readonly httpRequestDuration: Histogram<'method' | 'route' | 'status_code'>;
}

export function createServiceMetrics(service: string, version: string): ServiceMetrics {
  const registry = new Registry();
  registry.setDefaultLabels({ service, version });
  // Instruments created by shared packages (messaging, jobs, auth) and domain code.
  setPlatformDefaultLabels({ service, version });
  collectDefaultMetrics({ register: registry });
  const httpRequestDuration = new Histogram({
    name: 'http_server_request_duration_seconds',
    help: 'Duration of HTTP requests handled by the service',
    labelNames: ['method', 'route', 'status_code'] as const,
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    registers: [registry],
  });
  return { registry, httpRequestDuration };
}

/**
 * Records request durations. The route label uses the matched route template (never the raw
 * path) so label cardinality stays bounded; unmatched requests share one label.
 */
export function createHttpMetricsMiddleware(metrics: ServiceMetrics) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const end = metrics.httpRequestDuration.startTimer();
    res.once('finish', () => {
      const route: unknown = (req.route as { path?: unknown } | undefined)?.path;
      end({
        method: req.method,
        route: typeof route === 'string' ? `${req.baseUrl}${route}` : 'unmatched',
        status_code: String(res.statusCode),
      });
    });
    next();
  };
}

/**
 * Serves `GET /metrics` on a separate port that is only reachable on the internal
 * observability network, so metrics are never routed through the public API.
 */
export async function startMetricsServer(options: {
  readonly metrics: ServiceMetrics;
  readonly port: number;
  readonly host: string;
  readonly logger: Logger;
}): Promise<Server> {
  const server = createServer((req, res) => {
    if (req.method !== 'GET' || req.url !== '/metrics') {
      res.writeHead(404, { 'content-type': 'text/plain' }).end('not found\n');
      return;
    }
    collectMetricsText(options.metrics)
      .then((body) => {
        res.writeHead(200, { 'content-type': options.metrics.registry.contentType }).end(body);
      })
      .catch((error: unknown) => {
        options.logger.error({ err: error }, 'failed to collect metrics');
        res.writeHead(500, { 'content-type': 'text/plain' }).end('metrics unavailable\n');
      });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port, options.host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  server.unref();
  options.logger.info({ port: options.port }, 'metrics endpoint listening');
  return server;
}

/** Both registries in the Prometheus text format: process/HTTP metrics and platform instruments. */
export async function collectMetricsText(metrics: ServiceMetrics): Promise<string> {
  const [own, platform] = await Promise.all([
    metrics.registry.metrics(),
    platformRegistry.metrics(),
  ]);
  return platform.trim() === '' ? own : `${own.trimEnd()}\n${platform}`;
}

/**
 * Publishes readiness as metrics at scrape time: `service_ready` (1 when readiness is not
 * `down`) and `service_dependency_up{dependency}` (1 ok, 0.5 degraded, 0 down). Concurrent
 * collectors share one readiness evaluation so a scrape checks each dependency once.
 */
export function registerReadinessMetrics(
  metrics: ServiceMetrics,
  readiness: () => Promise<HealthReport>,
): void {
  let pending: Promise<HealthReport> | undefined;
  const evaluate = (): Promise<HealthReport> => {
    pending ??= readiness().finally(() => {
      setTimeout(() => {
        pending = undefined;
      }, 1_000).unref();
    });
    return pending;
  };
  new Gauge({
    name: 'service_ready',
    help: 'Whether the service reports itself ready (1) or not (0)',
    registers: [metrics.registry],
    async collect() {
      const report = await evaluate();
      this.set(report.status === 'down' ? 0 : 1);
    },
  });
  new Gauge({
    name: 'service_dependency_up',
    help: 'Dependency health from the readiness checks: 1 ok, 0.5 degraded, 0 down',
    labelNames: ['dependency'] as const,
    registers: [metrics.registry],
    async collect() {
      const report = await evaluate();
      this.reset();
      for (const check of report.checks) {
        const value = check.status === 'ok' ? 1 : check.status === 'degraded' ? 0.5 : 0;
        this.set({ dependency: check.name }, value);
      }
    },
  });
}
