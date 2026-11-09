import { createLogger } from '@cve/logger';
import { afterAll, describe, expect, it } from 'vitest';

import type { HealthReport } from '@cve/contracts';
import { counter } from '@cve/metrics';

import {
  collectMetricsText,
  createServiceMetrics,
  registerReadinessMetrics,
  startMetricsServer,
} from './metrics.js';

describe('metrics server', () => {
  const metrics = createServiceMetrics('cve-service', '1.2.3');
  const logger = createLogger({ service: 'test', level: 'silent' });
  let close: (() => void) | undefined;

  afterAll(() => {
    close?.();
  });

  it('serves Prometheus metrics with service labels and nothing else', async () => {
    metrics.httpRequestDuration.observe(
      { method: 'GET', route: '/api/v1/x', status_code: '200' },
      0.01,
    );
    const server = await startMetricsServer({ metrics, port: 0, host: '127.0.0.1', logger });
    close = () => server.close();
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('no address');
    const base = `http://127.0.0.1:${address.port}`;

    const res = await fetch(`${base}/metrics`);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('http_server_request_duration_seconds_bucket');
    expect(body).toContain('service="cve-service"');
    expect(body).toContain('process_cpu_user_seconds_total');

    expect((await fetch(`${base}/other`)).status).toBe(404);
    expect((await fetch(`${base}/metrics`, { method: 'POST' })).status).toBe(404);
  });
});

describe('platform and readiness metrics', () => {
  it('serves platform instruments with the service labels', async () => {
    const metrics = createServiceMetrics('poc-service', '2.0.0');
    counter({ name: 'test_platform_events_total', help: 'h', labelNames: [] }).inc();
    const text = await collectMetricsText(metrics);
    expect(text).toMatch(/test_platform_events_total\{service="poc-service",version="2.0.0"\} 1/);
    expect(text).toContain('process_cpu_user_seconds_total');
  });

  it('turns readiness into service_ready and service_dependency_up gauges', async () => {
    const metrics = createServiceMetrics('download-service', '1.0.0');
    let calls = 0;
    const report: HealthReport = {
      service: 'download-service',
      version: '1.0.0',
      status: 'degraded',
      uptimeSeconds: 1,
      timestamp: new Date().toISOString(),
      checks: [
        { name: 'postgres', status: 'ok' },
        { name: 'clamav', status: 'degraded' },
        { name: 'minio', status: 'down' },
      ],
    };
    registerReadinessMetrics(metrics, () => {
      calls += 1;
      return Promise.resolve(report);
    });
    const text = await metrics.registry.metrics();
    expect(text).toMatch(/service_ready\{[^}]*\} 1/);
    expect(text).toMatch(/service_dependency_up\{dependency="postgres"[^}]*\} 1/);
    expect(text).toMatch(/service_dependency_up\{dependency="clamav"[^}]*\} 0.5/);
    expect(text).toMatch(/service_dependency_up\{dependency="minio"[^}]*\} 0/);
    // Both gauges share one readiness evaluation per scrape.
    expect(calls).toBe(1);
  });

  it('reports not ready when readiness is down', async () => {
    const metrics = createServiceMetrics('cve-service', '1.0.0');
    registerReadinessMetrics(metrics, () =>
      Promise.resolve({
        service: 'cve-service',
        version: '1.0.0',
        status: 'down',
        uptimeSeconds: 1,
        timestamp: new Date().toISOString(),
        checks: [{ name: 'postgres', status: 'down' }],
      }),
    );
    expect(await metrics.registry.metrics()).toMatch(/service_ready\{[^}]*\} 0/);
  });
});
