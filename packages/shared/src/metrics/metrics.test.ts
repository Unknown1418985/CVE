import { createLogger } from '@cve/logger';
import { afterAll, describe, expect, it } from 'vitest';

import { createServiceMetrics, startMetricsServer } from './metrics.js';

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
